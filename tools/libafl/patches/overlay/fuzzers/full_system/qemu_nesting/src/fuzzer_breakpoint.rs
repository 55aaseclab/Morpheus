use core::time::Duration;
use std::{
    env, fs,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process,
};

use libafl::{
    Error,
    corpus::{Corpus, OnDiskCorpus, Testcase},
    events::{EventConfig, ProgressReporter, SimpleEventManager, launcher::Launcher},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    generators::Generator,
    inputs::Input,
    monitors::MultiMonitor,
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_nesting::{
    MAX_ENCODED_SCENARIO_BYTES, ScenarioGenerator, ScenarioInput, ScenarioMetadataStore,
    ScenarioMutator, decode_scenario, encode_scenario,
};
use libafl_qemu::{
    FastSnapshotManager, QemuSnapshotManager, SnapshotManager, emu::Emulator,
    executor::QemuExecutor,
    modules::edges::StdEdgeCoverageModule,
};
use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND, edges_map_mut_ptr};

const MAX_INPUT_SIZE: usize = MAX_ENCODED_SCENARIO_BYTES;

/// The semantic sidecar directory: an explicit
/// `MORPHEUS_LIBAFL_SDG_METADATA_DIR` override, or a sibling
/// `<corpus-name>.sdg-metadata` of the corpus directory. The sidecar lives
/// outside the corpus directory, so OnDiskCorpus never interprets a
/// metadata record as a testcase.
fn sdg_metadata_dir(corpus_dir: &Path) -> PathBuf {
    env::var("MORPHEUS_LIBAFL_SDG_METADATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| ScenarioMetadataStore::sidecar_dir_for_corpus(corpus_dir))
}

/// The number of generated semantic seeds: an explicit
/// `MORPHEUS_LIBAFL_INITIAL_GENERATED_SEEDS` override, or the default of
/// eight rule families.
fn initial_generated_seeds() -> usize {
    std::env::var("MORPHEUS_LIBAFL_INITIAL_GENERATED_SEEDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8)
}

/// Build the scenario generator from the environment and point its shared
/// metadata store at the persistent sidecar. Generator and mutator clones
/// share the store; records are written atomically and lazy-loaded, so
/// seeds generated in one process or client are usable by another through
/// the shared sidecar directory.
fn scenario_generator_from_env(corpus_dir: &Path) -> ScenarioGenerator {
    let generator = ScenarioGenerator::from_env()
        .unwrap_or_else(|err| panic!("failed to load SDG rules: {err}"));
    let metadata_dir = sdg_metadata_dir(corpus_dir);
    let (loaded, executable) = generator.rule_counts();
    eprintln!("[libafl/qemu_nesting] SDG rules loaded={loaded} executable={executable} irq=ignored");
    if env::var("MORPHEUS_LIBAFL_REQUIRE_SDG").is_ok_and(|v| v == "true") && executable == 0 {
        panic!("grammar run requires at least one executable SDG rule");
    }
    if env::var("MORPHEUS_LIBAFL_DISABLE_SDG").is_err() {
        eprintln!(
            "[libafl/qemu_nesting] semantic metadata sidecar={}",
            metadata_dir.display()
        );
    }
    generator.with_metadata_dir(&metadata_dir)
}

const DEFAULT_MUTATIONAL_MAX_ITERATIONS: &str = "1";

fn parse_mutational_max_iterations(value: Option<&str>) -> Result<NonZeroUsize, String> {
    let value = value.unwrap_or(DEFAULT_MUTATIONAL_MAX_ITERATIONS);
    value.parse::<NonZeroUsize>().map_err(|_| {
        format!(
            "MORPHEUS_LIBAFL_MUTATIONAL_MAX_ITERATIONS must be a positive integer, got {value:?}"
        )
    })
}

fn mutational_max_iterations() -> NonZeroUsize {
    let configured = env::var("MORPHEUS_LIBAFL_MUTATIONAL_MAX_ITERATIONS").ok();
    let iterations = parse_mutational_max_iterations(configured.as_deref())
        .unwrap_or_else(|err| panic!("invalid mutational stage configuration: {err}"));
    eprintln!(
        "[libafl/qemu_nesting] mutational max iterations={}",
        iterations
    );
    iterations
}

fn report_progress<EM, S>(manager: &mut EM, state: &mut S) -> Result<(), Error>
where
    EM: ProgressReporter<S>,
{
    manager.report_progress(state)
}

/// QEMU's stdio chardev marks fd 1 non-blocking (char-fd.c). LibAFL's monitor
/// prints share that fd, so a backed-up console pipeline would panic the
/// fuzzer with EAGAIN instead of blocking. Restore the default blocking mode
/// after the outer QEMU boots so slow consoles only slow down, never crash.
fn restore_blocking_stdout() {
    unsafe {
        let flags = libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL);
        if flags >= 0 && (flags & libc::O_NONBLOCK) != 0 {
            libc::fcntl(
                libc::STDOUT_FILENO,
                libc::F_SETFL,
                flags & !libc::O_NONBLOCK,
            );
        }
    }
}

fn executor_timeout(_replay_enabled: bool) -> Duration {
    // No host-side timeout: the L2 run window is the per-iteration bound.
    // The stub terminates, reaps, and waits for the realm teardown on expiry
    // (or earlier via stop-on-login), so every iteration returns on its own.
    // A zero duration disarms the executor's break timer.  A hung cleanup is
    // still bounded by the workflow step timeout.
    Duration::ZERO
}

fn snapshot_manager_from_env() -> SnapshotManager {
    match env::var("MORPHEUS_LIBAFL_SNAPSHOT_MANAGER")
        .unwrap_or_else(|_| "fast".to_owned())
        .to_ascii_lowercase()
        .as_str()
    {
        "qemu" => {
            eprintln!("[libafl/qemu_nesting] snapshot manager=qemu");
            SnapshotManager::Qemu(QemuSnapshotManager::default())
        }
        "fast" => {
            eprintln!("[libafl/qemu_nesting] snapshot manager=fast");
            SnapshotManager::Fast(FastSnapshotManager::default())
        }
        value => panic!(
            "unsupported MORPHEUS_LIBAFL_SNAPSHOT_MANAGER={value:?}; use fast or qemu"
        ),
    }
}

fn replay_input_paths() -> Option<Vec<PathBuf>> {
    let manifest = env::var("MORPHEUS_LIBAFL_REPLAY_INPUTS").ok()?;
    input_paths_from_manifest(&manifest, "replay")
}

fn initial_input_paths() -> Option<Vec<PathBuf>> {
    let manifest = env::var("MORPHEUS_LIBAFL_INITIAL_INPUTS").ok()?;
    let paths = input_paths_from_manifest(&manifest, "initial");
    if let Some(paths) = paths.as_ref() {
        eprintln!(
            "[libafl/qemu_nesting] initial input manifest={} entries={}",
            manifest,
            paths.len()
        );
    }
    paths
}

fn input_paths_from_manifest(manifest: &str, kind: &str) -> Option<Vec<PathBuf>> {
    let content = fs::read_to_string(&manifest)
        .unwrap_or_else(|err| panic!("failed to read {kind} input manifest {manifest}: {err}"));
    let paths = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    Some(paths)
}

fn validate_input_size(input: ScenarioInput, path: &Path) -> Result<ScenarioInput, Error> {
    let encoded_len = encode_scenario(&input).len();
    if encoded_len > MAX_INPUT_SIZE {
        return Err(Error::illegal_argument(format!(
            "input {} encodes to {encoded_len} bytes, over the {MAX_INPUT_SIZE}-byte limit",
            path.display()
        )));
    }
    Ok(input)
}

fn load_replay_input(path: &Path) -> Result<ScenarioInput, Error> {
    let bytes = fs::read(path)?;
    let input = decode_scenario(&bytes).map_err(|decode_err| {
        Error::illegal_argument(format!(
            "failed to load replay input {} as raw scenario bytes ({decode_err})",
            path.display()
        ))
    })?;
    validate_input_size(input, path)
}

pub fn fuzz() {
    env_logger::init();

    let replay_inputs = replay_input_paths();
    let initial_inputs = initial_input_paths();
    let timeout = executor_timeout(replay_inputs.is_some());
    let broker_port = env::var("BROKER_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(1341);
    let cores = Cores::from_cmdline("1").unwrap();
    let corpus_dir = env::var("MORPHEUS_LIBAFL_CORPUS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./corpus"));
    let objective_dir = env::var("MORPHEUS_LIBAFL_OBJECTIVE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./crashes"));
    let scenario_generator = scenario_generator_from_env(&corpus_dir);
    macro_rules! run_client_body {
        ($state:expr, $mgr:ident) => {{
            (|| -> Result<(), Error> {
                let args: Vec<String> = env::args().collect();

                let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                                   _state: &mut _,
                                   input: &ScenarioInput| unsafe {
                    eprintln!(
                        "[libafl/qemu_nesting] execution start actions={} encoded-bytes={}",
                        input.total_actions(),
                        encode_scenario(input).len(),
                    );
                    let emulator_exit = match emulator.run(input) {
                        Ok(exit) => exit,
                        Err(err) => {
                            eprintln!(
                                "[libafl/qemu_nesting] outer QEMU execution failed: {err:?}"
                            );
                            process::exit(1);
                        }
                    };
                    let exit_kind = match emulator_exit.try_into() {
                        Ok(exit_kind) => exit_kind,
                        Err(err) => {
                            eprintln!(
                                "[libafl/qemu_nesting] invalid outer QEMU exit result: {err:?}"
                            );
                            process::exit(1);
                        }
                    };
                    eprintln!("[libafl/qemu_nesting] execution complete exit={exit_kind:?}");
                    exit_kind
                };

                let mut edges_observer = unsafe {
                    HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                        "edges",
                        OwnedMutSlice::from_raw_parts_mut(
                            edges_map_mut_ptr(),
                            EDGES_MAP_DEFAULT_SIZE,
                        ),
                        &raw mut MAX_EDGES_FOUND,
                    ))
                    .track_indices()
                };

                let time_observer = TimeObserver::new("time");
                let modules = tuple_list!(
                    StdEdgeCoverageModule::builder()
                        .map_observer(edges_observer.as_mut())
                        .build()?
                );

                let mut emu = Emulator::builder()
                    .qemu_parameters(args)
                    .modules(modules)
                    // Select the snapshot implementation explicitly so a
                    // launcher failure can be compared without changing the
                    // guest input or its MMIO path.
                    .snapshot_manager(snapshot_manager_from_env())
                    .build()?;

                unsafe {
                    eprintln!("[libafl/qemu_nesting] starting outer QEMU");
                    emu.start().expect("failed to start outer QEMU");
                }
                eprintln!("[libafl/qemu_nesting] outer QEMU reached guest stub");
                restore_blocking_stdout();

                let mut feedback = feedback_or!(
                    MaxMapFeedback::new(&edges_observer),
                    TimeFeedback::new(&time_observer)
                );
                let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

                let mut state = $state.unwrap_or_else(|| {
                    let mut initial_scenario_generator = scenario_generator.clone();
                    let mut state = StdState::new(
                        StdRand::with_seed(current_nanos()),
                        OnDiskCorpus::new(corpus_dir.clone()).unwrap(),
                        OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                        &mut feedback,
                        &mut objective,
                    )
                    .unwrap();
                    if let Some(paths) = replay_inputs.as_ref() {
                        for path in paths {
                            eprintln!("[libafl/qemu_nesting] loading replay input {}", path.display());
                            let input = load_replay_input(path).unwrap();
                            let mut testcase = Testcase::from(input);
                            *testcase.filename_mut() =
                                Some(path.file_name().unwrap().to_string_lossy().to_string());
                            state.corpus_mut().add(testcase).unwrap();
                        }
                    } else if let Some(paths) = initial_inputs.as_ref() {
                        let mut loaded = 0usize;
                        for path in paths {
                            eprintln!("[libafl/qemu_nesting] loading initial input {}", path.display());
                            let input = match load_replay_input(path) {
                                Ok(input) => input,
                                Err(err) => {
                                    eprintln!(
                                        "skipping invalid initial fuzz input {}: {err:?}",
                                        path.display()
                                    );
                                    continue;
                                }
                            };
                            let mut testcase = Testcase::from(input);
                            *testcase.filename_mut() =
                                Some(path.file_name().unwrap().to_string_lossy().to_string());
                            state.corpus_mut().add(testcase).unwrap();
                            loaded += 1;
                        }
                        if loaded == 0 {
                            panic!("no valid initial fuzz inputs loaded");
                        }
                    } else {
                        for _ in 0..initial_generated_seeds() {
                            let input = initial_scenario_generator.generate(&mut state).unwrap();
                            state.corpus_mut().add(input.into()).unwrap();
                        }
                    }
                    // Imported seeds have no semantic provenance. Add generated
                    // seeds so grammar mutation has exact source placements.
                    if replay_inputs.is_none() && initial_inputs.is_some()
                        && initial_scenario_generator.rule_counts().1 > 0 {
                        let count = initial_generated_seeds();
                        for _ in 0..count {
                            let input = initial_scenario_generator.generate(&mut state).unwrap();
                            state.corpus_mut().add(input.into()).unwrap();
                        }
                        eprintln!(
                            "[libafl/qemu_nesting] added {count} SDG seeds with semantic metadata"
                        );
                    }
                    eprintln!(
                        "[libafl/qemu_nesting] initial corpus entries={}",
                        state.corpus().count()
                    );
                    state
                });

                let scheduler =
                    IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());
                let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

                let mut executor = QemuExecutor::new(
                    emu,
                    &mut harness,
                    tuple_list!(edges_observer, time_observer),
                    &mut fuzzer,
                    &mut state,
                    &mut $mgr,
                    timeout,
                )
                .expect("Failed to create QemuExecutor");
                eprintln!("[libafl/qemu_nesting] executor ready");

                executor.break_on_timeout();

                if replay_inputs.is_some() {
                    let corpus_ids = state.corpus().ids().collect::<Vec<_>>();
                    for corpus_id in corpus_ids {
                        let input = {
                            let mut testcase = state.corpus().get(corpus_id)?.borrow_mut();
                            testcase.load_input(state.corpus())?.clone()
                        };
                        fuzzer
                            .evaluate_input(&mut state, &mut executor, &mut $mgr, &input)
                            .unwrap_or_else(|err| {
                                println!("failed replay: {err:?}");
                                process::exit(1);
                            });
                    }
                    // Replay runs bypass `fuzz_loop`, so publish the execution
                    // count explicitly instead of leaving the broker with its
                    // initial zero snapshot.
                    report_progress(&mut $mgr, &mut state).unwrap_or_else(|err| {
                        println!("failed replay progress report: {err:?}");
                        process::exit(1);
                    });
                } else {
                    if initial_inputs.is_some() {
                        let corpus_ids = state.corpus().ids().collect::<Vec<_>>();
                        for corpus_id in corpus_ids {
                            eprintln!(
                                "[libafl/qemu_nesting] evaluating initial corpus id={corpus_id:?}"
                            );
                            let input = {
                                let mut testcase = state.corpus().get(corpus_id)?.borrow_mut();
                                testcase
                                    .load_input(state.corpus())
                                    .map_err(|err| {
                                        Error::illegal_state(format!(
                                            "failed to reload initial corpus input {corpus_id:?}: {err:?}"
                                        ))
                                    })?
                                    .clone()
                            };
                            fuzzer
                                .evaluate_input(&mut state, &mut executor, &mut $mgr, &input)
                                .unwrap_or_else(|err| {
                                    println!("failed initial input: {err:?}");
                                    process::exit(1);
                                });
                        }
                        // Initial corpus evaluation also happens before the
                        // regular fuzz loop.  Report it now so a slow first
                        // mutation cannot hide completed executions.
                        report_progress(&mut $mgr, &mut state).unwrap_or_else(|err| {
                            println!("failed initial progress report: {err:?}");
                            process::exit(1);
                        });
                    }

                    // The shadow/CmpLog stage would boot a second nested L2 for
                    // every fuzz input. Guest-side compare logs do not justify
                    // that cost for this systemmode target, so keep only the
                    // structured scenario mutation stage on the hot path.
                    let mut executor = executor;
                    let mut stages = tuple_list!(StdMutationalStage::with_max_iterations(
                        ScenarioMutator::new(scenario_generator.clone()),
                        mutational_max_iterations(),
                    ));

                    // Run one complete fuzzer iteration at a time.  The
                    // regular `fuzz_loop` only checks the reporting timer
                    // before an iteration, while this target's executor can
                    // take longer than the broker heartbeat interval.  The
                    // bounded loop reports after every iteration and keeps
                    // the broker's execution snapshot current.
                    loop {
                        fuzzer
                            .fuzz_loop_for(
                                &mut stages,
                                &mut executor,
                                &mut state,
                                &mut $mgr,
                                1,
                            )
                            .map_err(|err| {
                                eprintln!("[libafl/qemu_nesting] fuzz loop stopped: {err:?}");
                                err
                            })?;
                    }
                }
                Ok(())
            })()
        }};
    }

    let monitor = MultiMonitor::new(|s| println!("{s}"));
    if replay_inputs.is_some() {
        let mut mgr = SimpleEventManager::new(monitor);
        run_client_body!(None, mgr).unwrap_or_else(|err| panic!("Failed to run replay: {err:?}"));
        return;
    }

    let mut run_client =
        |state: Option<_>, mut mgr, _client_description| run_client_body!(state, mgr);

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_mutational_max_iterations;

    #[test]
    fn slow_target_defaults_to_one_mutation_per_iteration() {
        assert_eq!(parse_mutational_max_iterations(None).unwrap().get(), 1);
    }

    #[test]
    fn mutational_iteration_limit_accepts_positive_values() {
        assert_eq!(parse_mutational_max_iterations(Some("7")).unwrap().get(), 7);
    }

    #[test]
    fn mutational_iteration_limit_rejects_zero_and_non_numbers() {
        assert!(parse_mutational_max_iterations(Some("0")).is_err());
        assert!(parse_mutational_max_iterations(Some("many")).is_err());
    }
}
