//! End-to-end pipeline coverage of the documented architecture: a synthetic
//! non-empty extractor JSON rule goes through convert_to_sdg.py, the
//! generated directory is loaded with the actual Rust parser, the runtime
//! generates semantically, lowers, registers corpus metadata, mutates with
//! the actual Mutator trait, and registers child metadata with exact
//! target/precondition/placement validation.

use libafl::mutators::{MutationResult, Mutator};
use libafl_bolts::rands::StdRand;
use libafl_nesting::{
    ScenarioGenerator, ScenarioInput, ScenarioMutator, SemanticDependencyGraph,
};

fn converter_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("SDG_CONVERTER") {
        let path = std::path::PathBuf::from(path);
        assert!(path.exists(), "SDG_CONVERTER points at a missing converter: {}", path.display());
        return path;
    }
    // Overlay layout: <tools>/libafl/patches/overlay/crates/libafl_nesting.
    let candidate = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../../sdg-extractor/scripts/convert_to_sdg.py");
    assert!(
        candidate.exists(),
        "convert_to_sdg.py not found at {}; set SDG_CONVERTER to its path",
        candidate.display()
    );
    candidate
}

/// A synthetic but valid extractor rule: the docs' feature-guard pattern
/// with a feature-word read, a config-byte read, a BitSet-style evaluable
/// precondition, a Gt target state, and a SetBoundary hint.
const RULES_JSON: &str = r#"{"version": "1.2", "rules": [{
  "id": "rule:probe|target:mmio:273:1:rss_max_key_size|predicate:gt:unsigned:40",
  "function": "probe",
  "status": "conditional",
  "vars": ["mmio:16:4:features", "mmio:273:1:rss_max_key_size"],
  "path": {"source": "mmio:16:4:features", "sink": "mmio:273:1:rss_max_key_size",
           "edges": ["edge:probe:guard"]},
  "preconditions": {"kind": "And", "operands": [
    {"kind": "&", "left": {"node": "mmio:16:4:features"},
     "right": {"kind": "Const", "value": 33554432}}
  ]},
  "target_state": {
    "src": "mmio:273:1:rss_max_key_size",
    "dst": "mmio:273:1:rss_max_key_size",
    "head": "head_bound",
    "predicate": {"kind": "Gt", "left": {"node": "mmio:273:1:rss_max_key_size"},
                  "right": {"kind": "Const", "value": 40}}
  },
  "mutation_hint": [{"operator": "SampleRange", "var": "mmio:16:4:features",
                     "min": 33554432, "max": 4294967295}],
  "validation": {"method": "typed bit-vector constraints", "result": "sat",
                 "source_assignments": {"mmio:16:4:features": 33554432}},
  "assumptions": [{"kind": "kernel_path_condition", "status": "assumed"}]
}]}"#;

const NODES_JSON: &str = r#"{"version": "1.2", "nodes": [
  {"id": "mmio:16:4:features", "kind": "source",
   "source": {"kind": "MmioRead", "offset": 16, "size_bytes": 4,
              "byte_order": "Little", "access": "config", "access_context": []},
   "type": {"width": 32, "signedness": "Unsigned"}},
  {"id": "mmio:273:1:rss_max_key_size", "kind": "sink",
   "source": {"kind": "MmioRead", "offset": 273, "size_bytes": 1,
              "byte_order": "Little", "access": "config", "access_context": []},
   "type": {"width": 8, "signedness": "Unsigned"}}
]}"#;

const EDGES_JSON: &str = r#"{"version": "1.2", "self_edges": [], "cross_edges": [
  {"id": "edge:probe:guard", "src": "mmio:16:4:features",
   "dst": "mmio:273:1:rss_max_key_size", "head": "head_guard",
   "predicate": {"kind": "BitSet", "bit": 25}}
]}"#;

/// Serialize the env-var manipulation behind one lock, like the unit tests.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Minimal state handle: the Generator and Mutator impls require `HasRand`.
#[derive(Clone, Debug)]
struct TestState {
    rand: StdRand,
}

impl libafl::state::HasRand for TestState {
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}

fn generator_from_rules_dir(dir: &std::path::Path) -> ScenarioGenerator {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: test-only environment manipulation
    unsafe { std::env::set_var("MORPHEUS_LIBAFL_SDG_RULES", dir); }
    // SAFETY: test-only environment manipulation
    unsafe { std::env::remove_var("MORPHEUS_LIBAFL_DISABLE_SDG"); }
    let generator = ScenarioGenerator::from_env()
        .expect("the converted rule directory should load through from_env");
    // SAFETY: test-only environment manipulation
    unsafe { std::env::remove_var("MORPHEUS_LIBAFL_SDG_RULES"); }
    generator
}

#[test]
fn end_to_end_json_to_runtime_pipeline() {
    let converter = converter_path();

    let dir = std::env::temp_dir().join(format!(
        "sdg-pipeline-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    let rules_file = dir.join("sdg-rules.json");
    std::fs::write(&rules_file, RULES_JSON).expect("rules json should be written");
    std::fs::write(dir.join("sdg-nodes.json"), NODES_JSON)
        .expect("nodes json should be written");
    std::fs::write(dir.join("sdg-edges.json"), EDGES_JSON)
        .expect("edges json should be written");
    let out_dir = dir.join("sdg");

    let status = std::process::Command::new("python3")
        .args([
            converter.to_str().expect("converter path should be utf-8"),
            "--rules",
            rules_file.to_str().expect("rules path should be utf-8"),
            "--output",
            out_dir.to_str().expect("out path should be utf-8"),
        ])
        .status()
        .expect("the converter should run");
    assert!(status.success(), "convert_to_sdg.py should succeed");

    // The generated directory loads with the actual Rust parser.
    let sdg = SemanticDependencyGraph::from_dir(&out_dir)
        .expect("the generated rule directory should load");
    assert_eq!(sdg.rules.len(), 1, "one canonical rule");
    let rule = &sdg.rules[0];
    assert_eq!(
        rule.name,
        "rule:probe|target:mmio:273:1:rss_max_key_size|predicate:gt:unsigned:40"
    );
    // Semantic rules carry the evaluable precondition in the private
    // semantic record; the public contract is the status and the resolved
    // runtime bindings.
    let semantic = rule.semantic.as_ref().expect("the rule is semantic");
    assert_eq!(semantic.status, "conditional");
    assert!(semantic.blockers.is_empty(), "the rule's sources are bound: {:?}", semantic.blockers);

    // Semantic generation: the actual Generator registers the semantic
    // scenario and its exact placements for the encoded bytes.
    let generator = generator_from_rules_dir(&out_dir);
    let mut state = TestState { rand: StdRand::with_seed(5) };
    let input: ScenarioInput = libafl::generators::Generator::generate(&mut generator.clone(), &mut state)
        .expect("generation should satisfy the rule");
    assert!(input.is_valid());
    let scenario = generator
        .metadata()
        .lookup(&input)
        .expect("generation registers corpus metadata for the encoded bytes");
    assert_eq!(scenario.target_rule, rule.name);
    let features = scenario
        .value("mmio:16:4:features")
        .expect("the precondition variable is present")
        .as_u64()
        .unwrap();
    assert!(features & (1 << 25) != 0, "the BitSet precondition holds");
    // Runtime scenarios encode the source observations; the sink stays in
    // the document for traceability.
    assert!(
        scenario.value("mmio:273:1:rss_max_key_size").is_none(),
        "the sink is not part of the runtime scenario"
    );
    // Placements are recorded for every source observation.
    assert!(scenario.placements.contains_key("mmio:16:4:features"));
    assert!(!scenario.placements.contains_key("mmio:273:1:rss_max_key_size"));

    // Lowering produces the wire format with aligned word models; the
    // scenario reads back from the wire through its exact placements.
    assert!(
        input.mmio.word_models.iter().any(|m| m.offset == 0x10),
        "the feature word is modelled"
    );
    let lifted = libafl_nesting::lift_with(&input, rule, &scenario.placements)
        .expect("the scenario lifts back through its exact placements");
    assert_eq!(lifted.values, scenario.values, "the wire encodes the scenario values");

    // The actual Mutator trait path mutates the exact stored scenario and
    // registers the child scenario for the child bytes.
    let mut mutator = ScenarioMutator::new(generator.clone());
    let parent_placement = scenario
        .placements
        .get("mmio:16:4:features")
        .copied()
        .expect("the source placement is recorded");
    let mut validated_child = None;
    for seed in 0..128u64 {
        let mut candidate = input.clone();
        let mut rng = TestState { rand: StdRand::with_seed(seed) };
        if !mutator
            .mutate(&mut rng, &mut candidate)
            .is_ok_and(|r| r == MutationResult::Mutated)
        {
            continue;
        }
        let child = generator
            .metadata()
            .lookup(&candidate)
            .expect("the mutator registers metadata for the child bytes");
        // The rule-aware branch mutates the exact stored scenario, so the
        // full placement map is preserved. A switched result carries fresh
        // random placements and is not this test's subject.
        if child.placements != scenario.placements {
            continue;
        }
        // Exact placement validation: the child keeps the source's stored
        // region and visit.
        assert_eq!(
            child.placements.get("mmio:16:4:features").copied(),
            Some(parent_placement),
            "only the stored source region and visit may be used"
        );
        // Exact target and precondition validation. A switched result can
        // coincide with the parent here (same single rule, same initial
        // value); the value change identifies a rule-aware mutation.
        let child_features = child
            .value("mmio:16:4:features")
            .expect("the source variable survives")
            .as_u64()
            .unwrap();
        if child_features == features {
            continue;
        }
        assert!(
            child_features & (1 << 25) != 0,
            "the precondition is preserved: {child_features}"
        );
        // The child scenario lifts back from the child bytes.
        let child_lifted =
            libafl_nesting::lift_with(&candidate, rule, &child.placements)
                .expect("the child scenario lifts back from the child bytes");
        assert_eq!(child_lifted.values, child.values);
        validated_child = Some((candidate, child));
        break;
    }
    assert!(validated_child.is_some(), "the rule-aware mutation should apply");
    let (child_input, _) = validated_child.unwrap();
    assert_ne!(encode_of(&child_input), encode_of(&input), "the child bytes differ");

    std::fs::remove_dir_all(&dir).expect("temp dir should be removed");
}

fn encode_of(input: &ScenarioInput) -> Vec<u8> {
    libafl_nesting::encode_scenario(input)
}
