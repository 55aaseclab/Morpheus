import argparse
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--libafl-root", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--semantic", action="store_true")
    parser.add_argument("--tests", action="store_true")
    parser.add_argument("--release", action="store_true",
                        help="use an optimized build for large rule directories")
    arguments = parser.parse_args()
    tests = Path(__file__).resolve().parent
    overlay = tests.parents[1] / "libafl" / "patches" / "overlay" / "crates" / "libafl_nesting" / "src"
    work = arguments.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    dependencies = []
    for name in ("libafl", "libafl_bolts"):
        path = arguments.libafl_root.resolve() / "crates" / name
        dependencies.append(name + " = { path = " + json.dumps(str(path)) +
                            ', default-features = false, features = ["std"] }')
    (work / "Cargo.toml").write_text(
        '[package]\nname = "sdg-runtime-check"\nversion = "0.0.0"\nedition = "2024"\n'
        '[workspace]\n[features]\ndefault = ["std"]\nstd = []\n'
        '[[bin]]\nname = "sdg-runtime-check"\npath = "main.rs"\n'
        '[dependencies]\n' + "\n".join(dependencies) + '\n'
        'serde = { version = "1", features = ["derive"] }\n'
        'serde_json = "1"\nsha2 = "0.10"\nflate2 = "1"\n')
    # LibAFL's SIMD implementation uses the wide 1.1 API; later releases
    # deprecate it while LibAFL treats deprecation warnings as errors.
    with (work / "Cargo.toml").open("a") as stream:
        stream.write('wide = "=1.1.1"\n')
    modules = "\n".join('#[path = ' + json.dumps(str(overlay / (name + ".rs"))) +
                        "]\nmod " + name + ";" for name in
                        ("input", "encoding", "sdg", "metadata", "generator", "mutator"))
    modules += "\npub use input::MAX_ENCODED_SCENARIO_BYTES;\n"
    runner = "semantic_runtime_check.rs" if arguments.semantic else "runtime_check.rs"
    (work / "main.rs").write_text(modules + "\n" + (tests / runner).read_text())
    lockfile = arguments.libafl_root / "Cargo.lock"
    if lockfile.exists() and not (work / "Cargo.lock").exists():
        shutil.copyfile(lockfile, work / "Cargo.lock")
    command = ["cargo", "test" if arguments.tests else "run", "--quiet", "--manifest-path", str(work / "Cargo.toml")]
    if arguments.release:
        command.append("--release")
    command += ["--", "--test-threads=1"] if arguments.tests else ["--", str(arguments.rules.resolve())]
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
