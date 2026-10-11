import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--codeql", default="codeql")
    arguments = parser.parse_args()
    work = arguments.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    original_tests = Path(__file__).resolve().parent
    snapshot = Path(tempfile.mkdtemp(prefix="snapshot-", dir=work))
    for directory in ("queries", "scripts", "tests"):
        shutil.copytree(original_tests.parent / directory, snapshot / directory,
                        ignore=shutil.ignore_patterns(".cache", "__pycache__", "*.qlx"))
    tests = snapshot / "tests"
    query_directory = snapshot / "queries"
    sources = ("semantic_paths.c", "semantic_consumer.c", "semantic_interrupts.c", "semantic_dma.c")
    commands = [["cc", "-O1", "-g", "-fno-strict-overflow", "-c", source,
                 "-o", str(work / (source + ".o"))] for source in sources]
    (work / "sources.txt").write_text("\n".join(sources) + "\n")
    database = arguments.database or work / "database"
    if arguments.database is None:
        command = [arguments.codeql, "database", "create", str(database), "--language=cpp",
                   "--source-root=" + str(tests / "fixtures"), "--overwrite"]
        for compile_command in commands:
            command.append("--command=" + shlex.join(compile_command))
        subprocess.run(command, check=True)
    subprocess.run([sys.executable, str(snapshot / "scripts" / "verify_database.py"),
                    "--database", str(database), "--input-list", str(work / "sources.txt"),
                    "--source-root", str(tests / "fixtures")], check=True)
    plan = work / "compile-plan.json"
    if arguments.database is None:
        plan.write_text(json.dumps([{"arguments": command, "output": command[-1]} for command in commands]))
    elif not plan.is_file():
        raise ValueError("reused regression objects require their original compile-plan.json")
    subprocess.run([sys.executable, str(tests.parent / "scripts" / "target_info.py"),
                    "--plan", str(plan),
                    "--output", str(work / "target.json")], check=True)
    for name, query in (("facts", "KernelExtract"), ("paths", "KernelPaths")):
        bqrs = work / (name + ".bqrs")
        subprocess.run([arguments.codeql, "query", "run",
                        str(query_directory / "sdg" / (query + ".ql")),
                        "--database=" + str(database), "--output=" + str(bqrs),
                        "--threads=2", "--ram=6000"], check=True)
        subprocess.run([arguments.codeql, "bqrs", "decode", str(bqrs), "--format=csv",
                        "--output=" + str(work / (name + ".csv"))], check=True)
    environment = dict(os.environ, SDG_TEST_FACTS=str(work / "facts.csv"),
                       SDG_TEST_PATHS=str(work / "paths.csv"), SDG_TEST_TARGET=str(work / "target.json"))
    subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(tests),
                    "-p", "test_semantics.py", "-v"], env=environment, check=True)


if __name__ == "__main__":
    main()
