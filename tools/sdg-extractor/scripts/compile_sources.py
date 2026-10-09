import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shlex
import subprocess


def source_files(input_list, source_root):
    sources = []
    for entry in Path(input_list).read_text().splitlines():
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        source = Path(entry)
        if not source.is_absolute():
            source = source_root / source
        source = source.resolve(strict=True)
        if not source.is_file() or source.suffix not in {".c", ".cc", ".cpp"}:
            raise ValueError(f"not a C/C++ source file: {source}")
        sources.append(source)
    if not sources:
        raise ValueError("source list is empty")
    if len(sources) != len(set(sources)):
        raise ValueError("source list contains duplicate files")
    return sorted(sources)


def kernel_build_tree(path):
    root = Path(path).resolve(strict=True)
    candidates = [root] if (root / ".config").is_file() else sorted(
        child for child in root.glob("kbuild-*")
        if (child / ".config").is_file()
    )
    if len(candidates) != 1:
        raise ValueError(f"expected one configured kernel build tree in {root}")
    return candidates[0]


def recorded_command(source, source_root, build_tree, output):
    relative = source.relative_to(source_root)
    target = relative.with_suffix(".o")
    command_file = build_tree / target.parent / f".{target.name}.cmd"
    lines = command_file.read_text().splitlines()
    commands = [line.split(" := ", 1)[1] for line in lines
                if line.startswith(("savedcmd_", "cmd_")) and " := " in line]
    if len(commands) != 1:
        raise ValueError(f"missing or ambiguous compile command: {command_file}")
    command = shlex.split(commands[0])
    if any(token in {";", "&&", "||", "|", ">", "<"} for token in command):
        raise ValueError(f"unsupported compound compile command: {command_file}")
    if "-c" not in command or "-o" not in command:
        raise ValueError(f"not a compile command: {command_file}")
    command[command.index("-o") + 1] = str(output)
    command = [token for token in command if not token.startswith("-Wp,-MMD,")]
    for option in ("-MF", "-MT", "-MQ"):
        while option in command:
            offset = command.index(option)
            del command[offset:offset + 2]
    return {"directory": str(build_tree), "file": str(source),
            "arguments": command, "output": str(output)}


def compilation_plan(input_list, source_root, output_dir, kbuild_dir=None,
                     compilation_database=None):
    source_root = Path(source_root).resolve(strict=True)
    sources = source_files(input_list, source_root)
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    build_tree = kernel_build_tree(kbuild_dir) if kbuild_dir else None
    database = None
    if compilation_database:
        database = {}
        for entry in json.loads(Path(compilation_database).read_text()):
            directory = Path(entry["directory"]).resolve()
            filename = (directory / entry["file"]).resolve()
            if filename in database:
                raise ValueError(f"multiple compile commands for {filename}")
            database[filename] = entry
    plan = []
    for index, source in enumerate(sources):
        output = output_dir / f"{index:04d}.o"
        if database is not None:
            entry = database[source]
            command = list(entry.get("arguments") or shlex.split(entry["command"]))
            if "-o" in command:
                command[command.index("-o") + 1] = str(output)
            else:
                command.extend(["-o", str(output)])
            plan.append({"directory": entry["directory"], "file": str(source),
                         "arguments": command, "output": str(output)})
        elif build_tree:
            plan.append(recorded_command(source, source_root, build_tree, output))
        else:
            if (source_root / "Kconfig").exists():
                raise ValueError("kernel extraction requires recorded compile commands")
            plan.append({"directory": str(source_root), "file": str(source),
                         "arguments": [os.environ.get("CC", "cc"), "-c", "-O1",
                                       "-g", str(source), "-o", str(output)],
                         "output": str(output)})
    return plan


def compile_entry(entry):
    print(f"extracting {entry['file']}", flush=True)
    subprocess.run(entry["arguments"], cwd=entry["directory"], check=True)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("--input-list", type=Path, required=True)
    plan_parser.add_argument("--source-root", type=Path, required=True)
    plan_parser.add_argument("--output-dir", type=Path, required=True)
    plan_parser.add_argument("--kbuild-dir", type=Path, required=True)
    plan_parser.add_argument("--output-plan", type=Path, required=True)
    compile_parser = commands.add_parser("compile")
    compile_parser.add_argument("--plan", type=Path, required=True)
    compile_parser.add_argument("--jobs", type=int, default=1)
    arguments = parser.parse_args()
    if arguments.command == "plan":
        plan = compilation_plan(arguments.input_list, arguments.source_root,
                                arguments.output_dir, arguments.kbuild_dir)
        arguments.output_plan.parent.mkdir(parents=True, exist_ok=True)
        arguments.output_plan.write_text(json.dumps(plan, indent=2) + "\n")
        print(f"planned {len(plan)} translation units")
        return
    if arguments.jobs < 1:
        parser.error("jobs must be positive")
    plan = json.loads(arguments.plan.read_text())
    with concurrent.futures.ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        for result in pool.map(compile_entry, plan):
            pass


if __name__ == "__main__":
    main()
