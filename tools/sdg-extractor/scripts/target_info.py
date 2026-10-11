import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def object_target(path, compiler=None):
    path = Path(path)
    with path.open("rb") as stream:
        header = stream.read(20)
    if header.startswith(b"\x7fELF"):
        if header[5] not in (1, 2) or header[4] not in (1, 2):
            raise ValueError(f"unsupported ELF target: {path}")
        byte_order = "Little" if header[5] == 1 else "Big"
        return {"byte_order": byte_order, "elf_class": 32 if header[4] == 1 else 64,
                "machine": int.from_bytes(header[18:20], byte_order.lower())}
    if header[:4] not in {b"BC\xc0\xde", b"\xde\xc0\x17\x0b"}:
        raise ValueError(f"unsupported compiled object: {path}")
    candidates = [os.environ.get("LLVM_DIS", "llvm-dis")]
    if compiler:
        match = re.search(r"clang(?:\+\+)?-(\d+)$", compiler)
        if match:
            candidates.insert(0, "llvm-dis-" + match.group(1))
    disassembler = next((shutil.which(candidate) for candidate in candidates if shutil.which(candidate)), None)
    if disassembler:
        command = [disassembler, str(path), "-o", "-"]
    else:
        raise ValueError("LLVM bitcode target inspection requires llvm-dis from the build's LLVM toolchain")
    result = {}
    with tempfile.TemporaryFile() as errors:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors) as process:
            for line in process.stdout:
                if line.startswith(b"target datalayout = "):
                    layout = line.decode().split('"')[1]
                    if layout[0] not in {"e", "E"}:
                        raise ValueError(f"LLVM data layout has no byte order: {path}")
                    result.update(byte_order="Little" if layout[0] == "e" else "Big", data_layout=layout)
                elif line.startswith(b"target triple = "):
                    result["triple"] = line.decode().split('"')[1]
            if process.wait() != 0:
                errors.seek(0)
                raise ValueError(errors.read().decode(errors="replace"))
    if "byte_order" not in result:
        raise ValueError(f"LLVM object does not specify its target byte order: {path}")
    return result


def signed_overflow_mode(arguments):
    active = {}
    for position, argument in enumerate(arguments):
        if argument in {"-fwrapv", "-fno-strict-overflow"}:
            active["Wrap"] = position
        elif argument in {"-fno-wrapv", "-fstrict-overflow"}:
            active.pop("Wrap", None)
        elif argument == "-ftrapv":
            active["Trap"] = position
        elif argument == "-fno-trapv":
            active.pop("Trap", None)
    return max(active, key=active.get) if active else "Undefined"


def capture_target(objects, compilers=None, commands=None):
    records = []
    for index, path in enumerate(objects):
        target = object_target(path, compilers[index] if compilers else None)
        with Path(path).open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        records.append({"object": str(path), "sha256": digest, **target,
                        "signed_overflow": signed_overflow_mode(commands[index]) if commands else "Unknown"})
    byte_orders = {record["byte_order"] for record in records}
    if len(byte_orders) != 1:
        raise ValueError("one extraction requires a consistent target byte order")
    overflow_modes = {record["signed_overflow"] for record in records}
    return {"byte_order": byte_orders.pop(), "evidence": records,
            "signed_overflow": overflow_modes.pop() if len(overflow_modes) == 1 else "Unknown"}


def main():
    parser = argparse.ArgumentParser()
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--plan", type=Path)
    inputs.add_argument("--objects", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.plan:
        plan = json.loads(arguments.plan.read_text())
        result = capture_target([entry["output"] for entry in plan], [entry["arguments"][0] for entry in plan],
                                [entry["arguments"] for entry in plan])
    else:
        result = capture_target(arguments.objects)
    arguments.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
