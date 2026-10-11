import argparse
import hashlib
import json
from pathlib import Path
import zipfile

from compile_sources import source_files


def verify(database, input_list, source_root):
    root = Path(source_root).resolve(strict=True)
    sources = source_files(input_list, root)
    with zipfile.ZipFile(Path(database) / "src.zip") as archive:
        names = archive.namelist()
        prefixes = set()
        for source in sources:
            relative = source.relative_to(root).as_posix()
            matches = [name for name in names if name == relative or name.endswith("/" + relative)]
            if len(matches) != 1:
                raise ValueError(f"missing or ambiguous database snapshot for {relative}")
            archived = matches[0]
            if archive.read(archived) != source.read_bytes():
                raise ValueError(f"database snapshot differs from source: {relative}")
            prefixes.add(archived[:-len(relative)])
        if len(prefixes) != 1:
            raise ValueError("source files do not share one database source root")
        prefix = prefixes.pop()
        checked = 0
        for name in names:
            if not name.startswith(prefix) or name.endswith("/"):
                continue
            relative = name[len(prefix):]
            source = (root / relative).resolve()
            if not source.is_relative_to(root):
                raise ValueError(f"snapshot path escapes source root: {relative}")
            if not source.is_file() or archive.read(name) != source.read_bytes():
                raise ValueError(f"database snapshot differs from source: {relative}")
            checked += 1
    files = [source.relative_to(root).as_posix() for source in sources]
    return {"input_count": len(sources), "input_files": files,
            "input_list_sha256": hashlib.sha256("\n".join(files).encode()).hexdigest(),
            "matching_snapshot_files": checked}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--input-list", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(verify(arguments.database, arguments.input_list, arguments.source_root)))


if __name__ == "__main__":
    main()
