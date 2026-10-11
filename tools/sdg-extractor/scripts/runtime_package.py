"""Build a portable runtime package with deduplicated, lossless evidence."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import time
import zlib

from convert_to_sdg import validate_graph


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class EvidenceWriter:
    def __init__(self, stream):
        self.stream, self.records, self.index = stream, {}, []

    def put(self, raw):
        key = digest(raw)
        if key not in self.records:
            data = zlib.compress(raw, 6)
            offset = self.stream.tell()
            self.stream.write(data)
            self.records[key] = len(self.index)
            self.index.append([offset, len(data), len(raw), key])
        return self.records[key]


def read_blob(stream, reference):
    offset, size, raw_size, checksum = reference
    stream.seek(offset)
    data = zlib.decompress(stream.read(size))
    if len(data) != raw_size or digest(data) != checksum:
        raise ValueError("evidence blob integrity mismatch")
    return data


def restore_document(archive, reference, index_reference=None):
    with Path(archive).open("rb") as stream:
        if index_reference is None:
            index_reference = json.loads(Path(archive).with_name("manifest.json").read_text())["evidence_index"]
        index = json.loads(read_blob(stream, index_reference))
        recipe = json.loads(read_blob(stream, index[reference]))
        chunks = []
        for group in recipe:
            chunks.extend(read_blob(stream, index[item]) for item in json.loads(read_blob(stream, index[group])))
        return b"".join(chunks)


def references(value):
    if isinstance(value, dict):
        if isinstance(value.get("node"), str):
            yield value["node"]
        for child in value.values():
            yield from references(child)
    elif isinstance(value, list):
        for child in value:
            yield from references(child)


def runtime_plan(rule, nodes, edges):
    """Keep all sources and the same unambiguous definitions used by runtime.

    Full paths, targets and proof records remain in the lossless evidence file.
    A runtime plan supplies guidance; it never promotes the recorded proof status.
    """
    definitions, ambiguous = {}, set()
    for edge in edges.values():
        p, dst = edge["predicate"], edge["dst"]
        if (edge["head"] != "head_guard" and p.get("kind") == "Eq" and
                p.get("left", {}).get("node") == dst and isinstance(p.get("right"), dict)):
            if dst in definitions and definitions[dst] != p["right"]:
                ambiguous.add(dst)
            definitions[dst] = p["right"]
    for key in ambiguous:
        definitions.pop(key, None)
    required = {key for key, node in nodes.items() if node["kind"] == "source"}
    pending = list(references(rule["preconditions"]))
    visited, selected = set(), {}
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        required.add(key)
        if key in definitions and nodes[key]["kind"] != "source":
            selected[key] = definitions[key]
            pending.extend(references(definitions[key]))
    return {
        "nodes": {key: {k: v for k, v in nodes[key].items() if k in ("id", "kind", "type", "source")}
                  for key in sorted(required)},
        "definitions": selected,
        "preconditions": rule["preconditions"],
        "mutation_hint": [{k: v for k, v in hint.items() if k != "derivation"}
                          for hint in rule["mutation_hint"]],
        "validation": {k: v for k, v in rule["validation"].items()
                       if k in ("result", "source_assignments")},
    }


def build_package(source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    if source == output or source in output.parents or output in source.parents:
        raise ValueError("package output must be separate from semantic exports")
    manifest = json.loads((source / "manifest.json").read_text())
    if manifest.get("format") != "semantic-sdg" or manifest.get("version") != "1.2":
        raise ValueError("expected complete semantic-sdg 1.2 exports")
    if output.exists():
        raise ValueError("package output already exists")
    staging = output.with_name(output.name + ".partial")
    staging.mkdir(parents=True, exist_ok=False)
    node_cache, edge_cache, plans, plan_ids, rules = {}, {}, [], {}, []
    total_bytes, last_progress = 0, time.monotonic()
    try:
        with (staging / "evidence.pack").open("wb") as evidence:
            writer = EvidenceWriter(evidence)
            for record in sorted(manifest["rules"], key=lambda r: r["file"]):
                path = source / record["file"]
                if path.parent != source or path.suffix != ".sdg":
                    raise ValueError("invalid export filename")
                fields, nodes, edges = {}, {}, {}
                groups = [[], [], []]
                hasher = hashlib.sha256()
                with path.open("rb") as stream:
                    for index, raw in enumerate(stream):
                        hasher.update(raw)
                        total_bytes += len(raw)
                        line = raw.decode().rstrip("\r\n")
                        kind = line.partition(" ")[0]
                        group = 1 if kind == "node" else 2 if kind == "edge" else 0
                        groups[group].append(writer.put(raw))
                        if index == 0:
                            if line != "sdg 1.2":
                                raise ValueError("invalid semantic header")
                        elif kind == "rule":
                            fields["id"] = line.split(" ", 1)[1]
                        elif kind == "field":
                            _, key, payload = line.split(" ", 2)
                            fields[key] = json.loads(payload)
                        elif kind in ("node", "edge"):
                            cache = node_cache if kind == "node" else edge_cache
                            key = groups[group][-1]
                            if key not in cache:
                                if kind == "node":
                                    _, identity, node_kind, payload = line.split(" ", 3)
                                    cache[key] = {"id": identity, "kind": node_kind, **json.loads(payload)}
                                else:
                                    _, identity, src, dst, head, payload = line.split(" ", 5)
                                    cache[key] = {"id": identity, "src": src, "dst": dst, "head": head, **json.loads(payload)}
                            item = cache[key]
                            (nodes if kind == "node" else edges)[item["id"]] = item
                        elif line:
                            raise ValueError("unknown semantic record")
                if hasher.hexdigest() != record["sha256"] or fields["id"] != record["id"]:
                    raise ValueError("semantic export integrity mismatch: " + record["id"])
                validate_graph(fields, nodes, edges)
                plan = runtime_plan(fields, nodes, edges)
                plan_hash = digest(encode(plan))
                if plan_hash not in plan_ids:
                    plan_ids[plan_hash] = len(plans)
                    plans.append(plan)
                recipe = writer.put(encode([writer.put(encode(group)) for group in groups]))
                rules.append({"id": fields["id"], "status": fields["status"],
                              "source": fields["path"]["source"], "plan": plan_ids[plan_hash],
                              "document": recipe, "document_sha256": record["sha256"]})
                if time.monotonic() - last_progress > 20:
                    print(json.dumps({"phase": "package", "rules": len(rules), "plans": len(plans),
                                      "evidence_bytes": evidence.tell()}), flush=True)
                    last_progress = time.monotonic()
            index_reference = writer.index[writer.put(encode(writer.index))]
        (staging / "runtime.json").write_bytes(encode({"plans": plans, "rules": rules}) + b"\n")
        result = {"format": "sdg-runtime-package", "version": 1, "rules": len(rules),
                  "plans": len(plans), "irq_policy": "ignored", "source_bytes": total_bytes,
                  "evidence_index": index_reference,
                  "source_manifest_sha256": file_digest(source / "manifest.json"),
                  "files": {name: {"bytes": (staging / name).stat().st_size,
                                   "sha256": file_digest(staging / name)}
                            for name in ("runtime.json", "evidence.pack")}}
        (staging / "manifest.json").write_bytes(encode(result) + b"\n")
        staging.rename(output)
        return result
    except BaseException:
        shutil.rmtree(staging)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--result-file", type=Path)
    args = parser.parse_args()
    result = build_package(args.source, args.output)
    managed = {"command": "exec", "status": "success", "exit_code": 0,
               "summary": "built final runtime rule package", "details": result,
               "artifacts": [{"path": "sdg-runtime-package", "location": str(args.output.resolve())}]}
    if args.result_file:
        args.result_file.write_text(json.dumps(managed, indent=2) + "\n")
    print(json.dumps(managed))


if __name__ == "__main__":
    main()
