#!/usr/bin/env python3
"""Export complete version 1.2 semantic dependency graphs as self-contained .sdg files."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys


VERSION = "1.2"
HEADS = {"head_guard", "head_dataflow", "head_bound", "head_offset", "head_call"}


def token(value):
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        raise ValueError(f"invalid record identifier: {value!r}")
    return value


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def index_records(records, kind):
    indexed = {}
    for record in records:
        identity = token(record["id"])
        if identity in indexed:
            raise ValueError(f"duplicate {kind}: {identity}")
        indexed[identity] = record
    return indexed


def node_references(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"node", "src", "dst", "var"} and isinstance(child, str):
                yield child
            else:
                yield from node_references(child)
    elif isinstance(value, list):
        for child in value:
            yield from node_references(child)


def validate_graph(rule, nodes, edges):
    token(rule["id"])
    variables = rule.get("vars")
    if not isinstance(variables, list) or any(not isinstance(item, str) for item in variables):
        raise ValueError("version 1.2 vars must contain node IDs")
    declared = set(variables)
    if len(declared) != len(variables):
        raise ValueError("duplicate rule variable")
    missing_nodes = declared - nodes.keys()
    if missing_nodes:
        raise ValueError("missing node: " + min(missing_nodes))
    for identity in declared:
        node = nodes[identity]
        if node.get("id") != identity or node.get("kind") not in {"source", "internal", "sink"}:
            raise ValueError("invalid node record: " + identity)
    path = rule["path"]
    edge_ids = path["edges"]
    if not isinstance(edge_ids, list) or any(not isinstance(item, str) for item in edge_ids):
        raise ValueError("version 1.2 path.edges must contain edge IDs")
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("duplicate path edge")
    missing_edges = set(edge_ids) - edges.keys()
    if missing_edges:
        raise ValueError("missing edge: " + min(missing_edges))
    required = {path["source"], path["sink"]}
    required.update(node_references(rule))
    required.update(path.get("source_observations", []))
    required.update(path.get("alternatives", {}).get("nodes", []))
    for context in path.get("equivalent_contexts", []):
        required.update(context["witness_nodes"])
    validation = rule.get("validation", {})
    required.update(validation.get("source_assignments", {}))
    required.update(validation.get("assumed_internal_values", {}))
    required.update(validation.get("internal_state_witness", {}))
    for identity in declared:
        required.update(nodes[identity].get("expressions", []))
    for identity in edge_ids:
        edge = edges[identity]
        if edge.get("id") != identity or edge.get("head") not in HEADS or not edge.get("predicate"):
            raise ValueError("invalid edge record: " + identity)
        required.update((edge["src"], edge["dst"]))
        required.update(node_references(edge))
    target = rule["target_state"]
    if target.get("head") not in HEADS or not target.get("predicate"):
        raise ValueError("invalid target edge")
    required.update((target["src"], target["dst"]))
    if required - declared:
        raise ValueError("undeclared node reference: " + min(required - declared))
    if nodes[path["source"]]["kind"] != "source" or nodes[path["sink"]]["kind"] != "sink":
        raise ValueError("invalid source or sink endpoint kind")
    for hint in rule.get("mutation_hint", []):
        if nodes[hint["var"]]["kind"] != "source":
            raise ValueError("mutation destination is not a source: " + hint["var"])


def render_sdg(rule, nodes, edges):
    validate_graph(rule, nodes, edges)
    lines = ["sdg " + VERSION, "rule " + token(rule["id"])]
    for key in sorted(rule.keys() - {"id"}):
        lines.append(f"field {token(key)} {encode(rule[key])}")
    for identity in sorted(rule["vars"]):
        node = nodes[identity]
        metadata = {key: value for key, value in node.items() if key not in {"id", "kind"}}
        lines.append(f"node {token(identity)} {node['kind']} {encode(metadata)}")
    for identity in sorted(rule["path"]["edges"]):
        edge = edges[identity]
        metadata = {key: value for key, value in edge.items() if key not in {"id", "src", "dst", "head"}}
        lines.append(f"edge {token(identity)} {token(edge['src'])} {token(edge['dst'])} "
                     f"{edge['head']} {encode(metadata)}")
    return "\n".join(lines) + "\n"


def parse_sdg(text):
    lines = text.splitlines()
    if not lines or lines[0] != "sdg " + VERSION:
        raise ValueError("expected sdg 1.2 header")
    rule, nodes, edges = {}, {}, {}
    for line_number, line in enumerate(lines[1:], 2):
        if not line.strip():
            continue
        kind = line.partition(" ")[0]
        try:
            if kind == "rule":
                if "id" in rule:
                    raise ValueError("duplicate rule")
                rule["id"] = token(line.split(" ", 1)[1])
            elif kind == "field":
                _, name, payload = line.split(" ", 2)
                token(name)
                if name == "id" or name in rule:
                    raise ValueError("duplicate field: " + name)
                rule[name] = json.loads(payload)
            elif kind == "node":
                _, identity, node_kind, payload = line.split(" ", 3)
                token(identity)
                if identity in nodes:
                    raise ValueError("duplicate node: " + identity)
                metadata = json.loads(payload)
                if not isinstance(metadata, dict) or {"id", "kind"} & metadata.keys():
                    raise ValueError("invalid node metadata")
                nodes[identity] = {"id": identity, "kind": node_kind, **metadata}
            elif kind == "edge":
                _, identity, source, destination, head, payload = line.split(" ", 5)
                token(identity)
                if identity in edges:
                    raise ValueError("duplicate edge: " + identity)
                metadata = json.loads(payload)
                if not isinstance(metadata, dict) or {"id", "src", "dst", "head"} & metadata.keys():
                    raise ValueError("invalid edge metadata")
                edges[identity] = {"id": identity, "src": token(source), "dst": token(destination),
                                   "head": head, **metadata}
            else:
                raise ValueError("unknown record: " + kind)
        except (ValueError, IndexError) as error:
            raise ValueError(f"line {line_number}: {error}") from error
    validate_graph(rule, nodes, edges)
    if set(nodes) != set(rule["vars"]) or set(edges) != set(rule["path"]["edges"]):
        raise ValueError("graph has records outside the rule")
    return {"version": VERSION, "rule": rule,
            "nodes": [nodes[key] for key in sorted(nodes)],
            "edges": [edges[key] for key in sorted(edges)]}


def filename(rule_id):
    return "rule-" + hashlib.sha256(rule_id.encode()).hexdigest() + ".sdg"


def repackage(source, destination, old_record, rule):
    """Hash-check a previous semantic export and retain its exact graph records."""
    old_hash, new_hash = hashlib.sha256(), hashlib.sha256()
    temporary = destination.with_suffix(".tmp")
    with source.open("rb") as reader, temporary.open("wb") as writer:
        def emit(data):
            writer.write(data)
            new_hash.update(data)
        emit(("sdg 1.2\nrule " + rule["id"] + "\n").encode())
        for key in sorted(rule.keys() - {"id"}):
            emit((f"field {key} {encode(rule[key])}\n").encode())
        body = False
        for line in reader:
            old_hash.update(line)
            if line.startswith((b"node ", b"edge ")):
                body = True
            if body:
                emit(line)
    if old_hash.hexdigest() != old_record["sha256"]:
        temporary.unlink()
        raise ValueError("original export hash mismatch: " + str(source))
    temporary.replace(destination)
    return {**old_record, "status": rule["status"], "sha256": new_hash.hexdigest()}


def export_rules(rules, nodes, edges, output):
    indexed_rules = index_records(rules, "rule")
    return export_rule_stream(lambda: iter(indexed_rules.values()), nodes, edges, output)


def export_rule_stream(records, nodes, edges, output):
    identities = set()
    for rule in records():
        if rule["id"] in identities:
            raise ValueError("duplicate rule: " + rule["id"])
        identities.add(rule["id"])
        validate_graph(rule, nodes, edges)
    output = Path(output)
    manifest_path = output / "manifest.json"
    previous = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    if previous and previous.get("format") != "semantic-sdg":
        raise ValueError("output directory belongs to another exporter")
    output.mkdir(parents=True, exist_ok=True)
    manifest_records = []
    for rule in records():
        identity = rule["id"]
        name = filename(identity)
        rendered = render_sdg(rule, nodes, edges)
        restored = parse_sdg(rendered)
        if (restored["rule"] != rule or
                {node["id"]: node for node in restored["nodes"]} != {key: nodes[key] for key in rule["vars"]} or
                {edge["id"]: edge for edge in restored["edges"]} != {key: edges[key] for key in rule["path"]["edges"]}):
            raise ValueError("SDG round-trip mismatch: " + identity)
        temporary = output / (name + ".tmp")
        temporary.write_text(rendered, encoding="utf-8")
        temporary.replace(output / name)
        cross_count = sum(edges[key]["src"] != edges[key]["dst"] for key in rule["path"]["edges"])
        manifest_records.append({"id": identity, "status": rule["status"], "file": name,
                        "sha256": hashlib.sha256(rendered.encode()).hexdigest(),
                        "nodes": len(rule["vars"]), "cross_edges": cross_count,
                        "self_edges": len(rule["path"]["edges"]) - cross_count,
                        "target_edges": 1})
    manifest_records.sort(key=lambda record: record["id"])
    manifest = {"version": VERSION, "format": "semantic-sdg", "count": len(manifest_records),
                "statuses": dict(Counter(record["status"] for record in manifest_records)),
                "rules": manifest_records}
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    temporary.replace(manifest_path)
    current_files = {record["file"] for record in manifest_records}
    for record in previous.get("rules", []):
        name = record.get("file", "")
        if re.fullmatch(r"rule-[0-9a-f]{64}\.sdg", name) and name not in current_files:
            (output / name).unlink(missing_ok=True)
    return manifest


def read_artifact(path):
    artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    if artifact.get("version") != VERSION:
        raise ValueError(f"{path}: expected version 1.2 query artifact")
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--nodes", type=Path)
    parser.add_argument("--edges", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rule-id", action="append", default=[])
    arguments = parser.parse_args()
    try:
        rules = read_artifact(arguments.rules)["rules"]
        indexed_rules = index_records(rules, "rule")
        if arguments.rule_id:
            missing = set(arguments.rule_id) - indexed_rules.keys()
            if missing:
                raise ValueError("rule IDs not found: " + ", ".join(sorted(missing)))
            rules = [indexed_rules[identity] for identity in sorted(set(arguments.rule_id))]
        nodes_file = arguments.nodes or arguments.rules.with_name("sdg-nodes.json")
        edges_file = arguments.edges or arguments.rules.with_name("sdg-edges.json")
        nodes = index_records(read_artifact(nodes_file)["nodes"], "node")
        raw_edges = read_artifact(edges_file)
        edges = index_records(raw_edges["self_edges"] + raw_edges["cross_edges"], "edge")
        manifest = export_rules(rules, nodes, edges, arguments.output)
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"SDG export failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"count": manifest["count"], "statuses": manifest["statuses"],
                      "manifest": str(arguments.output / "manifest.json")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
