"""Verify guidance publication and preservation of the Z3 analysis records."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from convert_to_sdg import encode
from guidance import derive_hints, domain, mutate_value
from guidance_export import records
from publication import publication_errors
from path_evidence import NativePaths, connected


def check_export(path, record, rule, nodes, edges, node_lines, edge_lines):
    """Compare every serialized record with its shared artifact exactly.

    Canonical node/edge lines can be reused across graphs, but every byte of
    every export is still read, hashed, and compared against the shared graph.
    """
    digest = hashlib.sha256()
    restored, seen_nodes, seen_edges = {}, set(), set()
    with path.open("rb") as stream:
        for index, line in enumerate(stream):
            digest.update(line)
            if index == 0:
                assert line == b"sdg 1.2\n"
            elif line.startswith(b"rule "):
                assert "id" not in restored
                restored["id"] = line.decode().rstrip("\n").split(" ", 1)[1]
            elif line.startswith(b"field "):
                _, name, value = line.decode().split(" ", 2)
                assert name not in restored
                restored[name] = json.loads(value)
            elif line.startswith(b"node "):
                identity = line.split(b" ", 2)[1].decode()
                assert identity not in seen_nodes
                seen_nodes.add(identity)
                if identity not in node_lines:
                    node = nodes[identity]
                    metadata = {k:v for k,v in node.items() if k not in {"id", "kind"}}
                    node_lines[identity] = f"node {identity} {node['kind']} {encode(metadata)}\n".encode()
                assert line == node_lines[identity], identity
            elif line.startswith(b"edge "):
                identity = line.split(b" ", 2)[1].decode()
                assert identity not in seen_edges
                seen_edges.add(identity)
                if identity not in edge_lines:
                    edge = edges[identity]
                    metadata = {k:v for k,v in edge.items() if k not in {"id", "src", "dst", "head"}}
                    edge_lines[identity] = (f"edge {identity} {edge['src']} {edge['dst']} "
                                            f"{edge['head']} {encode(metadata)}\n").encode()
                assert line == edge_lines[identity], identity
            else:
                raise AssertionError("unknown export record: " + str(path))
    assert digest.hexdigest() == record["sha256"]
    assert restored == rule
    assert seen_nodes == set(rule["vars"])
    assert seen_edges == set(rule["path"]["edges"])
    assert record["nodes"] == len(seen_nodes)
    cross_count = sum(edges[key]["src"] != edges[key]["dst"] for key in seen_edges)
    assert record["cross_edges"] == cross_count
    assert record["self_edges"] == len(seen_edges) - cross_count


def check(output, original=None):
    preserved_artifacts = []
    if original:
        for name in ("sdg-nodes.json", "sdg-edges.json", "assumption-policy.json", "assumption-ledger.json",
                     "analysis-coverage.json", "path-assumptions.csv", "path-assumptions.md"):
            with (output / name).open("rb") as current, (original / name).open("rb") as previous:
                assert hashlib.file_digest(current, "sha256").digest() == hashlib.file_digest(previous, "sha256").digest(), name
            preserved_artifacts.append(name)
    nodes = {n["id"]: n for n in json.loads((output / "sdg-nodes.json").read_text())["nodes"]}
    raw = json.loads((output / "sdg-edges.json").read_text())
    edges = {e["id"]: e for e in raw["self_edges"] + raw["cross_edges"]}
    del raw
    native_paths = NativePaths(output / "work" / "paths.csv", nodes)
    exports = {}
    published_ids = set()
    for directory in ("sdg", "sdg-conditional", "sdg-unresolved"):
        manifest = json.loads((output / directory / "manifest.json").read_text())
        assert manifest["count"] == len(manifest["rules"])
        assert {p.name for p in (output / directory).glob("*.sdg")} == {r["file"] for r in manifest["rules"]}
        for record in manifest["rules"]:
            assert record["id"] not in exports
            exports[record["id"]] = directory, record
            if directory == "sdg":
                published_ids.add(record["id"])
    published = iter(records(output / "sdg-rules.json"))
    originals = iter(records(original / "sdg-candidates.json")) if original else None
    statuses, operators, published_statuses = Counter(), Counter(), Counter()
    checked = set()
    executed = equivalent_contexts = preserved_proofs = verified_paths = 0
    last_progress = time.monotonic()
    node_lines, edge_lines = {}, {}
    for rule in records(output / "sdg-candidates.json"):
        identity = rule["id"]
        assert identity not in checked
        checked.add(identity)
        assert rule["publication"]["threshold"] == "basic"
        assert not rule["publication"]["solver_success_required"]
        assert rule.get("path_evidence") == native_paths.evidence(rule), identity
        verified_paths += bool(rule.get("path_evidence"))
        statuses[rule["status"]] += 1
        expected = derive_hints(rule, nodes, edges)
        assert expected == rule["mutation_hint"], identity
        errors = publication_errors(rule, nodes, edges, {})
        assert (not errors) == (identity in published_ids), (identity, errors)
        if identity in published_ids:
            assert connected(rule, nodes, edges), identity
            assert rule["mutation_hint"], identity
            assert next(published) == rule
            published_statuses[rule["status"]] += 1
        if originals:
            old = next(originals)
            assert old["id"] == identity
            for key in ("status", "validation", "assumptions", "preconditions", "path", "target_state", "vars", "runtime_export"):
                assert old.get(key) == rule.get(key), (identity, key)
            assert rule["enhancement"]["mutation_hint"] == old["mutation_hint"]
        if rule["validation"].get("assumption_proof", {}).get("proven"):
            preserved_proofs += 1
        path = rule["path"]
        alternative_nodes = set(path.get("alternatives", {}).get("nodes", []))
        alternative_steps = {(s["src"], s["dst"]) for s in path.get("alternatives", {}).get("steps", [])}
        contexts = {path.get("context_id")}
        for context in path.get("equivalent_contexts", []):
            assert context["context_id"] not in contexts
            contexts.add(context["context_id"])
            assert set(context["witness_nodes"]) <= alternative_nodes
            assert set(zip(context["witness_nodes"], context["witness_nodes"][1:])) <= alternative_steps
            equivalent_contexts += 1
        directory, record = exports[identity]
        assert record["status"] == rule["status"]
        check_export(output / directory / record["file"], record, rule, nodes, edges, node_lines, edge_lines)
        for hint in rule["mutation_hint"]:
            node = nodes[hint["var"]]
            assert node["kind"] == "source"
            operators[hint["operator"]] += 1
            if hint["operator"] == "DeliverIrq":
                assert node["source"]["kind"] == "Irq"
                assert hint["handler"] == node["source"]["handler"]
                continue
            width, minimum, maximum = domain(node)
            mask = (1 << width) - 1
            for value in {0, 1, mask, minimum & mask, maximum}:
                result = mutate_value(hint, node, value)
                if result is None:
                    continue
                assert 0 <= result <= mask
                signed_result = result - (1 << width) if minimum < 0 and result >= 1 << (width-1) else result
                signed_value = value - (1 << width) if minimum < 0 and value >= 1 << (width-1) else value
                if hint["operator"] == "Inc": assert signed_result == signed_value + hint["delta"]
                if hint["operator"] == "Dec": assert signed_result == signed_value - hint["delta"]
                if hint["operator"] == "SetBoundary":
                    assert signed_result == hint["boundary"] + {"Above":1, "Below":-1, "At":0}[hint["side"]]
                if hint["operator"] == "SetBits": assert result & hint["mask"] == hint["mask"]
                if hint["operator"] == "ClearBits": assert result & hint["mask"] == 0
                executed += 1
        if time.monotonic() - last_progress >= 30:
            print(json.dumps({"phase": "verify_guidance", "candidates": len(checked), "total": len(exports),
                              "mutation_cases": executed}), file=sys.stderr, flush=True)
            last_progress = time.monotonic()
    assert next(published, None) is None
    if originals: assert next(originals, None) is None
    assert checked == exports.keys()
    summary = json.loads((output / "sdg-diagnostics.json").read_text())["summary"]
    assert dict(statuses) == summary["candidate_statuses"]
    assert len(published_ids) == summary["rules"]
    coverage = json.loads((output / "analysis-coverage.json").read_text())
    assert coverage["candidate_count"] == len(checked)
    assert coverage["scope"]["input_count"] == len(coverage["files"])
    assert coverage["selection"] is None
    return {"candidates": len(checked), "published": len(published_ids), "statuses": dict(statuses),
            "published_statuses": dict(published_statuses), "hint_operators": dict(operators),
            "executed_mutation_cases": executed, "equivalent_contexts": equivalent_contexts,
            "preserved_z3_proofs": preserved_proofs, "preserved_artifacts": preserved_artifacts,
            "verified_input_files": coverage["scope"]["input_count"], "verified_native_paths": verified_paths}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.output, args.original), sort_keys=True))
