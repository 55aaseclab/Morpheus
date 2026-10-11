"""Check actual extracted kernel builtins and fail-closed publication artifacts."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time

import z3

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from semantics import Facts, SymbolicPath, children, load_facts
from publication import publication_errors
from convert_to_sdg import parse_sdg
from contracts import CallContracts
from path_assumptions import verify_path_assumptions


def check_builtins(facts):
    operations = {
        "__builtin_add_overflow": lambda a, b: a + b,
        "__builtin_sub_overflow": lambda a, b: a - b,
        "__builtin_mul_overflow": lambda a, b: a * b,
    }
    checked = Counter()
    for key, expression in list(facts.expressions.items()):
        name = expression.get("callee")
        if name not in operations:
            continue
        operands = children(expression)
        output = facts.expression(operands[2])
        if output["class"] != "AddressOfExpr":
            continue
        destination = facts.expression(children(output)[0])
        target_type = destination["type"]
        operand_types = [facts.expression(operands[position])["type"] for position in (0, 1)]
        if (destination["class"] != "VariableAccess" or
                any(t.get("signedness") not in {"Signed", "Unsigned"} or
                    not 0 < t.get("width", 0) <= 64 for t in [target_type, *operand_types])):
            continue
        reads = [read for read, writes in facts.write_definitions.items()
                 if len(writes) == 1 and not facts.definitions[read] and
                 writes[0]["calls"] == [{"call": key, "argument": 2}] and
                 facts.expression(read).get("declaration") == destination.get("declaration")]
        if not reads:
            continue
        width = target_type["width"]
        signed = target_type["signedness"] == "Signed"
        minimum = -(1 << (width - 1)) if signed else 0
        maximum = (1 << (width - int(signed))) - 1
        cases = []
        for t in operand_types:
            mask = (1 << t["width"]) - 1
            cases.append(sorted({0, 1, 2, mask, mask - 1, 1 << (t["width"] - 1)}))
        for first in cases[0]:
            for second in cases[1]:
                symbolic = SymbolicPath(facts, [])
                values = []
                for position, pattern in enumerate((first, second)):
                    t = operand_types[position]
                    symbolic.cache[operands[position]] = z3.BitVecVal(pattern, t["width"])
                    values.append(pattern - (1 << t["width"]) if
                                  t["signedness"] == "Signed" and pattern >> (t["width"] - 1)
                                  else pattern)
                exact = operations[name](*values)
                stored = exact % (1 << width)
                overflow = not minimum <= exact <= maximum
                for read in reads:
                    assert z3.simplify(symbolic.resolve(read)).as_long() == stored, (key, first, second)
                assert z3.is_true(z3.simplify(symbolic.resolve(key))) == overflow, (key, first, second)
                assert key in symbolic.visited, "output reads must retain their call conditions"
                checked[name] += 1
    assert checked, "no real extracted overflow builtin output was exercised"
    return dict(checked)


def check_publication(output):
    summary = json.loads((output / "sdg-diagnostics.json").read_text())["summary"]
    if summary.get("publication_threshold") == "basic":
        from check_guidance import check
        manifest = json.loads((output / "manifest.json").read_text())
        original = manifest.get("details", {}).get("guidance_source")
        return check(output, Path(original) if original else None)
    nodes = {n["id"]: n for n in json.loads((output / "sdg-nodes.json").read_text())["nodes"]}
    raw_edges = json.loads((output / "sdg-edges.json").read_text())
    edges = {e["id"]: e for e in raw_edges["self_edges"] + raw_edges["cross_edges"]}
    exports = {p.name: p.read_text() for p in (output / "runtime-sdg").glob("*.sdg")}
    rules = json.loads((output / "sdg-rules.json").read_text())
    policy = json.loads((output / "assumption-policy.json").read_text())["policy"]
    assert rules["count"] == len(rules["rules"])
    for rule in rules["rules"]:
        assert not publication_errors(rule, nodes, edges, exports, policy), rule["id"]
    runtime_rules = [rule for rule in rules["rules"] if "file" in rule.get("runtime_export", {})]
    assert set(exports) == {rule["runtime_export"]["file"] for rule in runtime_rules}
    semantic_manifest = json.loads((output / "sdg" / "manifest.json").read_text())
    assert semantic_manifest["format"] == "semantic-sdg"
    assert semantic_manifest["count"] == len(rules["rules"])
    rules_by_id = {rule["id"]: rule for rule in rules["rules"]}
    exported_ids = set()
    for record in semantic_manifest["rules"]:
        path = output / "sdg" / record["file"]
        payload = path.read_bytes()
        assert hashlib.sha256(payload).hexdigest() == record["sha256"]
        parsed = parse_sdg(payload.decode("utf-8"))
        rule = rules_by_id[record["id"]]
        assert record["id"] not in exported_ids
        exported_ids.add(record["id"])
        assert parsed["rule"] == rule
        assert {node["id"]: node for node in parsed["nodes"]} == {key: nodes[key] for key in rule["vars"]}
        assert {edge["id"]: edge for edge in parsed["edges"]} == {key: edges[key] for key in rule["path"]["edges"]}
        assert record["nodes"] == len(parsed["nodes"])
        cross_count = sum(edge["src"] != edge["dst"] for edge in parsed["edges"])
        assert record["cross_edges"] == cross_count
        assert record["self_edges"] == len(parsed["edges"]) - cross_count
        assert record["target_edges"] == 1
    assert exported_ids == rules_by_id.keys()
    assert {path.name for path in (output / "sdg").glob("*.sdg")} == {
        record["file"] for record in semantic_manifest["rules"]}
    policy = json.loads((output / "assumption-policy.json").read_text())["policy"]
    configured = {item["callee"]: {"return": item["return"], "reason": item["reason"]}
                  for item in policy["contracts"]}
    assert CallContracts.from_record(policy).policy_record() == policy
    policy_reference = {key: policy[key] for key in ("id", "sha256")}
    ledger = json.loads((output / "assumption-ledger.json").read_text())
    assert ledger["policy_id"] == policy["id"]
    ledger_entries = {entry["id"]: entry["entry"] for entry in ledger["entries"]}
    conditional_directory = output / "sdg-conditional"
    conditional_manifest = json.loads((conditional_directory / "manifest.json").read_text())
    conditional_records = {record["id"]: record for record in conditional_manifest["rules"]}
    conditional_ids = set()
    unresolved_directory = output / "sdg-unresolved"
    unresolved_manifest = json.loads((unresolved_directory / "manifest.json").read_text())
    unresolved_records = {record["id"]: record for record in unresolved_manifest["rules"]}
    unresolved_ids = set()
    candidate_ids = set()
    proof_count = 0
    shared_contexts = 0
    statuses = Counter()
    last_progress = time.monotonic()
    with (output / "sdg-candidates.json").open() as stream:
        next(stream)
        for line in stream:
            if line.startswith("]"):
                break
            candidate = json.loads(line.rstrip(",\n"))
            statuses[candidate["status"]] += 1
            alternatives = candidate["path"].get("alternatives", {})
            alternative_nodes = set(alternatives.get("nodes", []))
            alternative_steps = {(step["src"], step["dst"]) for step in alternatives.get("steps", [])}
            context_ids = {candidate["path"].get("context_id")}
            for context in candidate["path"].get("equivalent_contexts", []):
                assert candidate["status"] == "unresolved"
                assert context["context_id"] not in context_ids
                context_ids.add(context["context_id"])
                witness = context["witness_nodes"]
                assert witness and set(witness) <= alternative_nodes
                assert set(zip(witness, witness[1:])) <= alternative_steps
                shared_contexts += 1
            assert candidate["id"] not in candidate_ids
            candidate_ids.add(candidate["id"])
            assert candidate.get("assumption_policy") == policy_reference
            validation = candidate["validation"]
            assert validation["assumption_policy"] == policy_reference
            assert validation["assumption_ledger"] == candidate["assumptions"]
            expected = validation["assumption_ledger"] + validation["unresolved_prerequisites"]
            actual = [ledger_entries[key] for key in ledger["rule_entries"][candidate["id"]]]
            assert {json.dumps(entry, sort_keys=True) for entry in actual} == {
                json.dumps(entry, sort_keys=True) for entry in expected}
            allowed = {"kernel_call"} | set(policy.get("path_assumptions", {}).get("kinds", []))
            for entry in validation["assumption_ledger"]:
                assert entry["kind"] in allowed and entry["status"] == "assumed"
                assert entry["policy_id"] == policy["id"]
                if entry["kind"] == "kernel_call":
                    assert entry["return"] == configured[entry["callee"]]["return"]
                    assert entry["predicate"]["kind"] == ("Eq" if entry["return"] == "zero" else "Ne")
                    assert entry["predicate"]["right"] == {"kind": "Const", "value": 0}
                    assert entry["node"] in candidate["vars"] and entry["node"] in nodes
                elif entry["kind"] == "kernel_path_condition":
                    assert entry["bindings"] and entry["predicate"]["kind"] == "SmtBool"
                    assert entry["origin"]["kind"] == "path_condition"
                elif entry["kind"] == "transport_callback":
                    assert entry["condition"]["operations"] and entry["condition"]["handler"]
                elif entry["kind"] == "memory":
                    assert entry.get("predicate")
                elif entry["kind"] == "interrupt_delivery":
                    assert entry.get("registration", {}).get("handler")
            for hint in candidate["mutation_hint"]:
                assert nodes[hint["var"]]["kind"] == "source"
            proof = validation["assumption_proof"]
            assert proof["internal_witnesses_fixed"] is False
            proof_candidate = candidate
            if candidate.get("publication", {}).get("threshold") == "basic":
                proof_candidate = {**candidate, "mutation_hint": candidate["enhancement"]["mutation_hint"]}
            verify_path_assumptions(proof_candidate, nodes, policy)
            if candidate["status"] == "conditional" and candidate["id"] not in rules_by_id:
                conditional_ids.add(candidate["id"])
                record = conditional_records[candidate["id"]]
                payload = (conditional_directory / record["file"]).read_bytes()
                assert hashlib.sha256(payload).hexdigest() == record["sha256"]
                parsed = parse_sdg(payload.decode("utf-8"))
                assert parsed["rule"] == candidate
                assert {node["id"]: node for node in parsed["nodes"]} == {
                    key: nodes[key] for key in candidate["vars"]}
                assert {edge["id"]: edge for edge in parsed["edges"]} == {
                    key: edges[key] for key in candidate["path"]["edges"]}
            if candidate["status"] == "unresolved" and candidate["id"] not in rules_by_id:
                unresolved_ids.add(candidate["id"])
                record = unresolved_records[candidate["id"]]
                payload = (unresolved_directory / record["file"]).read_bytes()
                assert hashlib.sha256(payload).hexdigest() == record["sha256"]
                parsed = parse_sdg(payload.decode("utf-8"))
                assert parsed["rule"] == candidate
                assert {node["id"]: node for node in parsed["nodes"]} == {
                    key: nodes[key] for key in candidate["vars"]}
                assert {edge["id"]: edge for edge in parsed["edges"]} == {
                    key: edges[key] for key in candidate["path"]["edges"]}
            if proof.get("proven"):
                solver = z3.Solver()
                solver.set(timeout=5000)
                solver.from_string(proof["antecedent_smt2"])
                assert solver.check() == z3.sat
                solver.reset()
                solver.set(timeout=5000)
                solver.from_string(proof["counterexample_smt2"])
                assert solver.check() == z3.unsat
                assert proof["consistency"] == "sat" and proof["counterexample"] == "unsat"
                proof_count += 1
            if candidate["status"] == "valid_under_assumptions":
                assert candidate["assumptions"]
                assert candidate["validation"]["assumption_constraints_proven"]
                assert candidate["validation"]["assumption_ledger"]
                assert "file" not in candidate["runtime_export"]
                assert candidate == rules_by_id[candidate["id"]]
            if candidate["id"] in rules_by_id:
                assert candidate == rules_by_id[candidate["id"]]
            else:
                assert publication_errors(candidate, nodes, edges, exports, policy), candidate["id"]
            if time.monotonic() - last_progress >= 30:
                print(json.dumps({"phase": "verify", "candidates": len(candidate_ids),
                                  "total": ledger["candidate_count"],
                                  "equivalent_contexts": shared_contexts}),
                      file=sys.stderr, flush=True)
                last_progress = time.monotonic()
    summary = json.loads((output / "sdg-diagnostics.json").read_text())["summary"]
    assert summary["assumption_policy"] == policy
    assert candidate_ids == ledger["rule_entries"].keys()
    assert ledger["candidate_count"] == len(candidate_ids)
    assert conditional_ids == conditional_records.keys()
    assert conditional_manifest["count"] == len(conditional_ids)
    assert unresolved_ids == unresolved_records.keys()
    assert unresolved_manifest["count"] == len(unresolved_ids)
    assert shared_contexts == summary["reused_unresolved_contexts"]
    assert {path.name for path in unresolved_directory.glob("*.sdg")} == {
        record["file"] for record in unresolved_records.values()}
    assert {path.name for path in conditional_directory.glob("*.sdg")} == {
        record["file"] for record in conditional_records.values()}
    coverage = json.loads((output / "analysis-coverage.json").read_text())
    assert coverage["candidate_count"] == len(candidate_ids)
    assert coverage["selection"] is None, "full kernel verification requires unfiltered analysis"
    assert coverage["scope"]["input_count"] == len(coverage["files"])
    assert {record["file"] for record in coverage["files"]} == set(coverage["scope"]["input_files"])
    assert dict(statuses) == summary["candidate_statuses"]
    assert rules["count"] == summary["rules"]
    return {"published": rules["count"], "semantic_exports": len(exported_ids),
            "candidate_statuses": dict(statuses), "policy_id": policy["id"],
            "candidates_with_policy": len(candidate_ids), "verified_proofs": proof_count,
            "conditional_exports": len(conditional_ids),
            "unresolved_exports": len(unresolved_ids),
            "verified_equivalent_contexts": shared_contexts,
            "verified_input_files": len(coverage["files"])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    work = args.output / "work"
    manifest = json.loads((args.output / "manifest.json").read_text())
    source = Path(manifest["details"]["source_dir"])
    assert (source / "Kconfig").is_file(), "verification requires an actual kernel checkout"
    target = json.loads((Path(manifest["details"]["database"]) / "sdg-target.json").read_text())
    facts = Facts(load_facts(work / "facts.csv"), target)
    builtins = check_builtins(facts)
    del facts
    print(json.dumps({"builtin_boundary_cases": builtins,
                      "publication": check_publication(args.output)}, sort_keys=True))


if __name__ == "__main__":
    main()
