from pathlib import Path
import csv
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from guidance import attach_guidance, derive_hints, mutate_value
from publication import publication_errors


def sample(operator=">", boundary=40):
    scalar = {"width": 8, "signedness": "Unsigned", "kind": "integer"}
    nodes = {
        "input": {"id": "input", "kind": "source", "expression_id": "read",
                  "type": scalar, "source": {"kind": "MmioRead", "size_bytes": 1}},
        "check": {"id": "check", "kind": "internal", "type": scalar},
        "sink": {"id": "sink", "kind": "sink", "location": {"file": "device.c", "line": 8}},
    }
    expression = {"kind": operator, "operands": [
        {"kind": "Ref", "node": "input", "position": 0},
        {"kind": "Const", "value": boundary, "position": 1}], "type": scalar}
    edges = {"compare": {"id": "compare", "src": "input", "dst": "check", "head": "head_bound",
             "predicate": {"kind": "Eq", "left": {"kind": "Ref", "node": "check"}, "right": expression}},
             "guard": {"id": "guard", "src": "check", "dst": "sink", "head": "head_guard",
             "predicate": {"kind": "Ne", "left": {"kind": "Ref", "node": "check"},
                           "right": {"kind": "Const", "value": 0}}}}
    rule = {"id": "rule:test", "status": "conditional", "vars": list(nodes),
        "path": {"source": "input", "sink": "sink", "source_expression": "read",
                 "dependency": "control", "edges": list(edges),
                 "control_conditions": [{"condition": "check", "branch": True}]},
        "preconditions": edges["guard"]["predicate"],
        "target_state": {"src": "check", "dst": "check", "head": "head_bound",
                         "predicate": {"kind": "Eq", "left": {"kind": "Ref", "node": "check"},
                                       "right": {"kind": "Const", "value": 1}}},
        "mutation_hint": [{"operator": "SetValue", "var": "input", "value": 255}],
        "assumptions": [], "validation": {"result": "unknown", "reason": "solver timeout"},
        "runtime_export": {"reason": "placement requires context"}}
    return rule, nodes, edges


class GuidanceTests(unittest.TestCase):
    def test_basic_rule_publishes_without_solver_proof(self):
        rule, nodes, edges = sample()
        attach_guidance(rule, nodes, edges)
        self.assertEqual(rule["status"], "conditional")
        self.assertEqual(rule["publication"]["threshold"], "basic")
        self.assertFalse(publication_errors(rule, nodes, edges, {}))
        hint = next(h for h in rule["mutation_hint"] if h["operator"] == "SetBoundary")
        self.assertEqual((hint["boundary"], hint["side"]), (40, "Above"))
        self.assertEqual(mutate_value(hint, nodes["input"], 0), 41)
        self.assertEqual(rule["enhancement"]["mutation_hint"][0]["value"], 255)

    def test_negated_rejection_guard_selects_below_boundary(self):
        rule, nodes, edges = sample(">=", 40)
        rule["path"]["control_conditions"][0]["branch"] = False
        rule["preconditions"] = {"kind": "Not", "operand": rule["preconditions"]}
        hints = derive_hints(rule, nodes, edges)
        hint = next(h for h in hints if h["operator"] == "SetBoundary")
        self.assertEqual((hint["boundary"], hint["side"]), (40, "Below"))
        self.assertEqual(mutate_value(hint, nodes["input"], 100), 39)

    def test_boundary_arithmetic_never_wraps(self):
        rule, nodes, edges = sample(">", 255)
        self.assertFalse(any(h["operator"] == "SetBoundary" and h.get("side") == "Above"
                             for h in derive_hints(rule, nodes, edges)))
        self.assertIsNone(mutate_value({"operator": "Inc", "delta": 1}, nodes["input"], 255))
        self.assertIsNone(mutate_value({"operator": "Dec", "delta": 1}, nodes["input"], 0))

    def test_signed_boundary_uses_signed_domain(self):
        rule, nodes, edges = sample("<", -3)
        nodes["input"]["type"]["signedness"] = "Signed"
        hint = next(h for h in derive_hints(rule, nodes, edges) if h["operator"] == "SetBoundary")
        self.assertEqual(mutate_value(hint, nodes["input"], 0), 252)

    def test_bit_guard_generates_set_and_clear(self):
        rule, nodes, edges = sample()
        edges["compare"]["predicate"]["right"] = {"kind": "&", "operands": [
            {"node": "input", "position": 0}, {"kind": "Const", "value": 8, "position": 1}]}
        hints = derive_hints(rule, nodes, edges)
        self.assertTrue(any(h["operator"] == "SetBits" and h["mask"] == 8 for h in hints))
        rule["path"]["control_conditions"][0]["branch"] = False
        hints = derive_hints(rule, nodes, edges)
        self.assertTrue(any(h["operator"] == "ClearBits" and h["mask"] == 8 for h in hints))

    def test_lossy_transform_is_exploration_not_false_monotonicity(self):
        rule, nodes, edges = sample()
        edges["compare"]["predicate"]["right"] = {"kind": "Cast",
            "value": {"node": "input", "kind": "Ref"}, "type": {"width": 4, "signedness": "Unsigned"}}
        hints = derive_hints(rule, nodes, edges)
        self.assertTrue(hints)
        self.assertTrue(all(h["derivation"]["guarantee"] == "guidance" for h in hints))
        self.assertTrue(any(h["operator"] in {"Inc", "Dec"} for h in hints))

    def test_forged_hint_or_internal_destination_is_rejected(self):
        rule, nodes, edges = sample()
        attach_guidance(rule, nodes, edges)
        rule["mutation_hint"][0]["var"] = "check"
        self.assertTrue(publication_errors(rule, nodes, edges, {}))

    def test_disconnected_source_cannot_be_published(self):
        rule, nodes, edges = sample()
        edges = {}
        rule["path"]["edges"] = []
        attach_guidance(rule, nodes, edges)
        self.assertFalse(rule["mutation_hint"])
        self.assertTrue(publication_errors(rule, nodes, edges, {}))

    def test_path_without_mutation_cannot_be_published(self):
        rule, nodes, edges = sample()
        attach_guidance(rule, nodes, edges)
        rule["mutation_hint"] = []
        self.assertTrue(publication_errors(rule, nodes, edges, {}))

    def test_source_appearing_in_witness_is_not_a_connected_path(self):
        rule, nodes, edges = sample()
        rule["path"]["edges"] = []
        rule["path"]["witness"] = [{"expressions": ["read"]}]
        attach_guidance(rule, nodes, {})
        self.assertFalse(rule["mutation_hint"])
        self.assertTrue(publication_errors(rule, nodes, {}, {}))

    def test_secondary_source_hint_does_not_replace_the_main_path(self):
        rule, nodes, edges = sample()
        nodes["other"] = {**nodes["input"], "id": "other", "expression_id": "other-read"}
        rule["vars"].append("other")
        rule["path"]["source"] = "other"
        attach_guidance(rule, nodes, edges)
        self.assertTrue(rule["mutation_hint"])
        self.assertFalse(rule["publication"]["eligible"])
        self.assertTrue(publication_errors(rule, nodes, edges, {}))

    def test_native_paths_require_matching_endpoints_and_connected_steps(self):
        from path_evidence import NativePaths, identity
        rule, nodes, edges = sample()
        rule["path"]["dependency"] = "data"
        nodes["sink"]["flow_operand"] = "copy-length"
        start, end = identity("internal", "flow:read-site"), identity("internal", "flow:copy-site")
        rule["path"]["alternatives"] = {"nodes": [start, end], "steps": [{"src": start, "dst": end}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paths.csv"
            with path.open("w", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["section", "key", "value"])
                writer.writerow(["flow", "flow-id", json.dumps({"source_expr": "read", "sink_expr": "copy-length",
                    "source": "read-site", "sink": "copy-site"})])
                writer.writerow(["flow_step", "step-id", json.dumps({"src": "read-site", "dst": "copy-site"})])
            index = NativePaths(path, nodes)
            self.assertTrue(index.evidence(rule))
            fake = "internal:invented"
            rule["path"]["alternatives"] = {"nodes": [start, fake, end],
                "steps": [{"src": start, "dst": fake}, {"src": fake, "dst": end}]}
            self.assertIsNone(index.evidence(rule))
            rule["path"]["alternatives"]["steps"] = []
            self.assertIsNone(index.evidence(rule))

    def test_solver_enhancement_does_not_change_basic_hints(self):
        rule, nodes, edges = sample()
        first = derive_hints(rule, nodes, edges)
        rule["status"] = "valid_under_assumptions"
        rule["validation"] = {"result": "sat", "assumption_constraints_proven": True}
        rule["mutation_hint"] = [{"operator": "SetValue", "var": "input", "value": 41}]
        self.assertEqual(first, derive_hints(rule, nodes, edges))

    def test_unknown_and_timeout_preserve_publishable_hints(self):
        for reason in ("solver timeout", "unmodeled kernel operation"):
            rule, nodes, edges = sample()
            rule["status"] = "unresolved"
            rule["validation"] = {"result": "unknown", "reason": reason}
            attach_guidance(rule, nodes, edges)
            self.assertEqual(rule["enhancement"]["backend"], "z3")
            self.assertFalse(rule["publication"]["solver_success_required"])
            self.assertFalse(publication_errors(rule, nodes, edges, {}))

    def test_proved_contradiction_is_not_a_solver_failure(self):
        rule, nodes, edges = sample()
        rule["validation"] = {"result": "unsat"}
        attach_guidance(rule, nodes, edges)
        self.assertTrue(publication_errors(rule, nodes, edges, {}))

    def test_export_verifier_checks_repeated_graph_records_and_modified_bytes(self):
        from convert_to_sdg import export_rules
        from check_guidance import check_export
        rule, nodes, edges = sample()
        attach_guidance(rule, nodes, edges)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = export_rules([rule], nodes, edges, root)
            record = manifest["rules"][0]
            path = root / record["file"]
            node_lines, edge_lines = {}, {}
            check_export(path, record, rule, nodes, edges, node_lines, edge_lines)
            check_export(path, record, rule, nodes, edges, node_lines, edge_lines)
            path.write_text(path.read_text().replace('"value":40', '"value":41'))
            with self.assertRaises(AssertionError):
                check_export(path, record, rule, nodes, edges, node_lines, edge_lines)


if __name__ == "__main__": unittest.main()
