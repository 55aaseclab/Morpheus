from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

import z3

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from contracts import CallContracts
from path_assumptions import apply_path_assumptions, verify_path_assumptions
from publication import publication_errors
from semantics import identifier
from test_convert import fixture
from convert_to_sdg import parse_sdg, render_sdg
from recheck_assumptions import repackage


def example(path=None, target=None, input_value=1):
    rule, nodes, edges = fixture()
    source = z3.BitVec(identifier("source", "input"), 8)
    state = z3.BitVec(identifier("environment", "return-value"), 32)
    nodes["source:input"]["expression_id"] = "input"
    nodes["internal:length"].update(expression_id="return-value", name="initialize()",
                                    function="probe", location={"file": "device.c", "line": 10})
    path = path(source, state) if path else state == 0
    target = target(source, state) if target else source == 1
    solver = z3.Solver()
    solver.add(source == input_value)
    antecedent = solver.to_smt2()
    solver.add(z3.Not(z3.And(path, target)))
    rule.update(status="conditional", assumptions=[])
    rule["validation"] = {
        "result": "sat", "source_assignments": {"source:input": input_value},
        "assumption_ledger": [], "transport_conditions": [],
        "unresolved_prerequisites": [{"id": "requirement:return", "kind": "internal_state",
            "status": "unresolved", "node": "internal:length", "expression": "return-value"}],
        "assumption_proof": {"proven": False, "consistency": "sat", "counterexample": "sat",
            "internal_witnesses_fixed": False, "antecedent_smt2": antecedent,
            "counterexample_smt2": solver.to_smt2()},
    }
    policy = CallContracts({"version": 2, "contracts": {}, "path_assumptions": {
        "kinds": ["kernel_path_condition", "transport_callback", "interrupt_delivery", "memory"],
        "reason": "List the kernel conditions for this path."}}).policy_record()
    return rule, nodes, edges, policy


class PathAssumptionsTests(unittest.TestCase):
    def test_kernel_return_condition_is_an_explicit_proved_assumption(self):
        rule, nodes, edges, policy = example()
        apply_path_assumptions(rule, nodes, policy)
        self.assertEqual(rule["status"], "valid_under_assumptions")
        self.assertEqual(rule["assumptions"][0]["kind"], "kernel_path_condition")
        self.assertEqual(rule["assumptions"][0]["bindings"][0]["text"], "initialize()")
        self.assertFalse(rule["validation"]["unresolved_prerequisites"])
        self.assertFalse(publication_errors(rule, nodes, edges, {}, policy))
        verify_path_assumptions(rule, nodes, policy)
        proof = rule["validation"]["assumption_proof"]
        for key, expected in (("antecedent_smt2", z3.sat), ("counterexample_smt2", z3.unsat)):
            solver = z3.Solver()
            solver.from_string(proof[key])
            self.assertEqual(solver.check(), expected)

    def test_target_internal_value_is_never_assumed(self):
        rule, nodes, _, policy = example(path=lambda x, k: k != 0,
                                       target=lambda x, k: z3.And(x == 1, k == 7))
        apply_path_assumptions(rule, nodes, policy)
        self.assertEqual(rule["status"], "conditional")
        self.assertFalse(rule["validation"]["assumption_proof"]["proven"])
        self.assertTrue(rule["validation"]["path_constraints_proven"])
        self.assertNotIn("#x00000007", rule["assumptions"][0]["predicate"]["expression"])
        verify_path_assumptions(rule, nodes, policy)

    def test_device_only_guard_is_not_an_assumption(self):
        rule, nodes, _, policy = example(path=lambda x, k: x == 2)
        apply_path_assumptions(rule, nodes, policy)
        self.assertEqual(rule["status"], "conditional")
        self.assertEqual(rule["assumptions"], [])

    def test_verifier_rejects_a_proof_unrelated_to_the_assumption_list(self):
        rule, nodes, _, policy = example()
        apply_path_assumptions(rule, nodes, policy)
        solver = z3.Solver()
        solver.add(z3.BoolVal(False))
        rule["validation"]["assumption_proof"]["counterexample_smt2"] = solver.to_smt2()
        with self.assertRaises(AssertionError):
            verify_path_assumptions(rule, nodes, policy)

    def test_verifier_rejects_changed_antecedent_and_preserved_target(self):
        rule, nodes, _, policy = example()
        apply_path_assumptions(rule, nodes, policy)
        proof = rule["validation"]["assumption_proof"]
        solver = z3.Solver()
        solver.from_string(proof["counterexample_smt2"])
        obligation = solver.assertions()[-1]
        solver.reset()
        solver.add(z3.BoolVal(True))
        proof["antecedent_smt2"] = solver.to_smt2()
        solver.add(obligation)
        proof["counterexample_smt2"] = solver.to_smt2()
        with self.assertRaises(AssertionError):
            verify_path_assumptions(rule, nodes, policy)

    def test_mixed_guard_records_source_binding_and_kernel_relation(self):
        rule, nodes, _, policy = example(path=lambda x, k: z3.ULT(z3.ZeroExt(24, x), k))
        apply_path_assumptions(rule, nodes, policy)
        self.assertEqual(rule["status"], "valid_under_assumptions")
        assumption = rule["assumptions"][0]
        self.assertEqual(assumption["source_bindings"], {"source:input": 1})
        self.assertNotIn(identifier("source", "input"), assumption["predicate"]["expression"])

    def test_inconsistent_path_does_not_prove_validity(self):
        rule, nodes, _, policy = example(path=lambda x, k: z3.And(k == 0, k == 1))
        apply_path_assumptions(rule, nodes, policy)
        self.assertEqual(rule["status"], "conditional")
        self.assertFalse(rule["validation"]["assumption_proof"]["proven"])
        verify_path_assumptions(rule, nodes, policy)

    def test_policy_is_explicit_and_changes_its_digest(self):
        rule, nodes, _, policy = example()
        old = deepcopy(rule)
        legacy = CallContracts().policy_record()
        apply_path_assumptions(rule, nodes, legacy)
        self.assertEqual(rule["status"], old["status"])
        self.assertEqual(rule["assumptions"], [])
        self.assertNotEqual(policy["id"], legacy["id"])
        self.assertEqual(CallContracts.from_record(policy).policy_record(), policy)

    def test_external_condition_requires_evidence_and_is_listed(self):
        rule, nodes, edges, policy = example()
        condition = {"operations": "device_ops", "handler": "read_config",
                     "registration": {"file": "device.c", "line": 20}}
        rule["validation"]["transport_conditions"] = [condition]
        rule["validation"]["unresolved_prerequisites"].append({
            "id": "requirement:transport", "kind": "transport_callback", "status": "unresolved",
            "node": "source:input", "condition": condition})
        apply_path_assumptions(rule, nodes, policy)
        self.assertEqual(rule["status"], "valid_under_assumptions")
        self.assertEqual({a["kind"] for a in rule["assumptions"]},
                         {"kernel_path_condition", "transport_callback"})
        self.assertFalse(publication_errors(rule, nodes, edges, {}, policy))
        verify_path_assumptions(rule, nodes, policy)
        rule["assumptions"] = [a for a in rule["assumptions"] if a["kind"] != "transport_callback"]
        rule["validation"]["assumption_ledger"] = rule["assumptions"]
        self.assertTrue(publication_errors(rule, nodes, edges, {}, policy))

    def test_missing_source_observation_is_solved_as_device_input(self):
        extra = z3.BitVec(identifier("source", "extra"), 8)
        rule, nodes, edges, policy = example(
            path=lambda x, k: z3.And(k == 0, extra == 9))
        nodes["source:extra"] = {**nodes["source:input"], "id": "source:extra", "expression_id": "extra"}
        rule["vars"].append("source:extra")
        apply_path_assumptions(rule, nodes, policy)
        self.assertEqual(rule["status"], "valid_under_assumptions")
        self.assertEqual(rule["validation"]["source_assignments"]["source:extra"], 9)
        self.assertIn({"operator": "SetValue", "var": "source:extra", "value": 9}, rule["mutation_hint"])
        self.assertEqual(len(rule["assumptions"]), 1)
        self.assertFalse(publication_errors(rule, nodes, edges, {}, policy))
        verify_path_assumptions(rule, nodes, policy)

    def test_interrupt_delivery_is_an_explicit_semantic_assumption(self):
        rule, nodes, edges, policy = example()
        nodes["irq:device"] = {"id": "irq:device", "kind": "source", "source": {"kind": "Irq"}}
        rule["vars"].append("irq:device")
        rule["validation"]["interrupt_registration"] = {"handler": "handle_device"}
        rule["mutation_hint"].append({"operator": "DeliverIrq", "var": "irq:device", "handler": "handle_device"})
        rule["validation"]["unresolved_prerequisites"].append({"id": "requirement:irq",
            "kind": "interrupt_delivery", "status": "unresolved", "node": "irq:device"})
        apply_path_assumptions(rule, nodes, policy)
        self.assertEqual(rule["status"], "valid_under_assumptions")
        self.assertFalse(publication_errors(rule, nodes, edges, {}, policy))
        verify_path_assumptions(rule, nodes, policy)

    def test_changed_export_keeps_the_original_graph_and_checks_its_hash(self):
        rule, nodes, edges, policy = example()
        original = render_sdg(rule, nodes, edges)
        record = {"id": rule["id"], "sha256": hashlib.sha256(original.encode()).hexdigest()}
        apply_path_assumptions(rule, nodes, policy)
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "original.sdg", Path(directory) / "updated.sdg"
            source.write_text(original)
            updated = repackage(source, destination, record, rule)
            self.assertEqual(updated["sha256"], hashlib.sha256(destination.read_bytes()).hexdigest())
            parsed = parse_sdg(destination.read_text())
            self.assertEqual(parsed["rule"], rule)
            self.assertEqual({n["id"]: n for n in parsed["nodes"]}, nodes)
            self.assertEqual({e["id"]: e for e in parsed["edges"]}, edges)
            source.write_text(original + "\n")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                repackage(source, destination, record, rule)


if __name__ == "__main__":
    unittest.main()
