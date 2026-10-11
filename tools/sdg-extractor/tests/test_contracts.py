from collections import defaultdict
import json
from pathlib import Path
import sys
import tempfile
import unittest

import z3

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from contracts import CallContracts, prove_under_assumptions, record_assumptions
from semantics import Facts, SymbolicPath
from rule_store import RuleStore
from publication import publication_errors


def sample(return_kind="nonnull"):
    policy = {"allocate": {"return": return_kind, "reason": "Allocation succeeds for this workload."}}
    sections = defaultdict(dict)
    pointer = {"name": "void *", "kind": "pointer", "width": 64, "signedness": "Unknown"}
    scalar = {"name": "unsigned int", "kind": "integer", "width": 32, "signedness": "Unsigned"}
    for key, value_type in (("call", pointer if return_kind == "nonnull" else scalar),
                            ("input", scalar), ("state", scalar)):
        sections["expression"][key] = {"id": key, "class": "FunctionCall" if key == "call" else "VariableAccess",
                                       "callee": "allocate" if key == "call" else "",
                                       "function": "probe", "text": key, "type": value_type,
                                       "location": {"file": "device.c", "line": 10}, "children": []}
    sections["call"]["binding"] = {"call": "call", "callee": "allocator", "parameters": []}
    sections["source"]["input"] = {"kind": "MmioRead", "size_bytes": 4, "byte_order": "Little"}
    contracts = CallContracts(policy)
    symbolic = SymbolicPath(Facts(sections), [], contracts)
    symbolic.resolve("call")
    symbolic.resolve("input")
    symbolic.resolve("state")
    symbolic.state_activations["call"].append(z3.BoolVal(True))
    symbolic.conditions_complete = True
    return symbolic, contracts


class ContractTests(unittest.TestCase):
    def test_nonnull_contract_does_not_fix_pointer_address(self):
        symbolic, _ = sample()
        pointer = symbolic.environment["call"]
        self.assertTrue(prove_under_assumptions(symbolic, pointer != 0, {"input": 1})["proven"])
        proof = prove_under_assumptions(symbolic, pointer == 1, {"input": 1})
        self.assertFalse(proof["proven"])
        self.assertEqual(proof["counterexample"], "sat")

    def test_unmodeled_state_cannot_become_an_assumption(self):
        symbolic, contracts = sample()
        formula = z3.And(symbolic.source_values["input"] == 1, symbolic.environment["state"] == 7)
        proof = prove_under_assumptions(symbolic, formula, {"input": 1})
        self.assertFalse(proof["proven"])
        self.assertFalse(proof["internal_witnesses_fixed"])
        solver = z3.Solver()
        solver.from_string(proof["counterexample_smt2"])
        self.assertEqual(solver.check(), z3.sat)
        witness = z3.Solver()
        witness.add(formula, *contracts.scoped_constraints(symbolic))
        self.assertEqual(witness.check(), z3.sat)
        rule = {"id": "rule:example", "vars": [], "path": {"edges": []}}
        record_assumptions(rule, contracts, symbolic, witness.model(), formula)
        self.assertTrue(rule["validation"]["internal_state_witness"])
        self.assertEqual({entry["kind"] for entry in rule["assumptions"]}, {"kernel_call"})
        self.assertEqual({entry["kind"] for entry in rule["validation"]["unresolved_prerequisites"]},
                         {"internal_state"})

    def test_zero_contract_and_source_assignment_prove_target(self):
        symbolic, _ = sample("zero")
        formula = z3.And(symbolic.environment["call"] == 0, symbolic.source_values["input"] == 8)
        proof = prove_under_assumptions(symbolic, formula, {"input": 8})
        self.assertTrue(proof["proven"])
        self.assertEqual(proof["consistency"], "sat")

    def test_contract_does_not_apply_to_inactive_call(self):
        symbolic, _ = sample("zero")
        symbolic.state_activations["call"] = [z3.BoolVal(False)]
        self.assertFalse(prove_under_assumptions(symbolic, symbolic.environment["call"] == 0,
                                               {"input": 2})["proven"])

    def test_contract_activation_depends_on_input(self):
        symbolic, _ = sample("zero")
        symbolic.state_activations["call"] = [symbolic.source_values["input"] != 0]
        formula = symbolic.environment["call"] == 0
        self.assertTrue(prove_under_assumptions(symbolic, formula, {"input": 2})["proven"])
        self.assertFalse(prove_under_assumptions(symbolic, formula, {"input": 0})["proven"])

    def test_contradictory_assumptions_do_not_prove_validity(self):
        symbolic, _ = sample()
        symbolic.domain_constraints.append(symbolic.environment["call"] == 0)
        proof = prove_under_assumptions(symbolic, z3.BoolVal(True), {"input": 1})
        self.assertEqual(proof["consistency"], "unsat")
        self.assertFalse(proof["proven"])

    def test_policy_digest_is_stable_and_covers_contracts(self):
        _, contracts = sample()
        policy = {**contracts.policy, "initialize": {"return": "zero", "reason": "Initialization succeeds."}}
        snapshot = CallContracts(policy).policy_record()
        self.assertEqual(snapshot, CallContracts(dict(reversed(list(policy.items())))).policy_record())
        changed = {**policy, "initialize": {"return": "zero", "reason": "Another workload."}}
        self.assertNotEqual(snapshot["id"], CallContracts(changed).policy_record()["id"])

    def test_streamed_unresolved_candidate_retains_applied_contracts(self):
        symbolic, contracts = sample()
        symbolic.conditions_complete = False
        rule = {"id": "rule:unresolved", "status": "unresolved", "vars": [], "path": {"edges": []},
                "validation": {"result": "unknown", "reason": "missing store effect"}}
        record_assumptions(rule, contracts, symbolic)
        with tempfile.TemporaryDirectory() as directory:
            store = RuleStore(directory)
            try:
                store.append(rule)
                decoded = list(store)[0]
                self.assertEqual(decoded, rule)
                self.assertEqual(decoded["assumption_policy"]["id"], contracts.policy_record()["id"])
                self.assertFalse(decoded["assumptions"][0]["activation_resolved"])
                self.assertFalse(decoded["validation"]["assumption_constraints_proven"])
            finally:
                store.close()

    def test_transport_and_interrupt_are_explicit_prerequisites(self):
        symbolic, contracts = sample()
        symbolic.facts.sources["input"]["transport_condition"] = {"operations": "device_ops"}
        rule = {"id": "rule:irq", "vars": [], "path": {"source": "irq:device"},
                "validation": {"interrupt_registration": {"handler": "handler"}}}
        record_assumptions(rule, contracts, symbolic)
        kinds = {entry["kind"] for entry in rule["validation"]["unresolved_prerequisites"]}
        self.assertTrue({"transport_callback", "interrupt_delivery"} <= kinds)

    def test_publication_rejects_fixed_internal_witness_proof(self):
        rule = {"status": "valid_under_assumptions", "assumptions": [{"kind": "kernel_call"}],
                "validation": {"result": "sat", "assumption_constraints_proven": True,
                               "assumption_ledger": [{"kind": "solver_state", "status": "assumed"}],
                               "assumption_proof": {"consistency": "sat", "counterexample": "unsat",
                                                    "proven": True, "internal_witnesses_fixed": True}}}
        errors = publication_errors(rule, {}, {}, {})
        self.assertTrue(any("non-vacuous" in error for error in errors))
        self.assertTrue(any("undeclared internal-state" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
