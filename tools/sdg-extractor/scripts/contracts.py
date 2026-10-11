import hashlib
import json
from pathlib import Path

import z3

from semantics import Unresolved, identifier


class CallContracts:
    def __init__(self, policy=None):
        self.configuration = policy or {}
        if self.configuration.get("version") == 2:
            if set(self.configuration) != {"version", "contracts", "path_assumptions"}:
                raise ValueError("invalid version 2 assumption policy")
            self.policy = self.configuration["contracts"]
            self.path_assumptions = self.configuration["path_assumptions"]
            allowed = {"kernel_path_condition", "transport_callback", "interrupt_delivery", "memory"}
            if (set(self.path_assumptions) != {"kinds", "reason"} or
                    not set(self.path_assumptions["kinds"]) <= allowed or
                    not self.path_assumptions["reason"]):
                raise ValueError("invalid path assumption policy")
        else:
            self.policy = self.configuration
            self.path_assumptions = None
        self.used = {}
        self.return_constraints = {}
        for name, contract in self.policy.items():
            if set(contract) != {"return", "reason"} or contract["return"] not in {"nonnull", "zero", "not_error"}:
                raise ValueError(f"invalid call contract: {name}")

    @classmethod
    def load(cls, path):
        return cls(json.loads(Path(path).read_text())) if path else cls()

    @staticmethod
    def policy_records(policy):
        return [
            {"id": identifier("policy", name + ":" + contract["return"] + ":" + contract["reason"]),
             "callee": name, "return": contract["return"], "reason": contract["reason"]}
            for name, contract in sorted((policy or {}).items())
        ]

    def policy_record(self):
        records = self.policy_records(self.policy)
        payload = records
        extra = {}
        if self.path_assumptions is not None:
            extra = {"path_assumptions": {**self.path_assumptions,
                                         "kinds": sorted(set(self.path_assumptions["kinds"]))}}
            payload = {"contracts": records, **extra}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {"id": "policy:" + digest, "sha256": digest, "contracts": records, **extra}

    @classmethod
    def from_record(cls, policy):
        contracts = {item["callee"]: {"return": item["return"], "reason": item["reason"]}
                     for item in policy["contracts"]}
        return cls({"version": 2, "contracts": contracts,
                    "path_assumptions": policy["path_assumptions"]}
                   if "path_assumptions" in policy else contracts)

    def scoped_constraints(self, symbolic):
        return [z3.Implies(z3.Or(*symbolic.state_activations[key]), condition)
                for key, condition in sorted(self.return_constraints.items())]

    def apply(self, symbolic, key):
        expression = symbolic.facts.expression(key)
        name = expression.get("callee")
        contract = self.policy.get(name)
        if contract is None:
            return None
        if len(symbolic.facts.calls[key]) != 1:
            raise Unresolved("call contract requires one resolved implementation: " + name)
        value_type = expression["type"]
        kind = contract["return"]
        if kind in {"nonnull", "not_error"} and value_type.get("kind") != "pointer":
            raise Unresolved("pointer success contract applied to non-pointer return")
        if kind == "zero" and value_type.get("kind") != "integer":
            raise Unresolved("zero success contract applied to non-integer return")
        value = symbolic.fresh(key, reason="explicit call-success contract")
        if kind == "zero":
            condition = value == 0
        elif kind == "nonnull":
            condition = value != 0
        else:
            raise Unresolved("error-pointer contract requires an extracted MAX_ERRNO bound")
        self.return_constraints[key] = condition
        self.used[key] = {
            "id": identifier("assumption", key + ":" + kind),
            "expression": key, "callee": name,
            "implementation": symbolic.facts.calls[key][0]["callee"],
            "return": kind, "reason": contract["reason"],
            "location": expression["location"],
        }
        return value


def prove_under_assumptions(symbolic, formula, assignments):
    constraints = [symbolic.source_values[key] == value for key, value in sorted(assignments.items())]
    constraints.extend(symbolic.domain_constraints)
    if symbolic.contracts is not None:
        constraints.extend(symbolic.contracts.scoped_constraints(symbolic))
    solver = z3.Solver()
    solver.set(timeout=5000, random_seed=0)
    solver.add(*constraints)
    consistency = solver.check()
    antecedent = solver.to_smt2()
    solver.add(z3.Not(formula))
    counterexample = solver.check() if consistency == z3.sat else None
    return {"method": "source assignments and scoped declared contracts",
            "internal_witnesses_fixed": False, "consistency": str(consistency),
            "counterexample": str(counterexample) if counterexample is not None else "not_checked",
            "proven": consistency == z3.sat and counterexample == z3.unsat,
            "antecedent_smt2": antecedent,
            "counterexample_smt2": solver.to_smt2()}


def record_assumptions(rule, contracts, symbolic=None, model=None, formula=None, requirements=()):
    from graph import node_id

    policy = contracts.policy_record()
    applied, prerequisites, witnesses = [], [], {}
    if symbolic is not None:
        facts = symbolic.facts
        for key, item in sorted(contracts.used.items()):
            activation = z3.simplify(z3.Or(*symbolic.state_activations[key]))
            applied.append({**item, "kind": "kernel_call", "status": "assumed",
                            "node": node_id(facts, key), "policy_id": policy["id"],
                            "predicate": {"kind": "Eq" if item["return"] == "zero" else "Ne",
                                          "left": {"kind": "Ref", "node": node_id(facts, key)},
                                          "right": {"kind": "Const", "value": 0}},
                            "activation_smt2": activation.sexpr(),
                            "activation_resolved": symbolic.conditions_complete})
        keys = symbolic.environment_in(formula) if formula is not None else set(symbolic.environment)
        for key in sorted(keys):
            identity = node_id(facts, key)
            if model is not None:
                witnesses[identity] = model.eval(symbolic.environment[key], model_completion=True).as_long()
            if key not in contracts.used:
                prerequisites.append({"id": identifier("requirement", key), "kind": "internal_state",
                                      "status": "unresolved", "node": identity, "expression": key,
                                      "location": facts.expression(key)["location"],
                                      "reason": symbolic.assumption_reasons[key]})
        sources = sorted(symbolic.source_values)
        for key in sources:
            condition = facts.sources[key].get("transport_condition")
            if condition:
                prerequisites.append({"id": identifier("requirement", "transport:" + key),
                                      "kind": "transport_callback", "status": "unresolved",
                                      "node": node_id(facts, key), "condition": condition})
        for requirement in requirements:
            prerequisites.append({"id": identifier("requirement", json.dumps(requirement, sort_keys=True)),
                                  "kind": "memory", "status": "unresolved", "predicate": requirement})
        rule["vars"] = sorted(set(rule["vars"]) | {node_id(facts, key) for key in symbolic.visited})
    if rule.get("validation", {}).get("interrupt_registration"):
        prerequisites.append({"id": identifier("requirement", "irq:" + rule["path"]["source"]),
                              "kind": "interrupt_delivery", "status": "unresolved",
                              "node": rule["path"]["source"]})
    validation = rule.setdefault("validation", {})
    rule["assumption_policy"] = {"id": policy["id"], "sha256": policy["sha256"]}
    rule["assumptions"] = applied
    validation["assumption_policy"] = rule["assumption_policy"]
    validation["assumption_ledger"] = applied
    validation["unresolved_prerequisites"] = prerequisites
    validation["internal_state_witness"] = witnesses
    validation.pop("assumed_internal_values", None)
    validation.setdefault("assumption_constraints_proven", False)
    validation.setdefault("assumption_proof", {"proven": False, "consistency": "not_checked",
                                               "counterexample": "not_checked",
                                               "internal_witnesses_fixed": False})
    return rule
