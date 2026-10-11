"""Name the kernel conditions of a path without assuming its device target."""

import hashlib
import json

import z3

from semantics import identifier


EXTERNAL_KINDS = {"transport_callback", "interrupt_delivery", "memory"}


def symbols(value):
    pending, seen, found = [value], set(), {}
    while pending:
        current = pending.pop()
        if current.get_id() in seen:
            continue
        seen.add(current.get_id())
        if z3.is_const(current) and current.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            found[str(current.decl().name())] = current
        pending.extend(current.children())
    return found


def conjuncts(value, address=()):
    if z3.is_and(value):
        for index, child in enumerate(value.children()):
            yield from conjuncts(child, address + (index,))
    else:
        yield address, value


def ledger_digest(entries):
    return hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def assert_equivalent(first, second, identity):
    if first.eq(second) or z3.is_true(z3.simplify(first == second)):
        return
    solver = z3.Solver()
    solver.set(timeout=5000)
    solver.add(first != second)
    assert solver.check() == z3.unsat, "different proof obligations: " + identity


def replay_queries(proof):
    antecedent = z3.Solver()
    antecedent.set(timeout=5000, random_seed=0)
    antecedent.from_string(proof["antecedent_smt2"])
    counterexample = z3.Solver()
    counterexample.from_string(proof["counterexample_smt2"])
    original, expanded = list(antecedent.assertions()), list(counterexample.assertions())
    if (len(expanded) != len(original) + 1 or
            any(not first.eq(second) for first, second in zip(original, expanded)) or
            not z3.is_not(expanded[-1])):
        raise ValueError("proof does not preserve its antecedent and negated obligation")
    obligation = expanded[-1].arg(0)
    # Assembly deliberately keeps path and target as separate children here.
    if not z3.is_and(obligation) or obligation.num_args() != 2:
        raise ValueError("proof must separate path conditions from the target")
    return antecedent, obligation


def external_assumption(requirement, rule, nodes, policy):
    kind = requirement["kind"]
    record = {**requirement, "id": identifier("assumption", requirement["id"]),
              "status": "assumed", "policy_id": policy["id"],
              "origin": {"kind": "recorded_prerequisite", "id": requirement["id"]},
              "reason": policy["path_assumptions"]["reason"]}
    node = nodes.get(requirement.get("node"), {})
    record["location"] = node.get("location", nodes.get(rule["path"]["sink"], {}).get("location"))
    if kind == "transport_callback":
        condition = requirement.get("condition", {})
        if not all(condition.get(key) for key in ("operations", "handler", "registration")):
            return None
        record["location"] = condition["registration"]
        record["description"] = f"{condition['operations']} selects {condition['handler']}"
    elif kind == "interrupt_delivery":
        interrupt = rule["validation"].get("interrupt_registration", {})
        if not interrupt.get("handler"):
            return None
        record["registration"] = interrupt
        record["description"] = f"Registered interrupt is delivered to {interrupt['handler']}"
    elif kind == "memory":
        if not requirement.get("predicate"):
            return None
        record["description"] = "The recorded memory-object validity predicate holds"
    else:
        return None
    return record


def apply_path_assumptions(rule, nodes, policy):
    """Recheck a recorded obligation under an explicitly authorized path policy.

    Only original path conjuncts are eligible. Device assignments specialize
    mixed guards; no source-only condition, target equality, or solver-selected
    kernel witness is added to the antecedent.
    """
    reference = {key: policy[key] for key in ("id", "sha256")}
    rule["assumption_policy"] = reference
    validation = rule["validation"]
    validation["assumption_policy"] = reference
    for entry in rule.get("assumptions", []):
        entry["policy_id"] = policy["id"]
    validation["assumption_ledger"] = rule.get("assumptions", [])
    enabled = set(policy.get("path_assumptions", {}).get("kinds", []))
    if not enabled or rule["status"] != "conditional" or validation.get("result") != "sat":
        return rule
    base = validation["assumption_proof"]
    if not base.get("antecedent_smt2") or not base.get("counterexample_smt2"):
        return rule
    solver, obligation = replay_queries(base)
    path = obligation.arg(0)
    all_symbols = symbols(obligation)
    node_symbols = {}
    for identity in rule["vars"]:
        node = nodes.get(identity, {})
        expression = node.get("expression_id")
        if expression:
            prefix = "source" if node["kind"] == "source" else "environment"
            node_symbols[identifier(prefix, expression)] = identity
    replacements = []
    source_values = validation.get("source_assignments", {})
    missing_sources = {name: variable for name, variable in all_symbols.items()
                       if name.startswith("source:") and name in node_symbols and
                       node_symbols[name] not in source_values}
    if missing_sources:
        completion = z3.Solver()
        completion.set(timeout=5000, random_seed=0)
        completion.add(*solver.assertions(), obligation)
        if completion.check() != z3.sat:
            return rule
        model = completion.model()
        added = {}
        for name, variable in sorted(missing_sources.items()):
            identity = node_symbols[name]
            value = model.eval(variable, model_completion=True).as_long()
            added[identity] = value
            source_values[identity] = value
            rule["mutation_hint"].append({"operator": "SetValue", "var": identity, "value": value})
            solver.add(variable == value)
        validation["source_assignment_completion"] = {
            "method": "solve all source observations under the original path and target",
            "assignments": added, "original_proof": base}
        complete = z3.Solver()
        complete.add(*solver.assertions())
        complete_antecedent = complete.to_smt2()
        complete.add(z3.Not(obligation))
        base = {**base, "antecedent_smt2": complete_antecedent,
                "counterexample_smt2": complete.to_smt2()}
    for name, variable in all_symbols.items():
        identity = node_symbols.get(name)
        if name.startswith("source:") and identity in source_values:
            replacements.append((variable, z3.BitVecVal(source_values[identity], variable.size())))
    entries = list(rule.get("assumptions", []))
    seen = set()
    if "kernel_path_condition" in enabled:
        for address, clause in conjuncts(path):
            original_symbols = symbols(clause)
            condition = z3.substitute(clause, *replacements)
            remaining = symbols(condition)
            if (not remaining or not all(name.startswith("environment:") and name in node_symbols
                                         for name in remaining)):
                continue
            if condition.sexpr() in seen:
                continue
            seen.add(condition.sexpr())
            bindings = []
            for name in sorted(remaining):
                identity = node_symbols[name]
                node = nodes[identity]
                bindings.append({"symbol": name, "node": identity,
                                 "expression": node["expression_id"], "text": node.get("name"),
                                 "function": node.get("function"), "location": node.get("location"),
                                 "invocation": node.get("invocation")})
            sources = {node_symbols[name]: source_values[node_symbols[name]]
                       for name in sorted(original_symbols)
                       if name in node_symbols and node_symbols[name] in source_values}
            entry = {"id": identifier("assumption", "path:" + condition.sexpr()),
                     "kind": "kernel_path_condition", "status": "assumed", "policy_id": policy["id"],
                     "predicate": {"kind": "SmtBool", "expression": condition.sexpr()},
                     "origin": {"kind": "path_condition", "conjunct": list(address),
                                "expression": clause.sexpr()},
                     "bindings": bindings, "source_bindings": sources,
                     "description": "Path condition on " + ", ".join(
                         f"{item['text']} ({item['function']})" for item in bindings),
                     "reason": policy["path_assumptions"]["reason"]}
            entries.append(entry)
            solver.add(condition)
    remaining_prerequisites = []
    for requirement in validation.get("unresolved_prerequisites", []):
        assumed = (external_assumption(requirement, rule, nodes, policy)
                   if requirement["kind"] in enabled & EXTERNAL_KINDS else None)
        if assumed is None:
            remaining_prerequisites.append(requirement)
        else:
            entries.append(assumed)
    consistency = solver.check()
    antecedent_smt2 = solver.to_smt2()
    solver.add(z3.Not(obligation))
    counterexample = solver.check() if consistency == z3.sat else None
    proven = consistency == z3.sat and counterexample == z3.unsat
    if proven:
        covered = [item for item in remaining_prerequisites if item["kind"] == "internal_state"]
        validation["kernel_state_covered_by_proof"] = covered
        remaining_prerequisites = [item for item in remaining_prerequisites if item["kind"] != "internal_state"]
    validation["base_assumption_proof"] = base
    validation["assumption_proof"] = {
        "method": "source assignments, declared calls, and listed kernel path conditions",
        "internal_witnesses_fixed": False, "consistency": str(consistency),
        "counterexample": str(counterexample) if counterexample is not None else "not_checked",
        "proven": proven, "antecedent_smt2": antecedent_smt2,
        "counterexample_smt2": solver.to_smt2(), "assumption_ids": [e["id"] for e in entries],
        "assumption_ledger_sha256": ledger_digest(entries),
    }
    rule["assumptions"] = entries
    validation["assumption_ledger"] = entries
    validation["unresolved_prerequisites"] = remaining_prerequisites
    validation["assumption_constraints_proven"] = proven
    if proven and entries and not remaining_prerequisites:
        rule["status"] = "valid_under_assumptions"
    if not proven:
        path_check = z3.Solver()
        path_check.set(timeout=5000)
        path_check.from_string(antecedent_smt2)
        path_check.add(z3.Not(obligation.arg(0)))
        validation["path_constraints_proven"] = consistency == z3.sat and path_check.check() == z3.unsat
        validation["conditional_reason"] = (
            "target still depends on kernel values not determined by the listed path conditions"
            if validation["path_constraints_proven"] else
            "listed kernel conditions do not establish every modeled path condition")
    else:
        validation["path_constraints_proven"] = True
    return rule


def verify_path_assumptions(rule, nodes, policy):
    """Reconstruct listed conditions from the preserved original proof."""
    from copy import deepcopy

    validation = rule["validation"]
    if "base_assumption_proof" not in validation:
        return
    restored = deepcopy(rule)
    check = restored["validation"]
    restored["status"] = "conditional"
    restored["assumptions"] = [e for e in restored["assumptions"] if e["kind"] == "kernel_call"]
    check["assumption_proof"] = check.pop("base_assumption_proof")
    check["unresolved_prerequisites"].extend(check.pop("kernel_state_covered_by_proof", []))
    for entry in validation["assumption_ledger"]:
        if entry["kind"] not in EXTERNAL_KINDS:
            continue
        requirement = {key: value for key, value in entry.items() if key not in {
            "description", "reason", "origin", "policy_id", "registration", "location"}}
        requirement.update(id=entry["origin"]["id"], status="unresolved")
        check["unresolved_prerequisites"].append(requirement)
    apply_path_assumptions(restored, nodes, policy)
    assert restored["status"] == rule["status"], rule["id"]
    assert restored["assumptions"] == rule["assumptions"], rule["id"]
    for key in ("proven", "consistency", "counterexample", "assumption_ledger_sha256"):
        assert restored["validation"]["assumption_proof"][key] == validation["assumption_proof"][key], rule["id"]
    replayed = restored["validation"]["assumption_proof"]
    try:
        actual_solver, actual_obligation = replay_queries(validation["assumption_proof"])
        expected_solver, expected_obligation = replay_queries(replayed)
    except ValueError as error:
        raise AssertionError(rule["id"] + ": " + str(error)) from error
    assert_equivalent(actual_obligation, expected_obligation, rule["id"])
    actual, expected = list(actual_solver.assertions()), list(expected_solver.assertions())
    assert len(actual) == len(expected), rule["id"]
    for first, second in zip(actual, expected):
        assert_equivalent(first, second, rule["id"])
    assert str(actual_solver.check()) == replayed["consistency"], rule["id"]
    if replayed["consistency"] == "sat":
        actual_solver.add(z3.Not(actual_obligation))
        assert str(actual_solver.check()) == replayed["counterexample"], rule["id"]


def write_assumption_list(output):
    """Write one readable row per candidate assumption, including exact predicates."""
    from collections import Counter
    import csv

    ledger = json.loads((output / "assumption-ledger.json").read_text())
    entries = {item["id"]: item["entry"] for item in ledger["entries"]}
    counts = Counter()
    with (output / "path-assumptions.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["rule", "kind", "status", "description",
            "locations", "functions", "predicate", "source_bindings", "assumption_id"])
        writer.writeheader()
        for rule_id, identities in ledger["rule_entries"].items():
            for identity in identities:
                entry = entries[identity]
                if entry["status"] != "assumed":
                    continue
                counts[entry["kind"]] += 1
                bindings = entry.get("bindings", [])
                writer.writerow({"rule": rule_id, "kind": entry["kind"], "status": entry["status"],
                    "description": entry.get("description", entry.get("callee", "") + " " + entry.get("return", "")),
                    "locations": json.dumps([b.get("location") for b in bindings] or [entry.get("location")]),
                    "functions": json.dumps([b.get("function") for b in bindings] or [entry.get("callee")]),
                    "predicate": json.dumps(entry.get("predicate", entry.get("condition", {})), sort_keys=True),
                    "source_bindings": json.dumps(entry.get("source_bindings", {}), sort_keys=True),
                    "assumption_id": identity})
    lines = ["# Kernel path assumption list", "", f"Policy: `{ledger['policy_id']}`.", "",
             "`path-assumptions.csv` lists every assumed condition by rule, with its",
             "predicate, source binding, kernel function, and source location.", "",
             "| Assumption kind | Occurrences |", "| --- | ---: |"]
    lines.extend(f"| {kind} | {count} |" for kind, count in sorted(counts.items()))
    lines.extend(["", "`valid_under_assumptions` means the listed assumptions and device inputs",
                  "imply the modeled path and target. Kernel witness values are not assumed.",
                  "The complete ledger and replayable proof remain in each semantic SDG.", ""])
    (output / "path-assumptions.md").write_text("\n".join(lines))
