"""Fail-closed admission of executable and assumption-backed rules."""


def references(value):
    if isinstance(value, dict):
        if "node" in value:
            yield value["node"]
        for child in value.values():
            yield from references(child)
    elif isinstance(value, list):
        for child in value:
            yield from references(child)


def publication_errors(rule, nodes, edges, exports, policy=None):
    if rule.get("publication", {}).get("threshold") != "basic":
        return proof_publication_errors(rule, nodes, edges, exports, policy)
    from convert_to_sdg import validate_graph
    from guidance import guidance_errors
    from path_evidence import connected

    errors = guidance_errors(rule, nodes, edges)
    if not connected(rule, nodes, edges):
        errors.append("source-to-sink dependency path is not connected")
    try:
        validate_graph(rule, nodes, edges)
    except (KeyError, TypeError, ValueError) as error:
        errors.append("invalid semantic graph: " + str(error))
    if rule.get("validation", {}).get("result") == "unsat":
        errors.append("target is explicitly disproved by recorded constraints")
    return sorted(set(errors))


def proof_publication_errors(rule, nodes, edges, exports, policy=None):
    errors = []
    assumption_valid = rule.get("status") == "valid_under_assumptions"
    if rule.get("status") not in {"satisfiable", "valid_under_assumptions"}:
        errors.append("path feasibility is " + rule.get("status", "unrecorded"))
    validation = rule.get("validation", {})
    if validation.get("result") != "sat":
        errors.append("no satisfiable typed-constraint witness")
    if assumption_valid:
        if not rule.get("assumptions"):
            errors.append("valid-under-assumptions rule has no explicit kernel assumptions")
        if not validation.get("assumption_constraints_proven"):
            errors.append("assumptions have not been proved to imply the constraints")
        if not validation.get("assumption_ledger"):
            errors.append("valid-under-assumptions rule has no assumption ledger")
        proof = validation.get("assumption_proof", {})
        if (proof.get("consistency") != "sat" or proof.get("counterexample") != "unsat" or
                proof.get("internal_witnesses_fixed") is not False or not proof.get("proven")):
            errors.append("declared assumptions do not establish a non-vacuous implication")
        allowed = {"kernel_call"} | set((policy or {}).get("path_assumptions", {}).get("kinds", []))
        if any(item.get("kind") not in allowed or item.get("status") != "assumed"
               for item in validation.get("assumption_ledger", [])):
            errors.append("assumption ledger contains undeclared internal-state assumptions")
        ledger = validation.get("assumption_ledger", [])
        if validation.get("base_assumption_proof"):
            from path_assumptions import ledger_digest
            if (proof.get("assumption_ledger_sha256") != ledger_digest(ledger) or
                    proof.get("assumption_ids") != [entry["id"] for entry in ledger] or
                    ledger != rule.get("assumptions")):
                errors.append("proof and assumption list differ")
            if validation.get("unresolved_prerequisites"):
                errors.append("path prerequisites remain unresolved")
        if any(not any(item.get("kind") == "transport_callback" and item.get("condition") == condition
                       for item in ledger) for condition in validation.get("transport_conditions", [])) or any(
                item.get("kind") in {"memory", "transport_callback", "interrupt_delivery"}
                for item in validation.get("unresolved_prerequisites", [])):
            errors.append("external prerequisites remain unresolved")
    else:
        if validation.get("assumed_internal_values") or validation.get("transport_conditions"):
            errors.append("unresolved internal or transport prerequisites")
    if (not assumption_valid and
            not validation.get("source_assignments_imply_constraints")):
        errors.append("source assignments have not been proved to imply the constraints")
    export = rule.get("runtime_export", {})
    if not assumption_valid and export.get("file") not in exports:
        errors.append(export.get("reason", "no executable runtime export"))
    variables = set(rule.get("vars", []))
    if variables - nodes.keys():
        errors.append("undeclared rule variables")
    if set(references(rule)) - variables:
        errors.append("predicate references outside rule variables")
    path = rule.get("path", {})
    if (path.get("source") not in variables or path.get("sink") not in variables or
            nodes.get(path.get("source"), {}).get("kind") != "source" or
            nodes.get(path.get("sink"), {}).get("kind") != "sink"):
        errors.append("source/sink endpoints are not declared with the required kinds")
    relationships = list(path.get("edges", []))
    if not relationships:
        errors.append("empty dependency path")
    for identity in relationships:
        edge = edges.get(identity)
        if edge is None:
            errors.append("unresolved path edge")
            continue
        if (edge.get("src") not in variables or edge.get("dst") not in variables or
                set(references(edge)) - variables):
            errors.append("edge endpoints or predicates outside rule variables")
    target = rule.get("target_state", {})
    if (target.get("src") not in variables or target.get("dst") not in variables or
            not target.get("predicate")):
        errors.append("target endpoints or predicate are not closed")
    for key in variables & nodes.keys():
        if set(nodes[key].get("expressions", [])) - variables:
            errors.append("dependency node expressions outside rule variables")
    alternatives = path.get("alternatives", {})
    if set(alternatives.get("nodes", [])) - variables:
        errors.append("path alternatives outside rule variables")
    for step in alternatives.get("steps", []):
        if step.get("src") not in variables or step.get("dst") not in variables:
            errors.append("path step endpoints outside rule variables")
    hints = rule.get("mutation_hint", [])
    assignments = validation.get("source_assignments", {})
    assigned = {}
    if not hints:
        errors.append("empty executable mutation hint")
    for hint in hints:
        key = hint.get("var")
        node = nodes.get(key, {})
        source = node.get("source", {})
        width = source.get("size_bytes", 0) * 8
        value = hint.get("value")
        if assumption_valid and hint.get("operator") == "DeliverIrq":
            interrupt = validation.get("interrupt_registration", {})
            if (key not in variables or node.get("kind") != "source" or source.get("kind") != "Irq" or
                    not hint.get("handler") or hint["handler"] != interrupt.get("handler") or
                    not any(item.get("kind") == "interrupt_delivery" and item.get("node") == key
                            for item in validation.get("assumption_ledger", []))):
                errors.append("interrupt mutation lacks a matching delivery assumption")
            continue
        if (key not in variables or node.get("kind") != "source" or
                hint.get("operator") != "SetValue" or type(value) is not int or
                not 0 < width <= 64 or not 0 <= value < 1 << width):
            errors.append("mutation hint is not a typed writable source assignment")
            continue
        if key in assigned:
            errors.append("duplicate mutation destination")
        assigned[key] = value
    if assigned != assignments:
        errors.append("mutation hints differ from the proven source assignments")
    return sorted(set(errors))
