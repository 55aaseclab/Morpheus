import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys
import time

import z3

from semantics import Facts, FlowGraph, SymbolicPath, Unresolved, children, constant, identifier, integer, load_facts, truth
from graph import dependency_closure, edge_index, node_id, node_record, path_record, path_variables, preserve_graph, truth_predicate, unresolved_rule
from control import interrupt_rules
from rule_store import RuleStore
from memory import MemoryTarget, Quantity
from publication import publication_errors
from contracts import CallContracts, prove_under_assumptions, record_assumptions
from path_assumptions import apply_path_assumptions, write_assumption_list
from convert_to_sdg import export_rules, export_rule_stream


def expression_term(symbolic, key):
    facts = symbolic.facts
    expression = facts.expression(key)
    operands = children(expression)
    value = integer(expression.get("constant"))
    if key in facts.sources:
        return {"kind": "Ref", "node": node_id(facts, key)}
    if value is not None:
        return {"kind": "Const", "value": value, "type": expression["type"]}
    if key in symbolic.builtin_outputs or expression.get("callee") in {
            "__builtin_add_overflow", "__builtin_sub_overflow", "__builtin_mul_overflow"}:
        call_key = symbolic.builtin_outputs.get(key, key)
        call = facts.expression(call_key)
        arguments = children(call)
        destination = children(facts.expression(arguments[2]))[0]
        return {"kind": "OverflowResult" if key in symbolic.builtin_outputs else "OverflowFlag",
                "operation": call["callee"],
                "left": {"kind": "Ref", "node": node_id(facts, arguments[0])},
                "right": {"kind": "Ref", "node": node_id(facts, arguments[1])},
                "result_type": facts.expression(destination)["type"], "type": expression["type"]}
    if key in symbolic.merges:
        result = None
        for alternative in symbolic.merges[key]:
            value = {"kind": "Cast", "value": {"kind": "Ref", "node": node_id(facts, alternative["definition"])},
                     "type": expression["type"]}
            if result is None:
                result = value
            else:
                condition = {"kind": "And", "operands": [
                    {"kind": "Ne" if branch else "Eq", "left": {"kind": "Ref", "node": node_id(facts, condition)},
                     "right": {"kind": "Const", "value": 0}}
                    for condition, branch in alternative["conditions"]]}
                result = {"kind": "Conditional", "condition": condition, "then": value, "else": result}
        return result
    if key in symbolic.resolutions:
        return {"kind": "Cast", "value": {"kind": "Ref", "node": node_id(facts, symbolic.resolutions[key])},
                "type": expression["type"]}
    if key in symbolic.environment:
        return {"kind": "Ref", "node": node_id(facts, key)}
    if expression.get("callee") in {"__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64"}:
        return {"kind": "ByteSwap", "value": {"kind": "Ref", "node": node_id(facts, operands[0])},
                "type": expression["type"]}
    kind = expression.get("operator") or expression["class"]
    return {
        "kind": kind,
        "type": expression["type"],
        "operands": [{"position": position, "node": node_id(facts, child)}
                     for position, child in sorted(operands.items()) if child in symbolic.visited],
    }


def solver_for(conditions):
    solver = z3.Solver()
    solver.set(timeout=5000, random_seed=0)
    solver.add(z3.simplify(z3.And(*conditions)))
    return solver


def combine_predicates(kind, operands):
    unique = {}
    for operand in operands:
        if operand.get("kind") == ("Or" if kind == "And" else "And") and not operand.get("operands", [None]):
            return operand
        parts = operand["operands"] if operand.get("kind") == kind else [operand]
        for part in parts:
            unique[json.dumps(part, sort_keys=True)] = part
    if len(unique) == 1:
        return next(iter(unique.values()))
    return {"kind": kind, "operands": [unique[key] for key in sorted(unique)]}


def source_precondition(symbolic, key, source, active=None, cache=None):
    active = set() if active is None else active
    cache = {} if cache is None else cache
    if key in cache:
        return cache[key]
    if key == source or key in symbolic.source_values and symbolic.facts.origin(key) == source:
        return {"kind": "And", "operands": []}
    if key in active:
        return {"kind": "Or", "operands": []}
    active = active | {key}
    parts = []
    if key in symbolic.merges:
        alternatives = symbolic.merges[key]
        gates = [{"kind": "And", "operands": [truth_predicate(symbolic.facts, condition, branch)
                                                  for condition, branch in alternative["conditions"]]}
                 for alternative in alternatives]
        for index, alternative in enumerate(alternatives):
            parts.append(combine_predicates("And", [gates[index],
                *[{"kind": "Not", "operand": gate} for gate in gates[index + 1:]],
                source_precondition(symbolic, alternative["definition"], source, active, cache)]))
            parts.extend(source_precondition(symbolic, condition, source, active, cache)
                         for condition, _ in alternative["conditions"])
    else:
        for dependency, required in sorted(symbolic.evaluations[key], key=repr):
            parts.append(combine_predicates("And", [
                *[truth_predicate(symbolic.facts, condition, branch) for condition, branch in required],
                source_precondition(symbolic, dependency, source, active, cache)]))
    result = combine_predicates("Or", parts)
    cache[key] = result
    return result


def semantic_edges(symbolic, sink_id):
    facts = symbolic.facts
    edges = {}
    for key in sorted(symbolic.visited):
        if key in facts.sources or key in symbolic.environment:
            continue
        destination = node_id(facts, key)
        term = expression_term(symbolic, key)
        expression = facts.expression(key)
        dependencies = []
        if key in symbolic.builtin_outputs:
            call = facts.expression(symbolic.builtin_outputs[key])
            dependencies.extend(children(call)[position] for position in (0, 1))
        elif key in symbolic.merges:
            dependencies.extend(alternative["definition"] for alternative in symbolic.merges[key])
            dependencies.extend(condition for alternative in symbolic.merges[key]
                                for condition, _ in alternative["conditions"])
        elif key in symbolic.resolutions:
            dependencies.append(symbolic.resolutions[key])
        else:
            dependencies.extend(child for child in children(expression).values()
                                if child in symbolic.visited)
        predicate = {"kind": "Eq", "left": {"kind": "Ref", "node": destination}, "right": term}
        if not dependencies and integer(expression.get("constant")) is not None:
            dependencies.append(key)
        for dependency in sorted(set(dependencies)):
            edge = {"src": node_id(facts, dependency), "dst": destination,
                    "head": "head_dataflow", "predicate": predicate,
                    "location": expression["location"]}
            edges[json.dumps(edge, sort_keys=True)] = edge
    for guard in symbolic.path_guards:
        key = guard["condition"]
        condition = {"kind": "Ne", "left": {"kind": "Ref", "node": node_id(facts, key)},
                     "right": {"kind": "Const", "value": 0}}
        if not guard["branch"]:
            condition = {"kind": "Not", "operand": condition}
        if guard["activation"]:
            activation = {"kind": "And", "operands": [
                {"kind": "Ne" if branch else "Eq", "left": {"kind": "Ref", "node": node_id(facts, key)},
                 "right": {"kind": "Const", "value": 0}}
                for key, branch in guard["activation"]]}
            condition = {"kind": "Or", "operands": [{"kind": "Not", "operand": activation}, condition]}
        edge = {"src": node_id(facts, key), "dst": sink_id, "head": "head_guard",
                "predicate": condition, "location": facts.expression(key)["location"]}
        edges[json.dumps(edge, sort_keys=True)] = edge
    for exclusion in symbolic.path_exclusions:
        parts = []
        for guard in exclusion["conditions"]:
            predicate = {"kind": "Ne" if guard["branch"] else "Eq",
                         "left": {"kind": "Ref", "node": node_id(facts, guard["condition"])},
                         "right": {"kind": "Const", "value": 0}}
            parts.append(predicate)
        for key, branch in exclusion["activation"]:
            parts.append({"kind": "Ne" if branch else "Eq",
                          "left": {"kind": "Ref", "node": node_id(facts, key)},
                          "right": {"kind": "Const", "value": 0}})
        predicate = {"kind": "Not", "operand": {"kind": "And", "operands": parts}}
        for guard in exclusion["conditions"]:
            edge = {"src": node_id(facts, guard["condition"]), "dst": sink_id,
                    "head": "head_guard", "predicate": predicate, "location": exclusion["location"]}
            edges[json.dumps(edge, sort_keys=True)] = edge
    for key, source in symbolic.source_requirements.items():
        address = {"kind": "Add", "left": {"kind": "Ref", "node": node_id(facts, source["address"])},
                   "right": {"kind": "Const", "value": source["field_offset"]}}
        indices = source.get("indices", [{"expression": source["index"], "stride": source["stride"]}] if "index" in source else [])
        for index in indices:
            address = {"kind": "Add", "left": address, "right": {"kind": "Mul",
                       "left": {"kind": "Ref", "node": node_id(facts, index["expression"])},
                       "right": {"kind": "Const", "value": index["stride"]}}}
        end = {"kind": "Add", "left": address, "right": {"kind": "Const", "value": source["size_bytes"]}}
        alternatives = []
        for binding in source["bindings"]:
            base = {"kind": "Ref", "node": node_id(facts, binding["buffer"])}
            if "mapping_offset" in binding:
                base = {"kind": "Add", "left": base,
                        "right": {"kind": "Ref", "node": node_id(facts, binding["mapping_offset"])}}
            limit = {"kind": "Add", "left": base, "right": {"kind": "Ref", "node": node_id(facts, binding["size"])}}
            alternatives.append({"kind": "And", "operands": [
                *[truth_predicate(facts, condition, branch) for condition, branch in binding.get("conditions", [])],
                {"kind": "Ge", "left": address, "right": base},
                {"kind": "Le", "left": end, "right": limit},
                {"kind": "Ge", "left": end, "right": address},
                {"kind": "Ge", "left": limit, "right": base}]})
        edge = {"src": node_id(facts, source["address"]), "dst": node_id(facts, key),
                "head": "head_offset", "predicate": {"kind": "Or", "operands": alternatives},
                "location": source["location"]}
        edges[json.dumps(edge, sort_keys=True)] = edge
    for stored in symbolic.memory_equalities:
        def offset_term(fixed, indices):
            term = {"kind": "Const", "value": fixed}
            for index in indices:
                term = {"kind": "Add", "left": term, "right": {"kind": "Mul",
                        "left": {"kind": "Ref", "node": node_id(facts, index["expression"])},
                        "right": {"kind": "Const", "value": index["stride"]}}}
            return term
        edge = {"src": node_id(facts, stored["store"]), "dst": node_id(facts, stored["dst"]),
                "head": "head_offset", "predicate": {"kind": "Eq",
                    "left": offset_term(stored["write_offset"], stored["write_indices"]),
                    "right": offset_term(stored["read_offset"], stored["read_indices"])},
                "location": facts.expression(stored["dst"])["location"]}
        edges[json.dumps(edge, sort_keys=True)] = edge
    return list(edges.values())


def candidates(symbolic, sink):
    expression = symbolic.facts.expression(sink["operand"])
    width = expression["type"]["width"]
    signed = expression["type"]["signedness"] == "Signed"
    maximum = (1 << (width - int(signed))) - 1
    minimum = -(1 << (width - 1)) if signed else 0
    values = {0, 1, minimum, maximum}
    fixed = constant(symbolic.cache[sink["operand"]])
    if fixed is not None:
        values.add(fixed)
    sink_sources = symbolic.source_in(symbolic.cache[sink["operand"]])
    if "capacity" in sink:
        values.update(sink["capacity"] + delta for delta in (-1, 0, 1))
    for key in sink_sources:
        source_width = symbolic.facts.sources[key]["size_bytes"] * 8
        values.add((1 << source_width) - 1)
    for key in sorted(symbolic.visited):
        expression = symbolic.facts.expression(key)
        if expression.get("operator") not in {"<", "<=", ">", ">=", "==", "!="}:
            continue
        operands = children(expression)
        for position, operand in operands.items():
            if position not in (0, 1) or operand not in symbolic.cache:
                continue
            numeric = constant(symbolic.cache[operand])
            other = operands.get(1 - position)
            if numeric is not None and other in symbolic.cache and sink_sources & symbolic.source_in(symbolic.cache[other]):
                values.update(numeric + delta for delta in (-1, 0, 1))
    return sorted(value for value in values if minimum <= value <= maximum)


def runtime_export(rule, facts, symbolic, formula, assignments):
    if symbolic.environment_in(formula):
        return None, "required internal state cannot be encoded by the scalar runtime format"
    if not assignments or len(assignments) > 2:
        return None, "runtime generator supports at most one additional required source"
    bindings = {key: facts.binding(key) for key in assignments}
    if any(binding.get("byte_order") not in {None, "Little"} and binding["size_bytes"] > 1
           for binding in bindings.values()):
        return None, "source byte order needs explicit runtime lowering"
    if any(binding.get("transport_condition") for binding in bindings.values()):
        return None, "transport callback selection is an explicit prerequisite"
    if any(binding.get("placement_unresolved") for binding in bindings.values()):
        return None, "source address has unresolved mapping provenance"
    if any(binding.get("access_context") for binding in bindings.values()):
        return None, "MMIO write/read context requires runtime observation binding"
    if any(binding["kind"] != "MmioRead" or "offset" not in binding for binding in bindings.values()):
        return None, "source placement is unresolved or unsupported by the scalar runtime"
    if len({binding["offset"] & ~3 for binding in bindings.values()}) != len(bindings):
        return None, "multiple reads share a runtime word; observation binding is required"
    if len({binding.get("mapping") for binding in bindings.values()}) > 1:
        return None, "multiple MMIO regions require explicit runtime region binding"
    constraints = [symbolic.source_values[key] == value for key, value in assignments.items()]
    check = solver_for(constraints + [z3.Not(formula)])
    if check.check() != z3.unsat:
        return None, "fixed source assignments do not imply all extracted constraints"
    source = rule["path"]["source_expression"]
    if source not in assignments:
        return None, "target has no assignment to its source"
    target = node_id(facts, source)
    value = assignments[source]
    function = facts.expression(source)["function"].split(":")[-1]
    suffix = identifier("site", rule["id"]).split(":")[1]
    wire_id = f"rule:{function}@{suffix}|target:{target}|predicate:eq:{value}"
    lines = [f"rule {wire_id}"]
    for key, binding in sorted(bindings.items()):
        lines.append(f"node {node_id(facts, key)} mmio {hex(binding['offset'])} {binding['size_bytes']}")
    for key in sorted(assignments):
        if key != source:
            lines.append(f"precondition {node_id(facts, key)} {target} head_guard eq {assignments[key]}")
    lines.extend([f"trigger {target} head_bound eq {value}", f"mutation set_value {value}"])
    return {"id": wire_id, "text": "\n".join(lines) + "\n"}, None


def matches_selection(facts, flow, sink, selection):
    if not selection:
        return True
    source = facts.expression(flow["source_expr"])
    binding = facts.binding(flow["source_expr"])
    properties = {"source_function": source["function"].split(":")[-1],
                  "source_offset": binding.get("offset"),
                  "sink_function": sink["function"].split(":")[-1],
                  "sink_operation": sink["operation"], "sink_argument": sink.get("argument"),
                  "dependency": flow.get("dependency", "data")}
    if selection.keys() - properties.keys():
        raise ValueError("unknown path selection fields")
    return all(properties[key] == value for key, value in selection.items())


def assemble(facts_path, paths_path, target_info=None, progress=None, rule_store=None,
             selection=None, assumptions=None):
    target_configuration = json.loads(Path(target_info).read_text()) if target_info else None
    facts = Facts(load_facts(facts_path), target_configuration)
    assumption_policy = CallContracts(assumptions).policy_record()
    path_sections = load_facts(paths_path)
    graph = FlowGraph(path_sections)
    control_groups = {}
    for dependency in path_sections["control_dependency"].values():
        identity = (dependency["source"], dependency["source_expr"], dependency["sink_key"])
        group = control_groups.setdefault(identity, {"conditions": set(), "endpoints": set()})
        group["conditions"].add((dependency["guard"], dependency["branch"]))
        group["endpoints"].update(dependency["endpoints"])
    for (source, source_expression, sink_key), group in sorted(control_groups.items()):
        dependency = {"source": source, "source_expr": source_expression, "sink_key": sink_key,
                      "control_guards": [{"condition": guard, "branch": branch}
                                         for guard, branch in sorted(group["conditions"])],
                      "endpoints": sorted(group["endpoints"])}
        sink = facts.sections["sink"][dependency["sink_key"]]
        key = identifier("flow", source + "|" + source_expression + "|" + sink_key + "|control")
        graph.flows[key] = {**dependency, "dependency": "control", "sink": min(dependency["endpoints"]),
                           "guard_endpoints": dependency["endpoints"], "sink_expr": sink["flow_operand"]}
    sinks = defaultdict(list)
    for key, sink in facts.sections["sink"].items():
        sinks[sink["flow_operand"]].append((key, sink))
    nodes, edges = preserve_graph(facts, graph)
    indexed = edge_index(edges)
    rules = rule_store if rule_store is not None else []
    rejected, unresolved, exports = [], [], {}
    context_count = 0
    reused_contexts = 0
    pending_failures = defaultdict(list)
    previous_flow = None
    last_progress = 0
    for flow_index, (flow_key, contextual_flow) in enumerate(graph.contextual_flows(facts)):
        context_count += 1
        witness = contextual_flow["_witness"]
        context_id = contextual_flow["context_id"]
        base_flow = contextual_flow["_base_flow"]
        if previous_flow != base_flow:
            for entries in pending_failures.values():
                for _, rule in entries:
                    rules.append(rule)
            pending_failures.clear()
            previous_flow = base_flow
        flow = {key: value for key, value in contextual_flow.items()
                if not key.startswith("_") and key != "context_id"}
        if progress and (flow_index % 100 == 0 or time.monotonic() - last_progress >= 30):
            last_progress = time.monotonic()
            progress({"phase": "rules", "flows_processed": contextual_flow["_flow_index"],
                      "flows_total": len(graph.flows), "contexts_processed": flow_index,
                      "reused_unresolved_contexts": reused_contexts,
                      "rules": len(rules), "unresolved": len(unresolved)})
        if flow["source_expr"] not in facts.sources:
            unresolved.append({"flow": flow, "reason": "source is not declared"})
            continue
        matching_sinks = [(flow["sink_key"], facts.sections["sink"][flow["sink_key"]])] if "sink_key" in flow else sinks.get(flow["sink_expr"], [])
        for sink_key, sink in sorted(matching_sinks):
            if not matches_selection(facts, flow, sink, selection):
                continue
            contracts = CallContracts(assumptions)
            symbolic = None
            try:
                witness_expressions = [expression for key in witness
                                       for expression in graph.nodes[key]["expressions"]]
                symbolic = SymbolicPath(facts, witness_expressions, contracts)
                equivalent = next((rule for dependencies, rule in pending_failures[sink_key]
                                   if symbolic.matches_context_dependencies(dependencies)), None)
                if equivalent is not None:
                    equivalent["path"]["equivalent_contexts"].append({
                        "context_id": context_id,
                        "witness_nodes": [graph.node_ids[key] for key in witness]})
                    reused_contexts += 1
                    continue
                control_dependency = flow.get("dependency") == "control"
                if control_dependency:
                    requirements = []
                    for guard in flow["control_guards"]:
                        guard_value = truth(symbolic.resolve(guard["condition"]))
                        requirements.append(guard_value if guard["branch"] else z3.Not(guard_value))
                    required_guard = z3.And(*requirements)
                    if solver_for([required_guard, *symbolic.domain_constraints]).check() == z3.unsat:
                        rejected.append({"flow": flow, "reason": "control branch is impossible"})
                        continue
                memory = MemoryTarget(symbolic, sink) if facts.expression(sink["operand"])["type"].get("kind") == "pointer" else None
                target_value = memory.value if memory else symbolic.resolve(sink["operand"])
                if z3.is_bool(target_value):
                    raise Unresolved("sink operand is not an integer")
                if not control_dependency and not memory and flow["source_expr"] not in {facts.origin(key) for key in symbolic.source_in(target_value)}:
                    if constant(target_value) is not None and not symbolic.environment_in(target_value):
                        rejected.append({"flow": flow, "reason": "resolved sink value is independent of this source"})
                        continue
                    raise Unresolved("symbolic sink expression does not depend on this source")
                conditions = symbolic.conditions(sink["expression"], sink["operand"])
                if control_dependency:
                    if flow["source_expr"] not in {facts.origin(key) for key in symbolic.source_in(required_guard)}:
                        raise Unresolved("control guard still requires unresolved value bindings")
                    conditions.append(required_guard)
                    symbolic.path_guards.extend({**guard, "activation": ()} for guard in flow["control_guards"])
                else:
                    conditions.append(symbolic.source_dependency(sink["operand"], flow["source_expr"]))
                path_formula = z3.simplify(z3.And(*conditions))
                solver = solver_for(conditions + contracts.scoped_constraints(symbolic))
                reachable = solver.check()
                if reachable == z3.unsat:
                    if symbolic.unknown_integer_semantics:
                        raise Unresolved("path rejection depends on unrecorded signed-overflow compiler flags")
                    rejected.append({"flow": flow, "reason": "path constraints are inconsistent"})
                    continue
                if reachable == z3.unknown:
                    raise Unresolved("solver could not decide path feasibility")
                sink_id = identifier("sink", sink_key)
                nodes[sink_id] = {"id": sink_id, "kind": "sink", **sink}
                source_dependencies = dependency_closure(facts, symbolic.source_values)
                for key in symbolic.visited | source_dependencies:
                    record = node_record(facts, key)
                    if key in symbolic.environment:
                        record["required_internal_state"] = True
                        record["unresolved_reason"] = symbolic.assumption_reasons[key]
                    nodes[record["id"]] = record
                dependencies = semantic_edges(symbolic, sink_id)
                if memory:
                    dependencies.append(memory.edge(sink_id))
                if not control_dependency:
                    dependencies.append({"src": node_id(facts, flow["source_expr"]), "dst": sink_id,
                                         "head": "head_guard",
                                         "predicate": source_precondition(symbolic, sink["operand"], flow["source_expr"]),
                                         "location": sink["location"]})
                sink_edge = {"src": node_id(facts, sink["operand"]), "dst": sink_id,
                             "head": "head_call" if "argument" in sink else "head_offset",
                             "predicate": {"kind": "Eq", "operand": sink["operation"],
                                           "value": {"kind": "Ref", "node": node_id(facts, sink["operand"])}},
                             "location": sink["location"]}
                dependencies.append(sink_edge)
                for index, edge in enumerate(dependencies):
                    edge_key = json.dumps(edge, sort_keys=True)
                    dependencies[index] = edges.setdefault(edge_key, edge)
                targets = list(memory.candidates()) if memory else [(str(value), Quantity(
                    z3.BitVecVal(value, target_value.size()), {"kind": "Const", "value": value,
                        "type": facts.expression(sink["operand"])["type"]})) for value in candidates(symbolic, sink)]
                feasible_value = solver.model().eval(target_value, model_completion=True)
                if not any(z3.is_true(z3.simplify(candidate.value == feasible_value)) for _, candidate in targets):
                    value = feasible_value.as_signed_long() if not memory and facts.expression(sink["operand"])["type"]["signedness"] == "Signed" else feasible_value.as_long()
                    targets.append(("feasible:" + str(value), Quantity(feasible_value, {"kind": "Const", "value": value})))
                for target_key, candidate in targets:
                    target = candidate.term if memory else candidate.term["value"]
                    constraint = target_value == candidate.value
                    solver.push()
                    solver.add(constraint)
                    decision = solver.check()
                    if decision == z3.unsat:
                        if symbolic.unknown_integer_semantics:
                            unresolved.append({"flow": flow, "target": target,
                                               "reason": "target rejection depends on unrecorded signed-overflow compiler flags"})
                            solver.pop()
                            continue
                        rejected.append({"source": node_id(facts, flow["source_expr"]), "sink": sink_id,
                                         "target": target, "reason": "target contradicts dataflow or path constraints"})
                        solver.pop()
                        continue
                    if decision == z3.unknown:
                        solver.pop()
                        unresolved.append({"flow": flow, "target": target, "reason": "solver timeout"})
                        timed_out = unresolved_rule(facts, graph, flow_key, flow, sink_key, sink,
                                                    "solver timeout", indexed)
                        timed_out["id"] = identifier("rule", flow_key + "|" + sink_key + "|" + target_key)
                        timed_out["path"].update(context_id=context_id,
                            witness=[graph.nodes[key] for key in witness])
                        target_node = node_id(facts, sink["operand"])
                        timed_out["target_state"] = {"src": target_node, "dst": target_node,
                            "head": "head_offset" if memory else "head_bound",
                            "predicate": {"kind": "Eq", "left": memory.term if memory else
                                {"kind": "Ref", "node": target_node}, "right": candidate.term}}
                        record_assumptions(timed_out, contracts, symbolic)
                        rules.append(timed_out)
                        continue
                    model = solver.model()
                    assignments = {key: model.eval(value, model_completion=True).as_long()
                                   for key, value in sorted(symbolic.source_values.items())
                                   if z3.is_true(model.eval(z3.Or(*symbolic.source_activations[key]),
                                                            model_completion=True))}
                    observations = sorted(key for key in assignments if facts.origin(key) == flow["source_expr"])
                    if not observations:
                        solver.pop()
                        unresolved.append({"flow": flow, "target": target, "reason": "no active source observation in the selected context"})
                        continue
                    source_observation = observations[0]
                    guard_keys = symbolic.environment_in(z3.And(path_formula, constraint))
                    proof = prove_under_assumptions(symbolic, z3.And(path_formula, constraint), assignments)
                    external_prerequisites = bool(memory and memory.requirements or any(
                        facts.sources[key].get("transport_condition") for key in symbolic.source_values))
                    has_conditional_state = bool(
                        guard_keys or memory and memory.requirements or any(
                            facts.sources[key].get("transport_condition")
                            for key in assignments))
                    valid_under_assumptions = bool(
                        has_conditional_state and contracts.used and proof["proven"] and not external_prerequisites)
                    rule_id = identifier("rule", flow_key + "|" + sink_key + "|" + target_key)
                    target_node = node_id(facts, sink["operand"])
                    target_edge = {"src": target_node, "dst": target_node, "head": "head_offset" if memory else "head_bound",
                                   "predicate": {"kind": "Eq", "left": memory.term if memory else {"kind": "Ref", "node": target_node},
                                                 "right": candidate.term},
                                   "location": sink["location"]}
                    rule = {
                        "id": rule_id,
                        "status": "valid_under_assumptions" if valid_under_assumptions else (
                            "conditional" if has_conditional_state else "satisfiable"),
                        "vars": sorted({node_id(facts, key) for key in symbolic.visited | source_dependencies} |
                                       path_variables(facts, graph, flow, sink_key)),
                        "path": {**path_record(facts, graph, flow, sink_key),
                                 "context_id": context_id,
                                 "source": node_id(facts, source_observation),
                                 "source_expression": source_observation,
                                 "origin_source_expression": flow["source_expr"],
                                 "source_observations": [node_id(facts, key) for key in observations],
                                 "witness": [graph.nodes[key] for key in witness],
                                 "edges": dependencies},
                        "preconditions": {"kind": "And", "operands": [
                            edge["predicate"] for edge in dependencies if edge["head"] == "head_guard"] +
                            (memory.requirements if memory else [])},
                        "target_state": target_edge,
                        "mutation_hint": [{"operator": "SetValue", "var": node_id(facts, key), "value": value}
                                          for key, value in sorted(assignments.items())],
                        "validation": {"method": "typed bit-vector constraints", "result": "sat",
                                       "source_assignments": {node_id(facts, key): value for key, value in assignments.items()},
                                       "transport_conditions": [facts.sources[key]["transport_condition"]
                                                                for key in assignments
                                                                if facts.sources[key].get("transport_condition")],
                                       "assumption_proof": proof,
                                       "assumption_constraints_proven": proof["proven"],
                                       "kernel_reachability_proven": False,
                                       "runtime_execution": False},
                    }
                    record_assumptions(rule, contracts, symbolic, model, z3.And(path_formula, constraint),
                                       memory.requirements if memory else ())
                    if memory:
                        rule["validation"]["memory_access"] = memory.validation(model)
                    wire, reason = (None, "memory validity remains a workload prerequisite") if memory and memory.requirements else runtime_export(
                        rule, facts, symbolic, z3.And(path_formula, constraint), assignments)
                    if wire:
                        filename = hashlib.sha256(wire["id"].encode()).hexdigest()[:24] + ".sdg"
                        exports[filename] = wire["text"]
                        rule["runtime_export"] = {"file": filename, "id": wire["id"],
                                                  "placement": "runtime chooses a read visit",
                                                  "kernel_reachability_proven": False}
                        rule["validation"]["source_assignments_imply_constraints"] = True
                    else:
                        rule["runtime_export"] = {"reason": reason}
                    apply_path_assumptions(rule, nodes, assumption_policy)
                    rules.append(rule)
                    edges[json.dumps(target_edge, sort_keys=True)] = target_edge
                    solver.pop()
            except (Unresolved, RecursionError, z3.Z3Exception) as error:
                unresolved.append({"flow": flow, "sink": sink, "reason": str(error)})
                rule = unresolved_rule(facts, graph, flow_key, flow, sink_key, sink, str(error), indexed)
                rule["path"]["context_id"] = context_id
                rule["path"]["witness"] = [graph.nodes[key] for key in witness]
                record_assumptions(rule, contracts, symbolic)
                if symbolic is not None:
                    for key in symbolic.visited:
                        nodes[node_id(facts, key)] = node_record(facts, key)
                if isinstance(error, Unresolved) and symbolic is not None:
                    rule["path"]["equivalent_contexts"] = []
                    pending_failures[sink_key].append((symbolic.context_dependencies(), rule))
                else:
                    rules.append(rule)
    for entries in pending_failures.values():
        for _, rule in entries:
            rules.append(rule)
    control_nodes, control_edges, control_rules, control_diagnostics, control_flows = (
        ({}, {}, [], [], 0) if selection else interrupt_rules(
            facts, path_sections, semantic_edges, candidates, indexed, assumptions))
    nodes.update(control_nodes)
    edges.update(control_edges)
    rules.extend(control_rules)
    unresolved.extend(control_diagnostics)
    summary = {
        "flows": len(graph.flows), "rules": len(rules),
        "control_flows": control_flows,
        "control_dependencies": len(path_sections["control_dependency"]),
        "control_paths": len(control_groups),
        "statuses": dict(rules.statuses if isinstance(rules, RuleStore) else Counter(rule["status"] for rule in rules)),
        "runtime_exports": len(exports), "rejected": len(rejected), "unresolved": len(unresolved),
        "source_kinds": dict(Counter(source["kind"] for source in list(facts.sources.values()) + list(facts.interrupts.values()))),
        "unmodeled_source_kinds": [],
        "pending_semantics": ["page-pool and scatter DMA provenance", "coherent allocation lifetime and aligned subregions",
                              "asynchronous callback state", "loop recurrences", "all alternative value contexts",
                              "MMIO selector and runtime read-visit binding"],
        "path_selection": "distinct endpoint/call/store witness contexts; cyclic alternatives retained in the graph",
        "analyzed_contexts": context_count,
        "reused_unresolved_contexts": reused_contexts,
        "target_byte_order": target_configuration["byte_order"] if target_configuration else "Unknown",
        "signed_overflow": facts.signed_overflow,
        "assumption_policy": assumption_policy,
        "selection": selection,
    }
    return {"paths_file": str(paths_path), "nodes": sorted(nodes.values(), key=lambda node: node["id"]),
            "edges": [edges[key] for key in sorted(edges)],
            "rules": rules if isinstance(rules, RuleStore) else sorted(rules, key=lambda rule: rule["id"]),
            "rejected": rejected, "unresolved": unresolved, "exports": exports, "summary": summary}


def write_result(result, output, publication_threshold="basic"):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    def write_json(path, value):
        with path.open("w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
    identities = {id(edge): identifier("edge", json.dumps(edge, sort_keys=True)) for edge in result["edges"]}
    def edge_id(edge):
        if id(edge) not in identities:
            identities[id(edge)] = identifier("edge", json.dumps(edge, sort_keys=True))
        return identities[id(edge)]
    write_json(output / "sdg-nodes.json", {"version": "1.2", "count": len(result["nodes"]), "nodes": result["nodes"]})
    write_json(output / "assumption-policy.json", {
        "version": "1.2", "policy": result["summary"].get("assumption_policy", {})
    })
    # Keep every diagnostic path, but publish only executable, closed rules.
    node_index = {node["id"]: node for node in result["nodes"]}
    edge_index_by_id = {edge_id(edge): {"id": edge_id(edge), **edge} for edge in result["edges"]}
    admitted, withheld, conditional = [], [], []
    policy = result["summary"].get("assumption_policy", {})
    native_paths = None
    if publication_threshold == "basic" and result.get("paths_file"):
        from path_evidence import NativePaths
        native_paths = NativePaths(Path(result["paths_file"]), node_index)
    ledger_entries, rule_entries = {}, {}
    requirement_counts, unresolved_reasons = Counter(), Counter()
    scope = result.get("scope", {})
    coverage = {name: {"file": name, "sources": 0, "sinks": 0,
                       "source_candidates": Counter(), "sink_candidates": Counter()}
                for name in scope.get("input_files", [])}
    for node in result["nodes"]:
        name = node.get("location", {}).get("file")
        if name in coverage and node["kind"] in {"source", "sink"}:
            coverage[name]["sources" if node["kind"] == "source" else "sinks"] += 1

    def record_candidate(rule):
        if publication_threshold == "basic":
            from guidance import attach_guidance
            if native_paths:
                evidence = native_paths.evidence(rule)
                if evidence:
                    rule["path_evidence"] = evidence
            attach_guidance(rule, node_index, edge_index_by_id)
        if rule["status"] == "conditional" and publication_errors(
                rule, node_index, edge_index_by_id, result["exports"], policy):
            conditional.append(rule)
        validation = rule.get("validation", {})
        combined = validation.get("assumption_ledger", []) + validation.get("unresolved_prerequisites", [])
        identities = []
        for entry in combined:
            identity = identifier("ledger", json.dumps(entry, sort_keys=True))
            ledger_entries[identity] = {"id": identity, "entry": entry}
            identities.append(identity)
            requirement_counts[entry["kind"] + ":" + entry["status"]] += 1
        rule_entries[rule["id"]] = sorted(set(identities))
        if rule["status"] == "unresolved":
            unresolved_reasons[validation.get("reason", "unspecified")] += 1
        for endpoint in ("source", "sink"):
            name = node_index.get(rule["path"][endpoint], {}).get("location", {}).get("file")
            if name in coverage:
                coverage[name][endpoint + "_candidates"][rule["status"]] += 1
    with (output / "sdg-candidates.json").open("w") as stream:
        stream.write('{"version":"1.2","count":' + str(len(result["rules"])) + ',"rules":[\n')
        if isinstance(result["rules"], RuleStore):
            for index, payload in enumerate(result["rules"].encoded_records()):
                if index:
                    stream.write(",\n")
                rule = json.loads(payload)
                record_candidate(rule)
                json.dump(rule, stream, separators=(",", ":"))
                errors = publication_errors(rule, node_index, edge_index_by_id, result["exports"], policy)
                if errors:
                    withheld.append({"id": rule["id"], "status": rule["status"], "reasons": errors})
                else:
                    admitted.append(rule)
        else:
            for index, rule in enumerate(result["rules"]):
                if index:
                    stream.write(",\n")
                rule = {**rule, "path": {**rule["path"], "edges": [edge_id(edge) for edge in rule["path"]["edges"]]}}
                record_candidate(rule)
                json.dump(rule, stream, separators=(",", ":"))
                errors = publication_errors(rule, node_index, edge_index_by_id, result["exports"], policy)
                if errors:
                    withheld.append({"id": rule["id"], "status": rule["status"], "reasons": errors})
                else:
                    admitted.append(rule)
        stream.write("\n]}\n")
    write_json(output / "sdg-rules.json", {"version": "1.2", "count": len(admitted), "rules": admitted})
    admitted_files = {rule["runtime_export"]["file"] for rule in admitted
                      if rule.get("runtime_export", {}).get("file")}
    result["summary"].update(
        candidates=len(result["rules"]),
        candidate_statuses=dict(Counter(rule["status"] for rule in result["rules"])),
        rules=len(admitted), statuses=dict(Counter(rule["status"] for rule in admitted)),
        runtime_exports=len(admitted_files), semantic_exports=len(admitted),
        conditional_exports=len(conditional),
        unresolved_exports=sum(rule["status"] == "unresolved" for rule in withheld), withheld=len(withheld),
        publication_threshold=publication_threshold)
    write_json(output / "assumption-ledger.json", {
        "version": "1.2", "policy_id": policy.get("id"),
        "candidate_count": len(rule_entries), "occurrences": dict(sorted(requirement_counts.items())),
        "entries": [ledger_entries[key] for key in sorted(ledger_entries)],
        "rule_entries": rule_entries,
        "witness_values": "per-candidate validation.internal_state_witness; never assumed"})
    write_json(output / "analysis-coverage.json", {
        "version": "1.2", "scope": scope, "selection": result["summary"].get("selection"),
        "policy_id": policy.get("id"), "files": [coverage[key] for key in sorted(coverage)],
        "candidate_count": len(rule_entries), "unresolved_reasons": dict(unresolved_reasons.most_common())})
    edges = [{"id": edge_id(edge), **edge} for edge in result["edges"]]
    self_edges = [edge for edge in edges if edge["src"] == edge["dst"]]
    cross_edges = [edge for edge in edges if edge["src"] != edge["dst"]]
    write_json(output / "sdg-edges.json", {
        "version": "1.2", "self_count": len(self_edges), "cross_count": len(cross_edges),
        "self_edges": self_edges, "cross_edges": cross_edges,
    })
    write_json(output / "sdg-diagnostics.json", {
        "summary": result["summary"], "rejected": result["rejected"], "unresolved": result["unresolved"],
        "withheld": withheld
    })
    export_dir = output / "runtime-sdg"
    export_dir.mkdir(exist_ok=True)
    for stale in export_dir.glob("*.sdg"):
        stale.unlink()
    for filename, contents in sorted(result["exports"].items()):
        if filename in admitted_files:
            (export_dir / filename).write_text(contents)
    export_rules(admitted, node_index, {edge["id"]: edge for edge in edges}, output / "sdg")
    export_rules(conditional, node_index, {edge["id"]: edge for edge in edges}, output / "sdg-conditional")
    def unresolved_records():
        withheld_ids = {item["id"] for item in withheld}
        for rule in result["rules"]:
            if rule["status"] != "unresolved" or rule["id"] not in withheld_ids:
                continue
            if not isinstance(result["rules"], RuleStore):
                rule = {**rule, "path": {**rule["path"], "edges": [edge_id(edge) for edge in rule["path"]["edges"]]}}
            if publication_threshold == "basic":
                from guidance import attach_guidance
                if native_paths:
                    evidence = native_paths.evidence(rule)
                    if evidence:
                        rule["path_evidence"] = evidence
                attach_guidance(rule, node_index, edge_index_by_id)
            yield rule
    export_rule_stream(unresolved_records, node_index, {edge["id"]: edge for edge in edges}, output / "sdg-unresolved")
    write_assumption_list(output)
    from guidance import write_hint_index
    write_hint_index(output / "mutation-hints.csv", admitted, output / "sdg")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--facts", type=Path, required=True)
    parser.add_argument("--paths", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-info", type=Path)
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--assumptions", type=Path)
    parser.add_argument("--source-verification", type=Path)
    parser.add_argument("--publication-threshold", choices=("basic", "proof"), default="basic")
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)
    store = RuleStore(arguments.output)
    try:
        result = assemble(arguments.facts, arguments.paths, arguments.target_info,
                          progress=lambda message: print(json.dumps(message), file=sys.stderr, flush=True),
                          rule_store=store,
                          selection=json.loads(arguments.selection.read_text()) if arguments.selection else None,
                          assumptions=CallContracts.load(arguments.assumptions).configuration)
        result["scope"] = json.loads(arguments.source_verification.read_text()) if arguments.source_verification else {}
        write_result(result, arguments.output, arguments.publication_threshold)
        print(json.dumps(result["summary"], sort_keys=True))
    finally:
        store.close()


if __name__ == "__main__":
    main()
