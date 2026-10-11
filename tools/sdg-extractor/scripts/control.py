from collections import defaultdict
import json

import z3

from graph import dependency_closure, node_id, node_record, selected_edges, sink_edge
from semantics import FlowGraph, SymbolicPath, Unresolved, identifier
from memory import MemoryTarget, Quantity
from contracts import CallContracts, record_assumptions, prove_under_assumptions
from path_assumptions import apply_path_assumptions


def interrupt_graph(facts, sections):
    control = defaultdict(dict)

    def function_node(key):
        identity = "function:" + key
        function = facts.sections["function"][key]
        control["flow_node"][identity] = {"text": function["name"], "location": function["location"],
                                          "expressions": [], "function": key}
        return identity

    def step(previous, following):
        control["flow_step"][previous + "->" + following] = {"src": previous, "dst": following}

    for call in sections["control_call"].values():
        identity = "call:" + call["call"] + ":" + call["callee"]
        control["flow_node"][identity] = {
            "text": "call to " + facts.sections["function"][call["callee"]]["name"],
            "expressions": [call["call"]], "location": call["location"],
            "call": call["call"], "callee": call["callee"],
        }
        step(function_node(call["caller"]), identity)
        step(identity, function_node(call["callee"]))
    for item in sections["control_sink"].values():
        sink = facts.sections["sink"][item["sink"]]
        identity = "sink:" + item["sink"]
        control["flow_node"][identity] = {
            "text": sink["operation"], "expressions": [sink["expression"]], "location": sink["location"],
        }
        step(function_node(item["function"]), identity)
    for key, interrupt in facts.interrupts.items():
        control["flow_node"][key] = {"text": interrupt["handler"], "expressions": [],
                                     "location": interrupt["location"]}
        step(key, function_node(interrupt["function"]))
    graph = FlowGraph(control, namespace="control")
    for key in facts.interrupts:
        pending, reachable = [key], set()
        while pending:
            current = pending.pop()
            if current in reachable:
                continue
            reachable.add(current)
            pending.extend(graph.next[current])
        for item in sections["control_sink"].values():
            endpoint = "sink:" + item["sink"]
            if endpoint in reachable:
                graph.flows[key + "->" + endpoint] = {
                    "source": key, "sink": endpoint, "sink_key": item["sink"],
                }
    return graph


def interrupt_rules(facts, sections, make_semantic_edges, candidate_values, indexed, assumptions=None):
    graph = interrupt_graph(facts, sections)
    nodes, edges, rules, diagnostics = {}, {}, [], []
    for key, node in graph.nodes.items():
        identity = graph.node_ids[key]
        nodes[identity] = {"id": identity, "kind": "internal", "name": node["text"],
                           "location": node["location"], "control_id": key,
                           "expressions": [node_id(facts, expression) for expression in node["expressions"]]}
    for flow_key, flow in graph.contextual_flows(facts):
        interrupt = facts.interrupts[flow["source"]]
        source_id = node_id(facts, flow["source"])
        sink_key = flow["sink_key"]
        sink = facts.sections["sink"][sink_key]
        sink_id = identifier("sink", sink_key)
        reachable, steps = graph.subgraph(flow["source"], flow["sink"])
        expressions = [expression for key in reachable for expression in graph.nodes[key]["expressions"]]
        required = dependency_closure(facts, expressions + [sink["operand"]])
        relationships = selected_edges(facts, required, indexed)
        target = sink_edge(facts, sink_key, sink)
        relationships[json.dumps(target, sort_keys=True)] = target
        path = {
            "source": source_id, "sink": sink_id, "source_expression": flow["source"],
            "dependency": "interrupt",
            "context_id": flow["context_id"],
            "alternatives": {
                "nodes": [graph.node_ids[key] for key in sorted(reachable)],
                "steps": [graph.step_records[previous, following] for previous, following in steps],
            },
            "edges": list(relationships.values()),
        }
        base = {
            "id": identifier("rule", flow_key), "path": path,
            "vars": sorted({node_id(facts, key) for key in required} | {source_id, sink_id} |
                           set(path["alternatives"]["nodes"])),
            "status": "unresolved", "target_state": target,
            "preconditions": {"kind": "And", "operands": [],
                              "unresolved_reason": "interrupt invocation conditions require resolution"},
            "mutation_hint": [{"operator": "DeliverIrq", "var": source_id, "handler": interrupt["handler"]}],
            "validation": {"result": "unknown", "interrupt_registration": interrupt,
                           "kernel_reachability_proven": False, "runtime_execution": False},
            "runtime_export": {"reason": "runtime format cannot encode interrupt delivery"},
        }
        contracts = CallContracts(assumptions)
        symbolic = None
        try:
            witness = flow["_witness"]
            symbolic = SymbolicPath(facts, [expression for key in witness
                                           for expression in graph.nodes[key]["expressions"]], contracts)
            memory = MemoryTarget(symbolic, sink) if facts.expression(sink["operand"])["type"].get("kind") == "pointer" else None
            target_value = memory.value if memory else symbolic.resolve(sink["operand"])
            conditions = symbolic.conditions(sink["expression"], sink["operand"])
            formula = z3.simplify(z3.And(*conditions))
            if symbolic.environment_in(target_value):
                raise Unresolved("interrupt sink operand requires unresolved kernel state")
            solver = z3.Solver()
            solver.set(timeout=5000)
            solver.add(formula, *contracts.scoped_constraints(symbolic))
            reachable = solver.check()
            if reachable == z3.unsat and not symbolic.unknown_integer_semantics:
                diagnostics.append({"source": source_id, "sink": sink_id, "result": "unsat",
                                    "reason": "interrupt path constraints are inconsistent"})
                continue
            if reachable != z3.sat:
                raise Unresolved("interrupt path constraints are undecidable or depend on unknown arithmetic semantics")
            source_dependencies = dependency_closure(facts, symbolic.source_values)
            resolved_variables = {node_id(facts, key) for key in symbolic.visited | source_dependencies}
            if memory:
                targets = memory.candidates()
            else:
                values = candidate_values(symbolic, sink)
                values.append(solver.model().eval(target_value, model_completion=True).as_long())
                targets = [(str(value), Quantity(value, {"kind": "Const", "value": value})) for value in sorted(set(values))]
            for target_key, candidate in targets:
                solver.push()
                solver.add(target_value == candidate.value)
                decision = solver.check()
                if decision == z3.unknown:
                    timed_out = {**base, "id": identifier("rule", flow_key + "|" + target_key),
                        "vars": sorted(set(base["vars"]) | resolved_variables),
                        "path": {**path, "witness": [graph.nodes[k] for k in witness]},
                        "validation": {**base["validation"], "reason": "interrupt target solver timeout"},
                        "target_state": {"src": node_id(facts, sink["operand"]),
                            "dst": node_id(facts, sink["operand"]), "head": "head_offset" if memory else "head_bound",
                            "predicate": {"kind": "Eq", "left": memory.term if memory else
                                {"kind": "Ref", "node": node_id(facts, sink["operand"])}, "right": candidate.term}}}
                    record_assumptions(timed_out, contracts, symbolic)
                    rules.append(timed_out)
                if decision == z3.sat:
                    model = solver.model()
                    relations = make_semantic_edges(symbolic, sink_id) + [target]
                    if memory:
                        relations.append(memory.edge(sink_id))
                    assignments = {node_id(facts, key): model.eval(symbol, model_completion=True).as_long()
                                   for key, symbol in symbolic.source_values.items()
                                   if z3.is_true(model.eval(z3.Or(*symbolic.source_activations[key]),
                                                            model_completion=True))}
                    rule = {**base, "id": identifier("rule", flow_key + "|" + target_key),
                            "vars": sorted(set(base["vars"]) | resolved_variables),
                            "status": "conditional", "path": {**path, "edges": relations,
                                "witness": [graph.nodes[key] for key in witness]},
                            "preconditions": {"kind": "And", "operands": [edge["predicate"]
                                for edge in relations if edge["head"] == "head_guard"] +
                                (memory.requirements if memory else [])},
                            "target_state": {"src": node_id(facts, sink["operand"]),
                                "dst": node_id(facts, sink["operand"]), "head": "head_offset" if memory else "head_bound",
                                "predicate": {"kind": "Eq", "left": memory.term if memory else {"kind": "Ref", "node": node_id(facts, sink["operand"])},
                                    "right": candidate.term}},
                            "mutation_hint": [{"operator": "SetValue", "var": key, "value": assigned}
                                for key, assigned in sorted(assignments.items())] + base["mutation_hint"],
                            "validation": {**base["validation"], "result": "sat",
                                           "source_assignments": assignments}}
                    proof_assignments = {key: model.eval(symbol, model_completion=True).as_long()
                                         for key, symbol in symbolic.source_values.items()
                                         if node_id(facts, key) in assignments}
                    target_formula = z3.And(formula, target_value == candidate.value)
                    rule["validation"]["assumption_proof"] = prove_under_assumptions(
                        symbolic, target_formula, proof_assignments)
                    rule["validation"]["assumption_constraints_proven"] = rule["validation"]["assumption_proof"]["proven"]
                    record_assumptions(rule, contracts, symbolic, model, target_formula,
                                       memory.requirements if memory else ())
                    if memory:
                        rule["validation"]["memory_access"] = memory.validation(model)
                    assumption_nodes = {node_id(facts, key): node_record(facts, key)
                                        for key in symbolic.visited | source_dependencies}
                    apply_path_assumptions(rule, {**nodes, **assumption_nodes,
                        source_id: {"id": source_id, "kind": "source", "source": interrupt,
                                    "location": interrupt["location"]},
                        sink_id: {"id": sink_id, "kind": "sink", **sink}}, contracts.policy_record())
                    rules.append(rule)
                    for relation in relations:
                        edges[json.dumps(relation, sort_keys=True)] = relation
                solver.pop()
            for key in symbolic.visited | source_dependencies:
                nodes[node_id(facts, key)] = node_record(facts, key)
        except (Unresolved, RecursionError, z3.Z3Exception) as error:
            base["validation"]["reason"] = str(error)
            record_assumptions(base, contracts, symbolic)
            if symbolic is not None:
                for key in symbolic.visited:
                    nodes[node_id(facts, key)] = node_record(facts, key)
            rules.append(base)
            diagnostics.append({"source": source_id, "sink": sink_id, "reason": str(error)})
        edges.update(relationships)
    return nodes, edges, rules, diagnostics, len(graph.flows)
