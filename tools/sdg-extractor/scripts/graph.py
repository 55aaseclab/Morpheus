import json

from semantics import children, identifier, integer, source_expression_references


def node_id(facts, key):
    if key in facts.node_ids:
        return facts.node_ids[key]
    if key in facts.interrupts:
        identity = identifier("irq", key)
    elif key in facts.sources:
        binding = facts.binding(key)
        if binding["kind"] == "MmioRead" and "offset" in binding:
            identity = f"mmio:{binding['offset']}:{binding['size_bytes']}:{identifier('read', key).split(':')[1]}"
        else:
            identity = identifier("source", key)
    else:
        identity = identifier("internal", key)
    facts.node_ids[key] = identity
    return identity


def node_record(facts, key):
    expression = facts.expression(key)
    result = {
        "id": node_id(facts, key),
        "kind": "source" if key in facts.sources else "internal",
        "name": expression["text"],
        "type": expression["type"],
        "location": expression["location"],
        "function": expression["function"],
        "expression_id": key,
    }
    if key in facts.sources:
        result["source"] = facts.binding(key)
    if "invocation" in expression:
        result["invocation"] = expression["invocation"]
        result["origin_expression"] = expression["origin_expression"]
    return result


def reference(facts, key):
    return {"kind": "Ref", "node": node_id(facts, key)}


def truth_predicate(facts, key, branch=True):
    return {"kind": "Ne" if branch else "Eq", "left": reference(facts, key),
            "right": {"kind": "Const", "value": 0}}


def expression_predicate(facts, key):
    expression = facts.expression(key)
    operands = children(expression)
    value = integer(expression.get("constant"))
    if value is not None:
        return {"kind": "Const", "value": value, "type": expression["type"]}
    if key in facts.sources:
        return reference(facts, key)
    term = {
        "kind": expression.get("operator") or expression["class"],
        "type": expression["type"],
        "operands": [{"position": position, **reference(facts, operand)}
                     for position, operand in sorted(operands.items())],
    }
    if "Call" in expression["class"]:
        term["callees"] = [call["callee"] for call in facts.calls[key]]
        term["callsite"] = key
    return term


def sink_edge(facts, key, sink):
    return {
        "src": node_id(facts, sink["operand"]), "dst": identifier("sink", key),
        "head": "head_call" if "argument" in sink else "head_offset",
        "predicate": {"kind": "Eq", "operand": sink["operation"],
                      "value": reference(facts, sink["operand"])},
        "location": sink["location"],
    }


def expression_edges(facts, keys):
    edges = {}
    for key in sorted(keys):
        expression = facts.expression(key)
        if key in facts.sources:
            continue
        operands = children(expression)
        definitions = facts.definitions[key]
        dependencies = set()
        predicate = None
        if definitions:
            dependencies = set(definitions)
            alternatives = [{"kind": "Eq", "left": reference(facts, key),
                             "right": {"kind": "Cast", "value": reference(facts, definition),
                                       "type": expression["type"]}}
                            for definition in sorted(definitions)]
            predicate = alternatives[0] if len(alternatives) == 1 else {
                "kind": "Or", "operands": alternatives}
        elif expression.get("operator") or "/conversion:" in key or expression["class"] in {
                "StmtExpr", "ArrayExpr", "PointerDereferenceExpr"} or "Call" in expression["class"]:
            dependencies = set(operands.values())
            predicate = {"kind": "Eq", "left": reference(facts, key),
                         "right": expression_predicate(facts, key)}
        elif integer(expression.get("constant")) is not None:
            dependencies = {key}
            predicate = {"kind": "Eq", "left": reference(facts, key),
                         "right": expression_predicate(facts, key)}
        for dependency in sorted(dependencies):
            head = "head_dataflow"
            if "Call" in expression["class"]:
                head = "head_call"
            elif expression.get("operator") in {"==", "!=", "<", "<=", ">", ">="}:
                head = "head_bound"
            elif expression["class"] in {"ArrayExpr", "PointerDereferenceExpr"}:
                head = "head_offset"
            edge = {"src": node_id(facts, dependency), "dst": node_id(facts, key),
                    "head": head, "predicate": predicate,
                    "location": expression["location"]}
            if len(definitions) > 1:
                edge["unresolved_reason"] = "reaching definition selection requires path context"
            edges[json.dumps(edge, sort_keys=True)] = edge
        for guard in facts.guards[key]:
            edge = {"src": node_id(facts, guard["condition"]), "dst": node_id(facts, key),
                    "head": "head_guard", "predicate": truth_predicate(facts, guard["condition"], guard["branch"]),
                    "location": facts.expression(guard["condition"])["location"]}
            edges[json.dumps(edge, sort_keys=True)] = edge
    return edges


def edge_index(edges):
    indexed = {}
    for key, edge in edges.items():
        indexed.setdefault(edge["dst"], {})[key] = edge
    return indexed


def selected_edges(facts, keys, indexed):
    result = {}
    for key in keys:
        result.update(indexed.get(node_id(facts, key), {}))
    return result


def dependency_closure(facts, expressions):
    pending, found = list(expressions), set()
    while pending:
        key = pending.pop()
        if key in found or key not in facts.expressions:
            continue
        found.add(key)
        if key in facts.sources:
            pending.extend(source_expression_references(facts.sources[key]))
        pending.extend(children(facts.expression(key)).values())
        pending.extend(facts.definitions[key])
        for write in facts.write_definitions[key]:
            pending.append(write["site"])
            pending.extend(call["call"] for call in write["calls"])
        pending.extend(guard["condition"] for guard in facts.guards[key])
        for stored in facts.stores[key]:
            pending.extend((stored["store"], stored["src"]))
        for exclusion in facts.exit_guards[key]:
            pending.extend(guard["condition"] for guard in exclusion["conditions"])
    return found


def preserve_graph(facts, graph):
    nodes = {node_id(facts, key): node_record(facts, key) for key in facts.expressions}
    edges = expression_edges(facts, set(facts.expressions))
    for key, sink in facts.sections["sink"].items():
        identity = identifier("sink", key)
        nodes[identity] = {"id": identity, "kind": "sink", **sink}
        edge = sink_edge(facts, key, sink)
        edges[json.dumps(edge, sort_keys=True)] = edge
    for key, node in graph.nodes.items():
        identity = graph.node_ids[key]
        nodes[identity] = {"id": identity, "kind": "internal", "name": node["text"],
                           "location": node["location"], "flow_id": key,
                           "expressions": [node_id(facts, expression) for expression in node["expressions"]]}
    for key, interrupt in facts.interrupts.items():
        identity = node_id(facts, key)
        nodes[identity] = {"id": identity, "kind": "source", "name": interrupt["handler"],
                           "source": interrupt, "function": interrupt["function"],
                           "location": interrupt["location"]}
    return nodes, edges


def path_record(facts, graph, flow, sink_key):
    node_keys, steps = flow_subgraph(graph, flow)
    return {
        "source": node_id(facts, flow["source_expr"]), "source_expression": flow["source_expr"],
        "sink": identifier("sink", sink_key),
        "dependency": flow.get("dependency", "data"),
        "control_conditions": [{"condition": node_id(facts, guard["condition"]), "branch": guard["branch"]}
                               for guard in flow.get("control_guards", [])],
        "alternatives": {
            "nodes": [graph.node_ids[key] for key in sorted(node_keys)],
            "steps": [graph.step_records[previous, following] for previous, following in steps],
        },
    }


def flow_subgraph(graph, flow):
    nodes, steps = set(), set()
    for endpoint in flow.get("guard_endpoints", [flow["sink"]]):
        partial_nodes, partial_steps = graph.subgraph(flow["source"], endpoint)
        nodes.update(partial_nodes)
        steps.update(partial_steps)
    return nodes, sorted(steps)


def path_variables(facts, graph, flow, sink_key):
    keys, _ = flow_subgraph(graph, flow)
    expressions = dependency_closure(facts, [expression for key in keys
                                           for expression in graph.nodes[key]["expressions"]] +
                                          [guard["condition"] for guard in flow.get("control_guards", [])])
    return {node_id(facts, key) for key in expressions} | {identifier("sink", sink_key)} | {
        graph.node_ids[key] for key in keys}


def unresolved_rule(facts, graph, flow_key, flow, sink_key, sink, reason, indexed):
    path = path_record(facts, graph, flow, sink_key)
    graph_keys, _ = flow_subgraph(graph, flow)
    expression_keys = dependency_closure(facts, [sink["operand"], sink["expression"]] + [
        expression for key in graph_keys for expression in graph.nodes[key]["expressions"]] +
        [guard["condition"] for guard in flow.get("control_guards", [])])
    edges = list(selected_edges(facts, expression_keys, indexed).values())
    target = sink_edge(facts, sink_key, sink)
    edges.append(target)
    path["edges"] = edges
    return {
        "id": identifier("rule", flow_key + "|" + sink_key + "|unresolved"),
        "status": "unresolved", "path": path,
        "vars": sorted({node_id(facts, key) for key in expression_keys} | {path["sink"]} |
                       set(path["alternatives"]["nodes"])),
        "preconditions": {"kind": "And", "operands": [
            truth_predicate(facts, guard["condition"], guard["branch"])
            for key in (flow["source_expr"], sink["expression"]) for guard in facts.guards[key]],
            "unresolved_reason": "intermediate branch and invocation conditions require resolution"},
        "target_state": target, "mutation_hint": [],
        "validation": {"result": "unknown", "reason": reason,
                       "kernel_reachability_proven": False, "runtime_execution": False},
        "runtime_export": {"reason": "path semantics remain unresolved"},
    }
