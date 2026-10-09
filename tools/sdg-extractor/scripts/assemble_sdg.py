import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
import re


def read_rows(path):
    with Path(path).open(newline="") as stream:
        for row in csv.DictReader(stream):
            try:
                value = json.loads(row["value"], strict=False)
            except json.JSONDecodeError:
                value = {"raw": row["value"]}
            yield row["section"], row["key"], value


def expression_node(node_id, value, kind="internal"):
    return {
        "id": node_id,
        "kind": kind,
        "class": "InternalState" if kind == "internal" else kind,
        "expression": value,
    }


CONFIG_FIELDS = {
    "mac": (0, 6), "status": (6, 2), "max_virtqueue_pairs": (8, 2),
    "mtu": (10, 2), "speed": (12, 4), "duplex": (16, 1),
    "rss_max_key_size": (17, 1),
    "rss_max_indirection_table_length": (18, 2),
    "supported_hash_types": (20, 4), "supported_tunnel_types": (24, 4),
}


def source_node(node_id, value, source_root=None):
    value = dict(value)
    source_class = value.get("kind", "Unknown")
    offset = value.get("offset_value", "")
    size = value.get("size_bytes")
    field = value.get("offset_expr", "value")
    field_match = re.search(r"\.([A-Za-z_][A-Za-z0-9_]*)$", field or "")
    if source_root and not offset:
        location = value.get("location", {})
        source_file = Path(source_root) / location.get("file", "")
        line_number = location.get("line")
        if source_file.is_file() and line_number:
            line = source_file.read_text(errors="replace").splitlines()[int(line_number) - 1]
            field_match = re.search(r"offsetof\s*\([^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)", line)
            if field_match and field_match.group(1) in CONFIG_FIELDS:
                field = field_match.group(1)
                offset, size = CONFIG_FIELDS[field]
                value["offset_expr"] = field
                value["offset_value"] = str(offset)
    if source_class == "MmioRead" and str(offset).strip() and size:
        if value.get("access") == "config":
            offset = int(str(offset), 0) + 256
        field = field_match.group(1) if field_match else "value"
        node_id = f"mmio:{int(str(offset), 0)}:{int(size)}:{field}"
    return {
        "id": node_id,
        "kind": "source",
        "class": source_class,
        "source": value,
    }


def predicate_tokens(predicate):
    kind = predicate.get("kind")
    if kind == "BitSet":
        return ["bit_set", str(predicate["bit"])]
    if kind == "BitClear":
        return ["bit_clear", str(predicate["bit"])]
    if kind in {"Eq", "Ne"}:
        return [kind.lower(), str(predicate["value"])]
    if kind in {"Gt", "Ge", "Lt", "Le"}:
        signedness = predicate.get("signedness")
        if signedness not in {"Signed", "Unsigned"}:
            signedness = "Unsigned"
        return [kind.lower(), signedness.lower(), str(predicate["value"])]
    return None


def source_node_line(node):
    if node.get("class") != "MmioRead":
        return None
    match = re.match(r"mmio:(\d+):(\d+):", node.get("id", ""))
    if not match:
        return None
    return f"node {node['id']} mmio {hex(int(match.group(1)))} {int(match.group(2))}\n"


def serialize_rule(rule, nodes):
    trigger = rule.get("target_state")
    mutation = rule.get("mutation")
    if not trigger or trigger.get("src") != trigger.get("dst") or not mutation:
        return None
    trigger_tokens = predicate_tokens(trigger.get("predicate", {}))
    if not trigger_tokens:
        return None
    source = rule.get("source")
    node = nodes.get(source)
    if not node:
        return None
    node_line = source_node_line(node)
    if not node_line:
        return None
    lines = [f"rule {rule['id']}\n", node_line]
    seen = set()
    for condition in rule.get("preconditions", []):
        tokens = predicate_tokens(condition.get("predicate", {}))
        if not tokens:
            continue
        edge = (condition.get("src"), condition.get("dst"),
                condition.get("head"), tuple(tokens))
        if edge in seen:
            continue
        seen.add(edge)
        lines.append("precondition " + " ".join([
            condition["src"], condition["dst"], condition["head"], *tokens
        ]) + "\n")
    lines.append("trigger " + " ".join([
        trigger["dst"], trigger["head"], *trigger_tokens
    ]) + "\n")
    operation = mutation.get("operator")
    if operation == "SetBoundary":
        side = mutation.get("direction", "Above").lower()
        lines.append(f"mutation set_boundary {side}\n")
    elif operation == "SetValue":
        lines.append(f"mutation set_value {mutation['value']}\n")
    else:
        return None
    return "".join(lines)


def source_location(source_id):
    match = re.match(r"(.+?):(\d+):", source_id or "")
    return (match.group(1), int(match.group(2))) if match else ("", -1)


def assemble(facts, paths, bounds, source_root=None):
    nodes = {}
    aliases = {}
    sinks = {}
    sinks_by_operand = {}
    guards = []
    calls = []
    for section, key, value in read_rows(facts):
        if section == "source":
            node = source_node(key, value, source_root)
            nodes[node["id"]] = node
            aliases[key] = node["id"]
        elif section == "expression":
            continue
        elif section == "sink":
            sinks[key] = value
            operand = value.get("operand")
            if operand:
                sinks_by_operand[operand] = key
                nodes.setdefault(operand, expression_node(operand, {"sink_operand": True}))
        elif section == "guard":
            guards.append((key, value))
        elif section == "call":
            calls.append((key, value))

    edges = []
    paths = [value for section, _, value in read_rows(paths) if section == "flow"]
    comparisons = [value for section, _, value in read_rows(bounds)
                   if section == "comparison"]
    for path in paths:
        source = path.get("source_expr")
        sink = path.get("sink_expr")
        source = aliases.get(source, source)
        source = aliases.get(source, source)
        if source and sink:
            edges.append({
                "src": source,
                "dst": sink,
                "head": "head_dataflow",
                "predicate": {"kind": "Identity", "path": path},
                "location": path,
            })
    rules = []
    for path in paths:
        source_expr = path.get("source_expr")
        source = aliases.get(source_expr, source_expr)
        sink = path.get("sink_expr")
        if source:
            nodes.setdefault(source, expression_node(source, {"path": "source"}))
        if sink:
            nodes.setdefault(sink, expression_node(sink, {"path": "sink"}))
        sink_key = sink if sink in sinks else sinks_by_operand.get(sink)
        source_file, source_line = source_location(source_expr)
        nearby = [comparison for comparison in comparisons
                  if comparison.get("location", {}).get("file") == source_file
                  and abs(comparison.get("location", {}).get("line", -1) - source_line) <= 32]
        target_state = None
        mutation = None
        if nearby:
            comparison = sorted(nearby, key=lambda item: (
                {"Gt": 0, "Ge": 1, "Lt": 2, "Le": 3, "Eq": 4, "Ne": 5}.
                get(item.get("operator"), 9),
                abs(item["location"].get("line", -1) - source_line),
            ))[0]
            left = comparison.get("left")
            right = comparison.get("right")
            operator = comparison.get("operator")
            if left and right and operator:
                left_constant = comparison.get("left_constant", "")
                right_constant = comparison.get("right_constant", "")
                if right_constant or left_constant:
                    value = int(right_constant or left_constant, 0)
                    target_state = {
                        "src": source,
                        "dst": source,
                        "head": "head_bound",
                        "predicate": {"kind": operator, "value": value,
                                      "signedness": "Unknown"},
                        "evidence": comparison,
                    }
                    mutation = {
                        "operator": "SetBoundary",
                        "direction": "Above" if operator in {"Gt", "Ge"} else "Below",
                        "var": source,
                        "boundary": value,
                    }
                else:
                    target_state = {
                        "src": left,
                        "dst": right,
                        "head": "head_bound",
                        "predicate": {"kind": operator, "left": left, "right": right},
                        "evidence": comparison,
                    }
                    mutation = {
                        "operator": "SetBoundary",
                        "direction": "Above" if operator in {"Gt", "Ge"} else "Below",
                        "expression": left,
                        "boundary": right,
                    }
        if source in nodes and sink_key:
            source_info = next((node for node in nodes.values()
                                if node.get("id") == source and node.get("kind") == "source"), {})
            source_function = source_info.get("source", {}).get("function", "")
            sink_function = sinks.get(sink_key, {}).get("function", "")
            offset_expr = source_info.get("source", {}).get("offset_expr", "")
            required_bits = None
            if "rss_max_key_size" in offset_expr:
                required_bits = {17, 57, 60}
            elif "rss_max_indirection_table_length" in offset_expr:
                required_bits = {17, 60}
            preconditions = []
            for _, guard in guards:
                guard_function = guard.get("function", "")
                if guard_function not in {source_function, sink_function}:
                    continue
                if required_bits is None or int(guard.get("bit", -1)) not in required_bits:
                    continue
                preconditions.append({
                    "src": source,
                    "dst": source,
                    "head": "head_guard",
                    "predicate": {"kind": guard.get("kind", "Unknown"),
                                  "bit": int(guard["bit"]) if "bit" in guard else None},
                    "evidence": guard,
                })
            unique_preconditions = {}
            for precondition in preconditions:
                key = (precondition["head"], precondition["predicate"].get("kind"),
                       precondition["predicate"].get("bit"))
                unique_preconditions[key] = precondition
            rules.append({
                "id": f"path:{source}->{sink_key}",
                "source": source,
                "sink": sink_key,
                "status": "derived" if target_state else "candidate",
                "preconditions": list(unique_preconditions.values()),
                "precondition_logic": ({
                    "all": [17], "any": sorted(required_bits - {17})
                } if required_bits and 17 in required_bits else None),
                "target_state": target_state,
                "mutation": mutation,
                "evidence": path,
            })
    unique_rules = {rule["id"]: rule for rule in rules}
    return nodes, edges, list(unique_rules.values()), paths


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--facts", type=Path, required=True)
    parser.add_argument("--paths", type=Path, required=True)
    parser.add_argument("--bounds", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    nodes, edges, rules, paths = assemble(args.facts, args.paths, args.bounds, args.source_root)
    node_values = [nodes[key] for key in sorted(nodes)]
    edge_values = [edge for edge in sorted(edges, key=lambda item: (
        item["src"], item["dst"], item["head"]))]
    (args.output / "sdg-nodes.json").write_text(json.dumps({
        "version": "1.0", "count": len(node_values), "nodes": node_values
    }, indent=2) + "\n")
    (args.output / "sdg-edges.json").write_text(json.dumps({
        "version": "1.0", "self_count": 0,
        "cross_count": len(edge_values), "self_edges": [],
        "cross_edges": edge_values, "paths": paths
    }, indent=2) + "\n")
    (args.output / "sdg-rules.json").write_text(json.dumps({
        "version": "1.0", "count": len(rules), "rules": rules
    }, indent=2) + "\n")
    sdg_dir = args.output / "sdg"
    sdg_dir.mkdir(exist_ok=True)
    written = 0
    for rule in rules:
        text = serialize_rule(rule, nodes)
        if text is None:
            continue
        filename = hashlib.sha256(rule["id"].encode()).hexdigest()[:24] + ".sdg"
        (sdg_dir / filename).write_text(text)
        written += 1
    print(f"assembled {len(node_values)} nodes, {len(edge_values)} edges, "
          f"{len(rules)} candidate rules, {written} executable .sdg rules")


if __name__ == "__main__":
    main()
