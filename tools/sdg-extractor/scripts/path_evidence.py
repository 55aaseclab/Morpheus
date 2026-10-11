"""Reconstruct source-to-sink connectivity from extracted dependency records."""

from collections import defaultdict, deque
import csv
import hashlib
import json


def identity(prefix, value):
    return prefix + ":" + hashlib.sha256(value.encode()).hexdigest()[:24]


def route(start, target, adjacency, allowed):
    if start not in allowed or target not in allowed:
        return None
    pending, previous = deque([start]), {start: None}
    while pending:
        key = pending.popleft()
        if key == target:
            path = []
            while key is not None:
                path.append(key)
                key = previous[key]
            return list(reversed(path))
        for next_key in sorted(adjacency.get(key, [])):
            if next_key in allowed and next_key not in previous:
                previous[next_key] = key
                pending.append(next_key)
    return None


class NativePaths:
    def __init__(self, paths_csv, nodes):
        self.nodes = nodes
        self.groups = defaultdict(lambda: defaultdict(list))
        self.flow_steps, self.control_steps = set(), set()
        sinks = defaultdict(list)
        for key, node in nodes.items():
            if node.get("kind") == "sink":
                sinks[node.get("flow_operand")].append(key)
        with paths_csv.open() as stream:
            for row in csv.DictReader(stream):
                if row["section"] not in {"flow", "control_dependency", "flow_step", "control_call", "control_sink"}:
                    continue
                value = json.loads(row["value"])
                if row["section"] == "flow_step":
                    self.flow_steps.add((identity("internal", "flow:" + value["src"]),
                                         identity("internal", "flow:" + value["dst"])))
                    continue
                if row["section"] in {"control_call", "control_sink"}:
                    if row["section"] == "control_call":
                        call = "call:" + value["call"] + ":" + value["callee"]
                        links = [("function:" + value["caller"], call), (call, "function:" + value["callee"])]
                    else:
                        links = [("function:" + value["function"], "sink:" + value["sink"])]
                    self.control_steps.update((identity("internal", "control:" + a),
                                               identity("internal", "control:" + b)) for a, b in links)
                    continue
                if row["section"] == "flow":
                    keys = [("data", value["source_expr"], sink) for sink in sinks[value["sink_expr"]]]
                    endpoints = [value["sink"]]
                else:
                    keys = [("control", value["source_expr"], identity("sink", value["sink_key"]))]
                    endpoints = value["endpoints"]
                for key in keys:
                    self.groups[key][value["source"]].append({"section": row["section"], "key": row["key"],
                        "source": identity("internal", "flow:" + value["source"]),
                        "endpoints": [identity("internal", "flow:" + e) for e in endpoints],
                        "guard": identity("internal", value["guard"]) if "guard" in value else None,
                        "branch": value.get("branch")})

    def evidence(self, rule):
        path = rule["path"]
        allowed = set(path.get("alternatives", {}).get("nodes", []))
        adjacency = defaultdict(set)
        for step in path.get("alternatives", {}).get("steps", []):
            adjacency[step["src"]].add(step["dst"])
        kind = path.get("dependency", "data")
        expression = path.get("origin_source_expression", path.get("source_expression"))
        required_steps = {(a, b) for a in adjacency for b in adjacency[a]}
        if kind == "interrupt":
            source = self.nodes.get(path["source"], {}).get("source", {})
            registration = rule.get("validation", {}).get("interrupt_registration", {})
            if not source.get("handler") or source.get("handler") != registration.get("handler"):
                return None
            entry_step = (identity("internal", "control:" + expression),
                          identity("internal", "control:function:" + source.get("function", "")))
            if not required_steps <= self.control_steps | {entry_step}:
                return None
            starts = [k for k in allowed if self.nodes[k].get("control_id") == expression]
            targets = [k for k in allowed if self.nodes[k].get("control_id", "").startswith("sink:") and
                       identity("sink", self.nodes[k]["control_id"][5:]) == path["sink"]]
            for start in sorted(starts):
                for target in sorted(targets):
                    witness = route(start, target, adjacency, allowed)
                    if witness:
                        return {"kind": "native_dependency", "dependency": kind, "source": path["source"],
                            "sink": path["sink"], "source_expression": expression,
                            "registration": registration, "routes": [{"nodes": witness}]}
            return None
        if not required_steps <= self.flow_steps:
            return None
        groups = self.groups.get((kind, expression, path["sink"]), {})
        for native_source, records in sorted(groups.items()):
            routes = []
            for record in records:
                for endpoint in record["endpoints"]:
                    witness = route(record["source"], endpoint, adjacency, allowed)
                    if witness is None:
                        break
                    routes.append({"nodes": witness, "query_section": record["section"],
                        "query_key": record["key"], "guard": record["guard"], "branch": record["branch"]})
                else:
                    continue
                break
            else:
                if routes:
                    return {"kind": "native_dependency", "dependency": kind, "source": path["source"],
                            "sink": path["sink"], "source_expression": expression, "routes": routes}
        return None


def connected(rule, nodes, edges):
    path = rule["path"]
    evidence = rule.get("path_evidence")
    if evidence:
        if evidence.get("source") != path["source"] or evidence.get("sink") != path["sink"]:
            return False
        allowed = set(path.get("alternatives", {}).get("nodes", []))
        steps = {(s["src"], s["dst"]) for s in path.get("alternatives", {}).get("steps", [])}
        routes = evidence.get("routes", [])
        return bool(routes) and all(r.get("nodes") and set(r["nodes"]) <= allowed and
            set(zip(r["nodes"], r["nodes"][1:])) <= steps for r in routes)
    adjacency = defaultdict(set)
    for key in path.get("edges", []):
        if key in edges:
            adjacency[edges[key]["src"]].add(edges[key]["dst"])
    return route(path["source"], path["sink"], adjacency, set(rule["vars"])) is not None
