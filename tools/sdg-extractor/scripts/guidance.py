"""Mutation guidance derived from path predicates regardless of solve success."""

from collections import defaultdict, deque
from copy import deepcopy
import hashlib
import json


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def references(value):
    if isinstance(value, dict):
        if isinstance(value.get("node"), str):
            yield value["node"]
        for child in value.values():
            yield from references(child)
    elif isinstance(value, list):
        for child in value:
            yield from references(child)


def operands(term):
    if "left" in term:
        return [term["left"], term["right"]]
    if "value" in term and isinstance(term["value"], dict):
        return [term["value"]]
    return [child for _, child in sorted((item.get("position", index), item)
            for index, item in enumerate(term.get("operands", [])))]


def domain(node):
    width = node.get("source", {}).get("size_bytes", 0) * 8
    if not 0 < width <= 64:
        return None
    signed = node.get("type", {}).get("signedness") == "Signed"
    return width, -(1 << (width-1)) if signed else 0, (1 << (width-int(signed))) - 1


def mutate_value(hint, node, current, random=None):
    """Execute a basic value operation, checking width and boundary arithmetic.

    Alternatives are selected by the consumer, never applied as a conjunction.
    Dynamic boundaries need the consumer to evaluate their recorded expression.
    """
    bounds = domain(node)
    if bounds is None:
        return None
    width, minimum, maximum = bounds
    mask = (1 << width) - 1
    if not isinstance(current, int) or not 0 <= current <= mask:
        return None
    base = current - (1 << width) if minimum < 0 and current >= 1 << (width-1) else current
    operator = hint["operator"]
    if operator == "SetBoundary":
        boundary = hint["boundary"]
        if not isinstance(boundary, int):
            return None
        value = boundary + {"Above": 1, "At": 0, "Below": -1}[hint["side"]]
    elif operator in {"Inc", "Dec"}:
        value = base + hint.get("delta", 1) * (1 if operator == "Inc" else -1)
    elif operator == "SetValue":
        value = hint["value"]
    elif operator in {"SetBits", "ClearBits", "FlipBit"}:
        bitmask = 1 << hint["bit"] if operator == "FlipBit" else hint["mask"]
        if bitmask < 0 or bitmask > mask:
            return None
        return current ^ bitmask if operator == "FlipBit" else (
            current | bitmask if operator == "SetBits" else current & ~bitmask)
    elif operator == "SampleRange":
        low, high = hint["min"], hint["max"]
        if not minimum <= low <= high <= maximum:
            return None
        value = random.randint(low, high) if random is not None else low
    elif operator == "Keep":
        return current
    else:
        return None
    return value & mask if minimum <= value <= maximum else None


class Derivation:
    def __init__(self, rule, nodes, edges):
        self.rule, self.nodes = rule, nodes
        self.edges = {key: edges[key] for key in rule["path"]["edges"] if key in edges}
        self.definitions = defaultdict(dict)
        self.next = defaultdict(list)
        for key, edge in self.edges.items():
            self.next[edge["src"]].append((edge["dst"], key))
            predicate = edge.get("predicate", {})
            left, right = predicate.get("left", {}), predicate.get("right", {})
            if (predicate.get("kind") == "Eq" and left.get("node") == edge["dst"] and
                    edge["head"] in {"head_dataflow", "head_bound", "head_call"} and right):
                self.definitions[edge["dst"]][digest(right)] = right

    def expand(self, term, active=frozenset()):
        if "node" not in term:
            return term
        key = term["node"]
        if key in active or self.nodes.get(key, {}).get("kind") == "source":
            return term
        choices = self.definitions.get(key, {})
        if len(choices) == 1:
            value = next(iter(choices.values()))
            if value.get("node") != key:
                return self.expand(value, active | {key})
        return term

    def scalar(self, term, active=frozenset()):
        """Resolve identity and value-preserving casts; other transforms stay explicit."""
        if "node" in term:
            key = term["node"]
            if key in active:
                return term
            if self.nodes.get(key, {}).get("kind") == "source":
                return {"kind": "Ref", "node": key}
            expanded = self.expand(term)
            if expanded == term:
                return term
            return self.scalar(expanded, active | {key})
        kind, children = term.get("kind"), operands(term)
        if kind == "Const":
            return term
        if kind in {"Cast", "ParenthesisExpr", "CStyleCast", "ImplicitConversion",
                    "IntegralConversion", "VariableAccess", "StmtExpr"} and len(children) == 1:
            value = self.scalar(children[0], active)
            if kind in {"ParenthesisExpr", "StmtExpr"}:
                return value
            if value.get("kind") == "Const":
                return value
            node = self.nodes.get(value.get("node"), {})
            source_type, target_type = node.get("type", {}), term.get("type", {})
            source_width = source_type.get("width", node.get("source", {}).get("size_bytes", 0)*8)
            target_width = target_type.get("width", source_width)
            a, b = source_type.get("signedness"), target_type.get("signedness")
            if value.get("node") and source_width and (a == b and target_width >= source_width or
                    a == "Unsigned" and b == "Signed" and target_width > source_width):
                return value
        if kind == "=" and len(children) == 2:
            return self.scalar(children[1], active)
        return term

    def predicates(self, term, branch=True, active=frozenset()):
        if "node" in term:
            key = term["node"]
            if key in active:
                return
            expanded = self.expand(term)
            if expanded != term:
                yield from self.predicates(expanded, branch, active | {key})
            return
        kind = term.get("kind")
        children = operands(term)
        if kind in {"Not", "!"}:
            child = term.get("operand", children[0] if children else {})
            yield from self.predicates(child, not branch, active)
        elif kind in {"And", "Or", "&&", "||"}:
            # These are candidate alternatives; the full boolean predicate stays
            # in rule.preconditions for coordinated checking by the consumer.
            for child in term.get("operands", []):
                yield from self.predicates(child, branch, active)
        elif kind in {"Cast", "CStyleCast", "ParenthesisExpr", "IntegralConversion"} and children:
            yield from self.predicates(children[0], branch, active)
        elif kind in {"Ne", "Eq", "!=", "=="} and len(children) == 2:
            left, right = children
            if right.get("kind") == "Const" and right.get("value") == 0:
                expanded = self.expand(left)
                if expanded != left and expanded.get("kind") in {
                        "<", ">", "<=", ">=", "==", "!=", "&", "!", "&&", "||"}:
                    yield from self.predicates(expanded, branch == (kind in {"Ne", "!="}), active)
                    return
            yield kind, children, branch
        elif kind in {"<", ">", "<=", ">=", "Lt", "Le", "Gt", "Ge", "&"}:
            yield kind, children, branch

    def evidence(self, source):
        sink = self.rule["path"]["sink"]
        pending, previous = deque([source]), {source: None}
        while pending:
            current = pending.popleft()
            if current == sink:
                result = []
                while previous[current] is not None:
                    current, edge = previous[current]
                    result.append(edge)
                return {"kind": "dependency_edges", "edges": list(reversed(result))}
            for target, edge in self.next.get(current, []):
                if target not in previous:
                    previous[target] = current, edge
                    pending.append(target)
        # Native CodeQL witnesses can cross calls and stores not yet represented
        # by an exact scalar expression; retain that witness as evidence.
        path = self.rule["path"]
        from path_evidence import connected
        if source == path["source"] and self.rule.get("path_evidence") and connected(self.rule, self.nodes, self.edges):
            return {"kind": "native_dependency", "path_evidence_sha256": digest(self.rule["path_evidence"])}
        return None

    def hints(self):
        hints = {}
        connected = {}
        for key in self.rule["vars"]:
            node = self.nodes.get(key, {})
            if node.get("kind") == "source":
                evidence = self.evidence(key)
                if evidence:
                    connected[key] = evidence

        def add(source, operator, parameters, target, role, reason):
            if source not in connected:
                return
            node = self.nodes[source]
            bounds = domain(node)
            if bounds is None:
                return
            hint = {"operator": operator, "var": source, **parameters,
                    "derivation": {"method": "source predicates", "guarantee": "guidance",
                        "role": role, "constraint": target, "reason": reason,
                        "evidence": connected[source], "source_width": bounds[0],
                        "signedness": node.get("type", {}).get("signedness", "Unknown")}}
            if operator in {"SetBoundary", "SetValue", "SetBits", "ClearBits"} and mutate_value(hint, node, 0) is None:
                return
            hints[digest(hint)] = hint

        contexts = [(self.rule.get("preconditions", {}), True, "precondition")]
        contexts.extend(({"kind": "Ref", "node": c["condition"]}, c["branch"], "precondition")
                        for c in self.rule["path"].get("control_conditions", []))
        # The target remains an exploration objective, not a solver-selected
        # source value. No enhancement fields are consulted here.
        contexts.append((self.rule["target_state"]["predicate"], True, "target"))
        for predicate, required, role in contexts:
            for kind, children, branch in self.predicates(predicate, required):
                if len(children) != 2:
                    continue
                first, second = [self.scalar(child) for child in children]
                comparison = {"Lt": "<", "Le": "<=", "Gt": ">", "Ge": ">=", "Eq": "==", "Ne": "!="}.get(kind, kind)
                if first.get("kind") == "Const":
                    first, second = second, first
                    comparison = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}.get(comparison, comparison)
                source, boundary = first.get("node"), second.get("value") if second.get("kind") == "Const" else None
                if source not in connected:
                    continue
                if comparison == "&" and isinstance(boundary, int):
                    add(source, "SetBits" if branch else "ClearBits", {"mask": boundary},
                        predicate, role, "bit-mask guard in the selected branch")
                    continue
                if not branch:
                    comparison = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}.get(comparison)
                if comparison is None:
                    continue
                if isinstance(boundary, int):
                    sides = {"<": ["Below"], "<=": ["At", "Below"], ">": ["Above"],
                             ">=": ["At", "Above"], "==": ["At"], "!=": ["Below", "Above"]}.get(comparison, [])
                    for side in sides:
                        add(source, "SetBoundary", {"boundary": boundary, "side": side},
                            predicate, role, "boundary follows the typed comparison and branch direction")
                elif comparison in {"<", "<=", ">", ">="}:
                    add(source, "Dec" if comparison in {"<", "<="} else "Inc", {"delta": 1},
                        predicate, role, "move toward a comparison against a dynamic kernel boundary")
        for source, evidence in connected.items():
            node = self.nodes[source]
            if node.get("source", {}).get("kind") == "Irq":
                handler = node["source"].get("handler")
                if handler:
                    hint = {"operator": "DeliverIrq", "var": source, "handler": handler,
                            "derivation": {"method": "registered interrupt", "guarantee": "guidance",
                                           "role": "delivery", "evidence": evidence}}
                    hints[digest(hint)] = hint
                continue
            if any(h["var"] == source for h in hints.values()):
                continue
            if domain(node) is None:
                continue
            # A native dependency establishes relevance, not monotonicity. Explore
            # both directions while retaining all guards and lossy computations.
            for operator in ("Inc", "Dec"):
                add(source, operator, {"delta": 1}, self.rule["target_state"]["predicate"],
                    "exploration", "explore the dependent source; no sink monotonicity is asserted")
        return [hints[key] for key in sorted(hints)]


def derive_hints(rule, nodes, edges):
    return Derivation(rule, nodes, edges).hints()


def attach_guidance(rule, nodes, edges):
    from path_evidence import connected
    if "enhancement" not in rule:
        rule["enhancement"] = {"backend": "z3", "result": rule.get("validation", {}).get("result", "unknown"),
                               "mutation_hint": deepcopy(rule.get("mutation_hint", [])),
                               "proof_status": rule.get("status", "unresolved")}
    rule["mutation_hint"] = derive_hints(rule, nodes, edges)
    rule["publication"] = {"threshold": "basic", "eligible": bool(rule["mutation_hint"]) and connected(rule, nodes, edges),
                           "basis": "connected source-to-sink path and derived source mutation",
                           "hint_semantics": "choose an alternative and recheck full path predicates",
                           "solver": "z3", "solver_success_required": False, "exact_target_guaranteed": False}
    return rule


def guidance_errors(rule, nodes, edges):
    errors = []
    expected = derive_hints(rule, nodes, edges)
    if not expected:
        errors.append("no source mutation guidance with dependency evidence")
    if expected != rule.get("mutation_hint"):
        errors.append("mutation guidance does not match its graph derivation")
    if rule.get("publication", {}).get("solver_success_required") is not False:
        errors.append("basic publication must not require successful solving")
    return errors


def write_hint_index(path, rules, export_directory=None):
    import csv
    from convert_to_sdg import filename
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["rule", "validation_status", "operator",
            "source", "role", "parameters", "export"])
        writer.writeheader()
        for rule in rules:
            for hint in rule.get("mutation_hint", []):
                writer.writerow({"rule": rule["id"], "validation_status": rule["status"],
                    "operator": hint["operator"], "source": hint["var"],
                    "role": hint.get("derivation", {}).get("role", "enhancement"),
                    "parameters": json.dumps({k:v for k,v in hint.items() if k not in {"operator", "var", "derivation"}}),
                    "export": str(export_directory / filename(rule["id"])) if export_directory else ""})
