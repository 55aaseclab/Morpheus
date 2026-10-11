from dataclasses import dataclass

import z3

from graph import node_id, reference
from semantics import Unresolved, children, integer, truth


@dataclass(frozen=True)
class Quantity:
    value: object
    term: dict

    def add(self, other):
        return Quantity(z3.simplify(self.value + other.value),
                        {"kind": "Add", "left": self.term, "right": other.term})

    def multiply(self, other):
        return Quantity(z3.simplify(self.value * other.value),
                        {"kind": "Mul", "left": self.term, "right": other.term})


def amount(value):
    return Quantity(z3.IntVal(value), {"kind": "Const", "value": value})


class PointerResolver:
    def __init__(self, symbolic):
        self.symbolic = symbolic
        self.facts = symbolic.facts
        self.active = set()
        self.context = ()

    def dependency(self, parent, child):
        self.symbolic.visited.update((parent, child))
        if parent != child:
            self.symbolic.evaluations[parent].add((child, self.context))

    def quantity(self, key, parent):
        self.dependency(parent, key)
        value = self.symbolic.resolve(key, self.context)
        if z3.is_bool(value):
            value = z3.If(value, z3.IntVal(1), z3.IntVal(0))
        else:
            signed = self.facts.expression(key)["type"].get("signedness") == "Signed"
            value = z3.BV2Int(value, is_signed=signed)
        return Quantity(z3.simplify(value), reference(self.facts, key))

    def shifted(self, view, offset):
        return {**view, "offset": view["offset"].add(offset)}

    def alternatives(self, key, definitions, explicit=None):
        if key in self.facts.cyclic_definitions:
            raise Unresolved("pointer recurrence requires an iteration context")
        ordering = self.facts.definition_order[key]
        remaining, ordered = set(definitions), []
        while remaining:
            available = sorted(definition for definition in remaining if not any(
                earlier in remaining and later == definition for earlier, later in ordering))
            if not available:
                raise Unresolved("pointer definition ordering is cyclic")
            ordered.append(available[0])
            remaining.remove(available[0])
        choices = []
        previous_context = self.context
        try:
            for definition in ordered:
                requirements = tuple(sorted(set(previous_context) | set((explicit or {}).get(definition, ())) | {
                    (guard["condition"], guard["branch"])
                    for guard in self.facts.guards[self.facts.unwrap(definition)]}))
                for condition, _ in requirements:
                    self.dependency(key, condition)
                gate = z3.simplify(z3.And(*[self.symbolic.guard_value(condition) == branch
                                          for condition, branch in requirements]))
                if z3.is_false(gate):
                    continue
                self.context = requirements
                self.dependency(key, definition)
                choices.append((definition, requirements, gate, self.pointer(definition)))
        finally:
            self.context = previous_context
        if not choices:
            raise Unresolved("pointer alternatives have no feasible region")
        for index, (definition, _, gate, view) in enumerate(choices):
            for earlier, _, earlier_gate, earlier_view in choices[:index]:
                if (earlier, definition) in ordering:
                    continue
                overlap = z3.Solver()
                overlap.set(timeout=1000)
                overlap.add(*self.symbolic.domain_constraints, gate, earlier_gate)
                if overlap.check() != z3.unsat and (
                        view["root"] != earlier_view["root"] or
                        not z3.is_true(z3.simplify(view["offset"].value == earlier_view["offset"].value))):
                    raise Unresolved("pointer alternatives overlap without execution order")
        selected = [z3.simplify(z3.And(choice[2], *[z3.Not(later[2]) for later in choices[index + 1:]]))
                    for index, choice in enumerate(choices)]
        gate_terms = [{"kind": "And", "operands": [
            {"kind": "Ne" if branch else "Eq", "left": reference(self.facts, condition),
             "right": {"kind": "Const", "value": 0}} for condition, branch in choice[1]]}
            for choice in choices]
        selected_terms = [{"kind": "And", "operands": [gate_terms[index], *[
            {"kind": "Not", "operand": later} for later in gate_terms[index + 1:]]]}
            for index in range(len(choices))]
        self.symbolic.semantic_constraints[key].append(z3.Or(*selected))
        self.symbolic.merges[key] = [{"definition": definition, "conditions": requirements}
                                    for definition, requirements, _, _ in choices]
        self.symbolic.value_dependencies[key] = [(choice[0], gate) for choice, gate in zip(choices, selected)]
        for _, requirements, _, _ in choices:
            for condition, _ in requirements:
                self.symbolic.value_dependencies[key].append((condition, z3.BoolVal(True)))
        offset, address = choices[0][3]["offset"], choices[0][3]["address"]
        for choice, gate, term in zip(choices[1:], selected[1:], selected_terms[1:]):
            view = choice[3]
            offset = Quantity(z3.If(gate, view["offset"].value, offset.value),
                              {"kind": "Conditional", "condition": term,
                               "then": view["offset"].term, "else": offset.term})
            address = {"kind": "Conditional", "condition": term, "then": view["address"], "else": address}
        bounds, requirements = [], []
        for choice, gate, term in zip(choices, selected, selected_terms):
            view = choice[3]
            bounds.extend({**bound, "activation": z3.And(gate, bound.get("activation", z3.BoolVal(True)))}
                          for bound in view["bounds"])
            requirements.extend({"kind": "Or", "operands": [{"kind": "Not", "operand": term}, requirement]}
                                for requirement in view["requirements"])
        return {"root": key, "address": address, "offset": offset, "bounds": bounds,
                "storage": "guarded", "requirements": requirements,
                "alternatives": [{"root": choice[3]["root"], "activation": gate,
                                  "storage": choice[3]["storage"]} for choice, gate in zip(choices, selected)]}

    def pointer(self, key):
        if key in self.active:
            raise Unresolved("pointer recurrence requires an iteration context")
        self.active.add(key)
        self.symbolic.visited.add(key)
        try:
            return self.pointer_value(key)
        finally:
            self.active.remove(key)

    def pointer_value(self, key):
        expression = self.facts.expression(key)
        operands = children(expression)
        if expression["type"].get("kind") == "array":
            return self.storage(key)
        if expression["type"].get("kind") == "pointer" and integer(expression.get("constant")) == 0:
            return {"root": key, "address": {"kind": "Const", "value": 0}, "offset": amount(0),
                    "bounds": [{"origin": key, "start": amount(0), "size": amount(0)}],
                    "storage": "null", "requirements": []}
        if "/conversion:" in key and 0 in operands:
            child = self.facts.expression(operands[0])
            self.dependency(key, operands[0])
            if child["type"].get("kind") == "array":
                view = self.storage(operands[0])
                if child["class"] == "ArrayExpr":
                    view = {**view, "bounds": view["bounds"] + [{"origin": operands[0],
                        "start": view["offset"], "size": amount(child["type"]["width"] // 8)}]}
                return view
            if child["type"].get("kind") != "pointer":
                raise Unresolved("integer-derived pointer has no resolved storage provenance")
            return self.pointer(operands[0])
        if expression["class"] == "AddressOfExpr":
            self.dependency(key, operands[0])
            return self.storage(operands[0])
        if expression["class"] == "StmtExpr" and 0 in operands:
            self.dependency(key, operands[0])
            self.symbolic.resolutions[key] = operands[0]
            return self.pointer(operands[0])
        if expression.get("operator") in {"+", "-"} and set(operands) >= {0, 1}:
            first, second = operands[0], operands[1]
            if self.facts.expression(first)["type"].get("kind") != "pointer":
                if expression["operator"] != "+":
                    raise Unresolved("pointer subtraction has no pointer base")
                first, second = second, first
            pointer_type = self.facts.expression(first)["type"]
            if pointer_type.get("kind") != "pointer" or self.facts.expression(second)["type"].get("kind") == "pointer":
                raise Unresolved("pointer calculation has incompatible operands")
            self.dependency(key, first)
            stride = max(1, pointer_type.get("stride", 1))
            offset = self.quantity(second, key).multiply(amount(stride if expression["operator"] == "+" else -stride))
            return self.shifted(self.pointer(first), offset)
        if expression.get("operator") == "=":
            self.dependency(key, operands[1])
            self.symbolic.resolutions[key] = operands[1]
            return self.pointer(operands[1])
        written = self.symbolic.written_definition(key)
        if written is not None:
            self.dependency(key, written)
            return self.pointer(written)
        definitions = self.facts.definitions[key]
        declaration = expression.get("declaration")
        if not definitions and declaration in self.symbolic.bindings:
            definitions = {self.symbolic.bindings[declaration]}
        if len(definitions) == 1:
            definition = next(iter(definitions))
            self.dependency(key, definition)
            self.symbolic.resolutions[key] = definition
            return self.pointer(definition)
        if len(definitions) > 1:
            return self.alternatives(key, definitions)
        if expression.get("operator") == "?":
            if not {0, 1, 2} <= operands.keys():
                raise Unresolved("pointer conditional has no complete operand mapping")
            if operands[1] == operands[2]:
                self.dependency(key, operands[0])
                self.symbolic.resolve(operands[0], self.context)
                self.dependency(key, operands[1])
                return self.pointer(operands[1])
            return self.alternatives(key, {operands[1], operands[2]}, {
                operands[1]: ((operands[0], True),), operands[2]: ((operands[0], False),)})
        if expression.get("allocation_size"):
            size = amount(1)
            for argument in expression["allocation_size"]:
                size = size.multiply(self.quantity(argument, key))
            maximum = (1 << expression["type"]["width"]) - 1
            self.symbolic.semantic_constraints[key].extend((size.value >= 0, size.value <= maximum))
            return {"root": key, "address": reference(self.facts, key), "offset": amount(0),
                    "bounds": [{"origin": key, "start": amount(0), "size": size}],
                    "storage": "allocation", "requirements": [
                        {"kind": "InRange", "value": size.term, "min": {"kind": "Const", "value": 0},
                         "max": {"kind": "Const", "value": maximum}},
                        {"kind": "Ne", "left": reference(self.facts, key),
                         "right": {"kind": "Const", "value": 0},
                         "unresolved_reason": "allocation success and live storage must hold at this operation"}]}
        if "Call" in expression["class"] and len(self.facts.calls[key]) == 1:
            call = self.facts.calls[key][0]
            instance = self.facts.invocation(key, call)
            if not instance["returns"]:
                raise Unresolved("pointer call has no extracted return")
            if len(instance["returns"]) > 1:
                view = self.alternatives(key, set(instance["returns"]))
                for alternative in view["alternatives"]:
                    if alternative["storage"] == "automatic" and self.facts.expression(
                            alternative["root"]).get("invocation") == key:
                        raise Unresolved("returned pointer outlives its automatic storage")
                return view
            returned = instance["returns"][0]
            self.dependency(key, returned)
            self.symbolic.resolutions[key] = returned
            view = self.pointer(returned)
            root = self.facts.expression(view["root"])
            if view["storage"] == "automatic" and root.get("invocation") == key:
                raise Unresolved("returned pointer outlives its automatic storage")
            return view
        raise Unresolved("pointer base has no resolved storage provenance")

    def storage(self, key):
        expression = self.facts.expression(key)
        operands = children(expression)
        self.symbolic.visited.add(key)
        if "/conversion:" in key and 0 in operands:
            self.dependency(key, operands[0])
            return self.storage(operands[0])
        if expression["class"] == "VariableAccess" and expression.get("storage"):
            width = expression["type"].get("width")
            if not width or width % 8:
                raise Unresolved("storage size requires a resolved declaration extent")
            size = amount(width // 8)
            return {"root": key, "address": {"kind": "AddressOf", "value": reference(self.facts, key)},
                    "offset": amount(0), "bounds": [{"origin": key, "start": amount(0), "size": size}],
                    "storage": expression["storage"], "requirements": []}
        if expression["class"] in {"PointerFieldAccess", "ValueFieldAccess"}:
            if "field_offset" not in expression or expression.get("bitfield"):
                raise Unresolved("field address requires a resolved byte layout")
            qualifier = operands.get(-1)
            if qualifier is None:
                raise Unresolved("field address has no receiver expression")
            self.dependency(key, qualifier)
            parent = self.pointer(qualifier) if expression["class"] == "PointerFieldAccess" else self.storage(qualifier)
            view = self.shifted(parent, amount(expression["field_offset"]))
            width = expression["type"].get("width")
            if not width or width % 8:
                raise Unresolved("field extent requires a resolved object layout")
            return {**view, "bounds": parent["bounds"] + [
                {"origin": key, "start": view["offset"], "size": amount(width // 8)}]}
        if expression["class"] == "ArrayExpr":
            self.dependency(key, operands[0])
            stride = expression["type"].get("width", 0) // 8
            if not stride:
                raise Unresolved("array element size is unresolved")
            return self.shifted(self.pointer(operands[0]), self.quantity(operands[1], key).multiply(amount(stride)))
        if expression["class"] == "PointerDereferenceExpr":
            self.dependency(key, operands[0])
            return self.pointer(operands[0])
        raise Unresolved("lvalue has no resolved storage provenance")


class MemoryTarget:
    def __init__(self, symbolic, sink):
        self.symbolic = symbolic
        self.facts = symbolic.facts
        self.sink = sink
        resolver = PointerResolver(symbolic)
        self.view = resolver.pointer(sink["operand"]) if "argument" in sink else resolver.storage(sink["expression"])
        if "width_expression" in sink:
            self.width = resolver.quantity(sink["width_expression"], sink["expression"])
        elif "width_bytes" in sink:
            self.width = amount(sink["width_bytes"])
        else:
            raise Unresolved("memory operation has no resolved access width")
        self.value = self.view["offset"].value
        self.term = self.view["offset"].term
        self.head = "head_offset"
        self.requirements = self.view["requirements"]
        if self.requirements:
            self.requirements = self.requirements + [{
                "kind": "ValidMemoryAccess", "base": self.view["address"],
                "offset": self.term, "width": self.width.term,
                "unresolved_reason": "selected storage must be live and cover this access"}]
        symbolic.visited.add(sink["operand"])
        if sink["operand"] != sink["expression"]:
            symbolic.evaluations[sink["operand"]].update(
                (key, requirements) for key, requirements in symbolic.evaluations[sink["expression"]]
                if key != sink["operand"])

    def candidates(self):
        candidates = {"zero": amount(0), "one": amount(1)}
        for index, bound in enumerate(self.view["bounds"]):
            end = bound["start"].add(bound["size"])
            last = end.add(self.width.multiply(amount(-1)))
            for label, boundary in (("start", bound["start"]), ("last", last), ("end", end)):
                for delta in (-1, 0, 1):
                    candidates[f"{index}:{label}:{delta}"] = boundary.add(amount(delta))
        unique = {}
        for key, candidate in candidates.items():
            unique.setdefault(candidate.value.sexpr(), (key, candidate))
        return unique.values()

    def edge(self, sink_id):
        address = reference(self.facts, self.sink["operand"]) if "argument" in self.sink else {
            "kind": "AddressOf", "value": reference(self.facts, self.sink["expression"])}
        return {"src": node_id(self.facts, self.view["root"]), "dst": sink_id, "head": "head_offset",
                "predicate": {"kind": "Eq", "left": address, "right": {
                    "kind": "Add", "left": self.view["address"], "right": self.term}, "unit": "bytes"},
                "location": self.sink["location"]}

    def validation(self, model):
        offset = model.eval(self.value, model_completion=True).as_long()
        width = model.eval(self.width.value, model_completion=True).as_long()
        bounds = [{"origin": node_id(self.facts, bound["origin"]),
                   "start_bytes": model.eval(bound["start"].value, model_completion=True).as_long(),
                   "size_bytes": model.eval(bound["size"].value, model_completion=True).as_long()}
                  for bound in self.view["bounds"] if z3.is_true(model.eval(
                      bound.get("activation", z3.BoolVal(True)), model_completion=True))]
        return {"base": node_id(self.facts, self.view["root"]), "offset_bytes": offset,
                "width_bytes": width, "bounds": bounds, "storage": self.view["storage"],
                "within_declared_bounds": (width >= 0 and all(
                    bound["start_bytes"] <= offset and offset + width <= bound["start_bytes"] + bound["size_bytes"]
                    for bound in bounds)) if bounds else None, "requirements": self.requirements}
