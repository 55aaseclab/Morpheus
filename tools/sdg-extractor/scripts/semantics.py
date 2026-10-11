from collections import defaultdict, deque
from functools import lru_cache
import csv
import hashlib
import json

import z3


class Unresolved(ValueError):
    pass


def identifier(prefix, value):
    return prefix + ":" + hashlib.sha256(value.encode()).hexdigest()[:24]


def load_facts(path):
    sections = defaultdict(dict)
    with open(path, newline="") as stream:
        for row_number, row in enumerate(csv.DictReader(stream), 2):
            value = json.loads(row["value"])
            section, key = row["section"], row["key"]
            if key in sections[section] and sections[section][key] != value:
                raise ValueError(f"conflicting {section} identity at {path}:{row_number}: {key}")
            sections[section][key] = value
    return sections


def integer(text):
    if isinstance(text, int):
        return text
    try:
        return int(text, 10)
    except (ValueError, TypeError):
        try:
            return int(text, 0)
        except (ValueError, TypeError):
            return None


def children(expression):
    return {entry["position"]: entry["id"] for entry in expression.get("children", [])}


def source_expression_references(source):
    references = {source[field] for field in ("address", "index", "offset_expr") if field in source}
    references.update(index["expression"] for index in source.get("indices", []))
    for binding in source.get("bindings", []) + source.get("mapping_bindings", []):
        references.update(binding[field] for field in (
            "base", "mapping", "allocation", "completion", "buffer", "size", "direction",
            "mapping_offset", "pool", "page", "sync_offset", "observation") if field in binding)
    for context in source.get("access_context", []):
        references.update(context[field] for field in ("write", "address", "value"))
        references.update(context["predecessors"])
    return references


def validate_expression_references(sections):
    expressions = sections["expression"]
    references = set(sections["source"]) | set(sections["definition_cycle"])
    for expression in expressions.values():
        references.update(children(expression).values())
        references.update(expression.get("allocation_size", []))
    for section, fields in {
        "guard": ("condition", "target"),
        "sink": ("expression", "operand", "flow_operand"),
        "definition": ("src", "dst"),
        "definition_order": ("use", "earlier", "later"),
        "store_use": ("store", "src", "dst"),
        "local_store": ("store", "src", "dst", "receiver"),
        "return": ("expression",),
        "call": ("call",),
        "write_definition": ("site", "dst"),
        "output_store": ("store", "src"),
    }.items():
        for record in sections[section].values():
            references.update(record[field] for field in fields)
    for exclusion in sections["exit_guard"].values():
        references.add(exclusion["target"])
        references.update(guard["condition"] for guard in exclusion["conditions"])
    for sink in sections["sink"].values():
        if "width_expression" in sink:
            references.add(sink["width_expression"])
        references.update(index["expression"] for index in sink.get("access_indices", []))
    for source in sections["source"].values():
        references.update(source_expression_references(source))
    for write in sections["write_definition"].values():
        references.update(call["call"] for call in write["calls"])
    for store in sections["store_use"].values():
        for field in ("write_indices", "read_indices"):
            references.update(index["expression"] for index in store.get(field, []))
    missing = sorted(references - expressions.keys())
    if missing:
        raise ValueError(f"extraction has {len(missing)} undeclared expression references: " + "; ".join(missing[:5]))


def truth(value):
    return value if z3.is_bool(value) else value != 0


def constant(value):
    simplified = z3.simplify(value)
    if z3.is_bv_value(simplified):
        return simplified.as_long()
    if z3.is_true(simplified):
        return 1
    if z3.is_false(simplified):
        return 0
    return None


def variables_in(value):
    pending, visited, variables = [value], set(), set()
    while pending:
        current = pending.pop()
        identity = current.get_id()
        if identity in visited:
            continue
        visited.add(identity)
        if z3.is_const(current) and current.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            variables.add(identity)
        pending.extend(current.children())
    return variables


class Facts:
    def __init__(self, sections, target=None):
        validate_expression_references(sections)
        self.sections = sections
        self.signed_overflow = (target or {}).get("signed_overflow", "Unknown")
        self.node_ids = {}
        self.expressions = sections["expression"]
        self.sources = sections["source"]
        self.interrupts = sections["irq"]
        if target is not None:
            for expression in self.expressions.values():
                for property_name in ("byte_order", "storage_byte_order"):
                    if expression["type"].get(property_name) == "Unknown":
                        expression["type"][property_name] = target["byte_order"]
            for source in self.sources.values():
                if source.get("byte_order") == "Unknown":
                    source["byte_order"] = target["byte_order"]
        self.definitions = defaultdict(set)
        self.definition_order = defaultdict(set)
        self.cyclic_definitions = set(sections["definition_cycle"])
        self.stores = defaultdict(list)
        self.guards = defaultdict(list)
        self.exit_guards = defaultdict(list)
        self.calls = defaultdict(list)
        self.write_definitions = defaultdict(list)
        self.output_stores = defaultdict(list)
        self.returns = defaultdict(list)
        self.parents = defaultdict(set)
        self.function_expressions = defaultdict(list)
        self.instances = {}
        mappings = sorted({binding["mapping"] for source in self.sources.values()
                           for binding in source.get("bindings", []) if "mapping" in binding})
        self.mapping_slots = {mapping: index for index, mapping in enumerate(mappings)}
        self.allocation_origins = {binding["allocation"] for source in self.sources.values()
                                   for binding in source.get("bindings", []) if "allocation" in binding}
        self.page_views = {binding["buffer"] for source in self.sources.values()
                           for binding in source.get("bindings", []) if "page" in binding}
        for definition in sections["definition"].values():
            self.definitions[definition["dst"]].add(definition["src"])
        for ordering in sections["definition_order"].values():
            self.definition_order[ordering["use"]].add((ordering["earlier"], ordering["later"]))
        for stored in sections["store_use"].values():
            self.stores[stored["dst"]].append(stored)
        for stored in sections["local_store"].values():
            self.stores[stored["dst"]].append(stored)
        for guard in sections["guard"].values():
            self.guards[guard["target"]].append(guard)
        for guard in sections["exit_guard"].values():
            self.exit_guards[guard["target"]].append(guard)
        for call in sections["call"].values():
            self.calls[call["call"]].append(call)
        for write in sections["write_definition"].values():
            self.write_definitions[write["dst"]].append(write)
        for stored in sections["output_store"].values():
            self.output_stores[stored["function"]].append(stored)
        for returned in sections["return"].values():
            self.returns[returned["function"]].append(returned["expression"])
        for key, expression in self.expressions.items():
            self.function_expressions[expression["function"]].append(key)
            for child in children(expression).values():
                self.parents[child].add(key)

    def invocation(self, call_key, call):
        identity = call_key, call["callee"]
        if identity in self.instances:
            return self.instances[identity]
        parent = self.expression(call_key)
        ancestors = parent.get("invocation_functions", [])
        if call["callee"] in ancestors:
            raise Unresolved("recursive invocation requires a recursive summary")
        suffix = "@" + identifier("call", call_key)
        aliases = {key: key + suffix for key in self.function_expressions[call["callee"]]}
        declarations = {parameter["declaration"]: parameter["declaration"] + suffix
                        for parameter in call["parameters"]}
        for key in aliases:
            expression = self.expressions[key]
            declaration = expression.get("declaration", "")
            if expression["class"] == "VariableAccess" and expression.get("storage") != "static" and declaration.startswith(call["callee"] + "/"):
                declarations[declaration] = declaration + suffix

        def scoped(value):
            if isinstance(value, str):
                return aliases.get(value, declarations.get(value, value))
            if isinstance(value, list):
                return [scoped(item) for item in value]
            if isinstance(value, tuple):
                return tuple(scoped(item) for item in value)
            if isinstance(value, dict):
                return {key: scoped(item) for key, item in value.items()}
            return value

        for original, contextual in aliases.items():
            expression = scoped(self.expressions[original])
            expression.update(origin_expression=original, invocation=call_key,
                              invocation_functions=ancestors + [call["callee"]])
            self.expressions[contextual] = expression
            self.definitions[contextual] = {aliases.get(key, key) for key in self.definitions[original]}
            self.definition_order[contextual] = {scoped(pair) for pair in self.definition_order[original]}
            if original in self.cyclic_definitions:
                self.cyclic_definitions.add(contextual)
            self.guards[contextual] = scoped(self.guards[original])
            self.exit_guards[contextual] = scoped(self.exit_guards[original])
            self.stores[contextual] = scoped(self.stores[original])
            self.calls[contextual] = scoped(self.calls[original])
            self.write_definitions[contextual] = scoped(self.write_definitions[original])
            if original in self.sources:
                self.sources[contextual] = {**scoped(self.sources[original]), "origin_expression": original,
                                            "invocation": call_key}
                for binding in self.sources[contextual].get("bindings", []):
                    if "mapping" in binding and binding["mapping"] not in self.mapping_slots:
                        self.mapping_slots[binding["mapping"]] = len(self.mapping_slots)
                    if "allocation" in binding:
                        self.allocation_origins.add(binding["allocation"])
                    if "page" in binding:
                        self.page_views.add(binding["buffer"])
            for child in children(expression).values():
                self.parents[child].add(contextual)
        arguments = children(parent)
        parameters = {declarations[parameter["declaration"]]: arguments[parameter["index"]]
                      for parameter in call["parameters"] if parameter["index"] in arguments}
        for contextual in aliases.values():
            expression = self.expressions[contextual]
            if expression["class"] == "ParameterValue" and expression.get("declaration") in parameters:
                self.definitions[contextual].add(parameters[expression["declaration"]])
        instance = {"expressions": aliases, "declarations": declarations,
                    "returns": [aliases[key] for key in self.returns[call["callee"]]]}
        self.instances[identity] = instance
        return instance

    def origin(self, key):
        return self.expressions.get(key, {}).get("origin_expression", key)

    def expression(self, key):
        if key not in self.expressions:
            raise Unresolved(f"missing expression: {key}")
        return self.expressions[key]

    def unwrap(self, key):
        visited = set()
        while key not in visited:
            visited.add(key)
            expression = self.expression(key)
            operands = children(expression)
            if "/conversion:" in key and set(operands) == {0}:
                key = operands[0]
            else:
                break
        return key

    def enclosing_calls(self, key):
        pending, visited, calls = [key], set(), set()
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            expression = self.expressions.get(current, {})
            if "Call" in expression.get("class", ""):
                calls.add(current)
            pending.extend(self.parents[current])
        return calls

    def relative_address(self, key, visited=None):
        visited = set() if visited is None else visited
        if key in visited:
            return key, None
        visited = visited | {key}
        expression = self.expression(key)
        operands = children(expression)
        if key in self.allocation_origins or key in self.page_views:
            return key, 0
        if expression["type"].get("kind") == "array" and expression.get("class") == "VariableAccess":
            return key, 0
        if expression.get("class") == "AddressOfExpr" and 0 in operands:
            target = self.expression(self.unwrap(operands[0]))
            if target.get("class") == "VariableAccess":
                return key, 0
        if "/conversion:" in key and 0 in operands:
            return self.relative_address(operands[0], visited)
        if expression.get("operator") in {"+", "-"} and set(operands) >= {0, 1}:
            left = self.expression(operands[0])
            right = self.expression(operands[1])
            if left["type"].get("kind") == "pointer":
                root, base = self.relative_address(operands[0], visited)
                numeric = integer(right.get("constant"))
                stride = max(1, left.get("type", {}).get("stride", 1))
                offset = base + numeric * stride * (1 if expression["operator"] == "+" else -1) if base is not None and numeric is not None else None
                return root, offset
            if right["type"].get("kind") == "pointer" and expression["operator"] == "+":
                root, base = self.relative_address(operands[1], visited)
                numeric = integer(left.get("constant"))
                stride = max(1, right.get("type", {}).get("stride", 1))
                return root, base + numeric * stride if base is not None and numeric is not None else None
            return key, None
        definitions = self.definitions.get(key, set())
        if len(definitions) == 1:
            return self.relative_address(next(iter(definitions)), visited)
        if not definitions and expression.get("class") in {"VariableAccess", "ParameterValue", "PointerFieldAccess", "ValueFieldAccess", "FunctionCall"}:
            return key, 0
        return key, None

    def address_offset(self, key):
        root, offset = self.relative_address(key)
        expression = self.expression(root)
        if root in self.allocation_origins or root in self.page_views or expression["type"].get("kind") == "array":
            return offset
        if expression.get("class") == "AddressOfExpr":
            return offset
        return None

    def binding(self, key):
        source = dict(self.sources[key])
        if source.get("access") == "config":
            base = integer(source.get("config_base"))
            relative = integer(source.get("relative_offset"))
            if base is not None and relative is not None:
                source["offset"] = base + relative
        elif source["kind"] == "MmioRead" and "address" in source:
            root, offset = self.relative_address(source["address"])
            source["relative_base"] = root
            source["offset_expr"] = source["address"]
            if offset is not None:
                source["relative_offset"] = offset
            mappings = {binding["mapping"] for binding in source.get("mapping_bindings", [])
                        if self.relative_address(binding["base"])[0] == root}
            if len(mappings) == 1:
                source["mapping"] = next(iter(mappings))
                if offset is not None:
                    source["offset"] = offset
            else:
                source["placement_unresolved"] = "MMIO address root has no unique proven mapping base"
        if source["kind"] in {"DmaReadStreaming", "DmaReadCoherent"}:
            source.pop("offset", None)
            source["offset_expr"] = {"address": source["address"], "field_offset": source["field_offset"],
                                     "indices": source.get("indices", [])}
            placements = {(binding.get("mapping"), binding["buffer"], binding["size"], binding.get("mapping_offset"))
                          for binding in source["bindings"]}
            if len(placements) == 1 and "mapping" in source["bindings"][0]:
                binding = source["bindings"][0]
                read_offset = self.address_offset(source["address"])
                mapped_offset = self.address_offset(binding["buffer"])
                region_offset = integer(self.expression(binding["mapping_offset"]).get("constant")) if "mapping_offset" in binding else 0
                indices = source.get("indices", [{"expression": source["index"], "stride": source["stride"]}] if "index" in source else [])
                offsets = [(integer(self.expression(index["expression"]).get("constant")), index["stride"]) for index in indices]
                if read_offset is not None and mapped_offset is not None and region_offset is not None and all(index is not None for index, _ in offsets):
                    source["offset"] = read_offset - mapped_offset - region_offset + source["field_offset"] + sum(index * stride for index, stride in offsets)
                source["region"] = identifier("mapping", binding["mapping"])
                slot = self.mapping_slots[binding["mapping"]]
                if source["kind"] == "DmaReadStreaming" and slot < 256:
                    source["slot"] = slot
            source["placement_unresolved"] = "mapping lifetime and runtime region require matching"
        return source


class FlowGraph:
    def __init__(self, sections, namespace="flow"):
        self.nodes = sections["flow_node"]
        self.flows = sections["flow"]
        self.next = defaultdict(set)
        self.previous = defaultdict(set)
        self.node_ids = {key: identifier("internal", namespace + ":" + key) for key in self.nodes}
        self.step_records = {}
        for step in sections["flow_step"].values():
            self.next[step["src"]].add(step["dst"])
            self.previous[step["dst"]].add(step["src"])
            self.step_records[step["src"], step["dst"]] = {
                "src": self.node_ids[step["src"]], "dst": self.node_ids[step["dst"]]}
        self.walk_tree = lru_cache(maxsize=64)(self.walk_tree)
        self.subgraph = lru_cache(maxsize=128)(self.subgraph)

    def walk_tree(self, source, reverse=False):
        adjacency = self.previous if reverse else self.next
        queue, previous = deque([source]), {source: None}
        while queue:
            current = queue.popleft()
            for successor in sorted(adjacency[current]):
                if successor not in previous:
                    previous[successor] = current
                    queue.append(successor)
        return previous

    def subgraph(self, source, sink):
        nodes = self.walk_tree(source).keys() & self.walk_tree(sink, True).keys()
        if source not in nodes or sink not in nodes:
            raise Unresolved("CodeQL endpoints have no connected dependency graph")
        return nodes, sorted((previous, following) for previous in nodes
                             for following in self.next[previous] if following in nodes)

    def witness(self, source, sink, reverse=False):
        previous = self.walk_tree(sink if reverse else source, reverse)
        current = source if reverse else sink
        if current not in previous:
            raise Unresolved("CodeQL endpoints have no connected witness")
        path = []
        while current is not None:
            path.append(current)
            current = previous[current]
        return path if reverse else list(reversed(path))

    def contexts(self, source, endpoints, facts):
        if not hasattr(self, "context_anchors"):
            self.context_stores = {record["store"] for stores in facts.stores.values() for record in stores}
            self.context_anchors = set()
            for key, node in self.nodes.items():
                for expression in node["expressions"]:
                    if expression in self.context_stores or facts.calls.get(expression) or facts.enclosing_calls(expression):
                        self.context_anchors.add(key)
        anchors, stored = self.context_anchors, self.context_stores
        signatures = set()
        for endpoint in sorted(set(endpoints)):
            nodes, _ = self.subgraph(source, endpoint)
            initial = self.witness(source, endpoint)
            candidates = [initial]
            for anchor in sorted(anchors & nodes):
                prefix, suffix = self.witness(source, anchor), self.witness(anchor, endpoint, reverse=True)
                if set(prefix[:-1]) & set(suffix):
                    continue
                candidates.append(prefix + suffix[1:])
            for path in candidates:
                expressions = [expression for key in path for expression in self.nodes[key]["expressions"]]
                calls = {call for expression in expressions for call in facts.enclosing_calls(expression)}
                signature = tuple(sorted(calls)), tuple(sorted(stored & set(expressions)))
                if signature in signatures:
                    continue
                signatures.add(signature)
                yield path

    def contextual_flows(self, facts):
        for flow_index, (flow_key, flow) in enumerate(sorted(self.flows.items())):
            for index, witness in enumerate(self.contexts(flow["source"], flow.get("guard_endpoints", [flow["sink"]]), facts)):
                context_id = identifier("context", "\n".join(witness))
                yield (flow_key if index == 0 else flow_key + "|" + context_id), {
                    **flow, "context_id": context_id, "_witness": witness,
                    "_base_flow": flow_key, "_flow_index": flow_index}


class SymbolicPath:
    def __init__(self, facts, witness_expressions, contracts=None):
        self.facts = facts
        self.contracts = contracts
        self.witness = [key for key in witness_expressions if key]
        self.cache = {}
        self.active = set()
        self.visited = set()
        self.source_values = {}
        self.environment = {}
        self.assumption_reasons = {}
        self.bindings = {}
        self.ambiguous_bindings = set()
        self.resolutions = {}
        self.builtin_outputs = {}
        self.merges = {}
        self.value_dependencies = defaultdict(list)
        self.dependency_cache = {}
        self.source_requirements = {}
        self.address_symbols = {}
        self.semantic_constraints = defaultdict(list)
        self.unknown_integer_semantics = set()
        self.domain_constraints = []
        self.evaluations = defaultdict(set)
        self.source_activations = defaultdict(list)
        self.state_activations = defaultdict(list)
        self.computing = []
        self.call_sites = set()
        self.conditional_targets = set()
        self.path_guards = []
        self.path_exclusions = []
        self.field_reads = {}
        self.memory_equalities = []
        self.condition_origins = []
        self.conditions_complete = False
        for key, stores in facts.stores.items():
            matching = [stored for stored in stores if stored["store"] in self.witness or stored.get("dominates")]
            if len(matching) == 1:
                self.field_reads[key] = matching[0]
        for key in self.witness:
            for call_key in sorted(facts.enclosing_calls(key)):
                if len(facts.calls[call_key]) != 1:
                    continue
                call = facts.calls[call_key][0]
                arguments = children(facts.expression(call_key))
                for parameter in call["parameters"]:
                    if parameter["index"] in arguments:
                        declaration = parameter["declaration"]
                        argument = arguments[parameter["index"]]
                        if declaration in self.bindings and self.bindings[declaration] != argument:
                            self.bindings.pop(declaration)
                            self.ambiguous_bindings.add(declaration)
                        if declaration not in self.ambiguous_bindings:
                            self.bindings[declaration] = argument
                self.call_sites.add(call_key)
        self.initial_bindings = dict(self.bindings)
        self.initial_field_reads = dict(self.field_reads)
        self.initial_callers = defaultdict(set)
        for call_key in self.call_sites:
            for call in facts.calls[call_key]:
                self.initial_callers[call["callee"]].add(call_key)
        self.queried_callers = set()

    def context_dependencies(self):
        """Inputs consulted before an unresolved result, including absent bindings."""
        declarations = {self.facts.expression(key).get("declaration") for key in self.visited}
        declarations.discard(None)
        return {
            "bindings": {key: self.initial_bindings.get(key) for key in declarations},
            "fields": {key: self.initial_field_reads.get(key) for key in self.visited},
            "callers": {key: self.initial_callers.get(key, set()) for key in self.queried_callers},
        }

    def matches_context_dependencies(self, dependencies):
        return (all(self.initial_bindings.get(key) == value for key, value in dependencies["bindings"].items()) and
                all(self.initial_field_reads.get(key) == value for key, value in dependencies["fields"].items()) and
                all(self.initial_callers.get(key, set()) == value for key, value in dependencies["callers"].items()))

    def fresh(self, key, source=False, reason="value requires kernel state outside the resolved dependency"):
        expression = self.facts.expression(key)
        width = expression.get("type", {}).get("width")
        if not width or width > 64:
            raise Unresolved(f"unsupported value type at {key}")
        value = z3.BitVec(identifier("source" if source else "environment", key), width)
        if source:
            self.source_values[key] = value
        else:
            self.environment[key] = value
            self.assumption_reasons[key] = reason
        if expression["type"].get("name") in {"bool", "_Bool"}:
            self.domain_constraints.append(z3.ULE(value, 1))
        return value

    def cast(self, value, target, origin=None):
        width = target.get("width")
        if not width or width > 64:
            raise Unresolved(f"unsupported cast to {target}")
        if target.get("name") in {"bool", "_Bool"}:
            return z3.If(truth(value), z3.BitVecVal(1, width), z3.BitVecVal(0, width))
        if z3.is_bool(value):
            return z3.If(value, z3.BitVecVal(1, width), z3.BitVecVal(0, width))
        if value.size() > width:
            return z3.Extract(width - 1, 0, value)
        if value.size() < width:
            return (z3.SignExt if (origin or {}).get("signedness") == "Signed" else z3.ZeroExt)(width - value.size(), value)
        return value

    def resolve(self, key, required=None):
        if required is None:
            required = ()
        elif required and isinstance(required[0], str):
            required = (required,)
        if self.computing:
            self.evaluations[self.computing[-1]].add((key, required))
        self.visited.add(key)
        if key in self.cache:
            return self.cache[key]
        if key in self.active:
            raise Unresolved(f"cyclic value dependency: {key}")
        self.active.add(key)
        self.computing.append(key)
        try:
            value = self.compute(key)
            self.cache[key] = value
            return value
        finally:
            self.computing.pop()
            self.active.remove(key)

    def constrain(self, constraint):
        self.semantic_constraints[self.computing[-1]].append(constraint)

    def constrain_signed_arithmetic(self, *constraints):
        if self.facts.signed_overflow == "Wrap":
            return
        for constraint in constraints:
            self.constrain(constraint)
            if self.facts.signed_overflow == "Unknown" and not z3.is_true(z3.simplify(constraint)):
                self.unknown_integer_semantics.add(self.computing[-1])

    def guard_value(self, key):
        controllers = tuple(sorted({(guard["condition"], guard["branch"])
                                    for guard in self.facts.guards[key] if guard["condition"] != key}))
        return truth(self.resolve(key, controllers))

    def written_definition(self, key):
        writes = self.facts.write_definitions[key]
        if not writes:
            return None
        if len(writes) != 1:
            raise Unresolved("call-written value has multiple reaching updates")
        write = writes[0]
        if write["kind"] != "call_write" or len(write["calls"]) != 1:
            raise Unresolved("assembly or indirect write requires an implementation effect")
        invocation = write["calls"][0]
        call_key = invocation["call"]
        if self.facts.expression(call_key).get("callee") in {
                "__builtin_add_overflow", "__builtin_sub_overflow", "__builtin_mul_overflow"}:
            if invocation["argument"] != 2:
                raise Unresolved("overflow builtin writes only its third argument")
            _, destination, _ = self.overflow_builtin(call_key)
            read = self.facts.expression(key)
            stored = self.facts.expression(destination)
            if (read.get("declaration") != stored.get("declaration") or
                    read["type"] != stored["type"]):
                raise Unresolved("overflow builtin output does not match the caller read")
            self.builtin_outputs[key] = call_key
            self.visited.add(call_key)
            self.resolve(call_key)
            self.evaluations[key].add((call_key, ()))
            return None
        if len(self.facts.calls[call_key]) != 1:
            raise Unresolved("output argument requires an unambiguous callee")
        call = self.facts.calls[call_key][0]
        stores = [stored for stored in self.facts.output_stores[call["callee"]]
                  if stored["argument"] == invocation["argument"]]
        if not stores or not (len(stores) == 1 and stores[0]["complete"]) and not all(
                stored.get("closed") for stored in stores):
            raise Unresolved("output argument requires a complete ordered store effect")
        if len(stores) != 1 or not stores[0]["complete"]:
            if any(self.facts.expression(key)["type"].get("width") != stored["width_bytes"] * 8
                   for stored in stores):
                raise Unresolved("output argument store width differs from the caller read")
            instance = self.facts.invocation(call_key, call)
            contextual = {stored["store"]: instance["expressions"][stored["store"]] for stored in stores}
            merged = key + "/output-effect"
            expression = self.facts.expression(key)
            self.facts.expressions[merged] = {**expression, "id": merged, "class": "VariableAccess",
                                             "children": [], "text": "guarded output effect"}
            self.facts.definitions[merged] = set(contextual.values())
            self.facts.definition_order[merged] = {
                (contextual[previous], contextual[stored["store"]]) for stored in stores
                for previous in stored.get("predecessors", []) if previous in contextual}
            self.visited.add(call_key)
            self.evaluations[key].add((call_key, ()))
            self.resolutions[key] = merged
            return merged
        stored = stores[0]
        if self.facts.expression(key)["type"].get("width") != stored["width_bytes"] * 8:
            raise Unresolved("output argument store width differs from the caller read")
        instance = self.facts.invocation(call_key, call)
        definition = instance["expressions"][stored["src"]]
        store = instance["expressions"][stored["store"]]
        self.visited.update((call_key, store))
        self.evaluations[key].update(((call_key, ()), (store, ()), (definition, ())))
        self.resolutions[key] = definition
        return definition

    def overflow_builtin(self, key):
        """Compiler builtin semantics: infinite-precision arithmetic, then a store cast."""
        expression = self.facts.expression(key)
        operands = children(expression)
        output = self.facts.expression(operands[2])
        if output["class"] != "AddressOfExpr":
            raise Unresolved("overflow builtin output requires a known scalar lvalue")
        destination = children(output)[0]
        target = self.facts.expression(destination)
        value_type = target["type"]
        if (target["class"] != "VariableAccess" or not target.get("declaration") or
                value_type.get("kind") != "integer" or
                value_type.get("signedness") not in {"Signed", "Unsigned"} or
                not 0 < value_type.get("width", 0) <= 64):
            raise Unresolved("overflow builtin output needs a typed scalar variable")
        wide = 2 * max(value_type["width"], *(
            self.facts.expression(operands[position])["type"].get("width", 0)
            for position in (0, 1))) + 2
        values = []
        for position in (0, 1):
            child = operands[position]
            child_type = self.facts.expression(child)["type"]
            if child_type.get("signedness") not in {"Signed", "Unsigned"}:
                raise Unresolved("overflow builtin operand signedness is unknown")
            value = self.resolve(child)
            value = self.cast(value, child_type)
            extend = z3.SignExt if child_type["signedness"] == "Signed" else z3.ZeroExt
            values.append(extend(wide - value.size(), value))
        name = expression["callee"]
        if name == "__builtin_add_overflow":
            result = values[0] + values[1]
        elif name == "__builtin_sub_overflow":
            result = values[0] - values[1]
        else:
            result = values[0] * values[1]
        stored = z3.Extract(value_type["width"] - 1, 0, result)
        extend = z3.SignExt if value_type["signedness"] == "Signed" else z3.ZeroExt
        restored = extend(wide - stored.size(), stored)
        return stored, destination, result != restored

    def memory_offset_value(self, fixed, indices):
        value = z3.BitVecVal(fixed, 64)
        for index in indices:
            expression = self.facts.expression(index["expression"])
            value += self.cast(self.resolve(index["expression"]), {"width": 64}, expression["type"]) * index["stride"]
        return value

    def address_value(self, key, required=()):
        self.visited.add(key)
        if self.computing and self.computing[-1] != key:
            self.evaluations[self.computing[-1]].add((key, required))
        expression = self.facts.expression(key)
        operands = children(expression)
        identity = expression.get("declaration") or key
        if "/conversion:" in key and 0 in operands:
            child = self.facts.expression(operands[0])
            if child["type"].get("kind") != "array":
                return self.cast(self.address_value(operands[0], required), expression["type"], child["type"])
            if child.get("class") == "VariableAccess":
                identity = "address:" + child["declaration"]
        if expression.get("operator") in {"+", "-"} and set(operands) >= {0, 1}:
            base = self.address_value(operands[0], required)
            value_type = self.facts.expression(operands[1])["type"]
            offset = self.cast(self.resolve(operands[1], required), {"width": base.size()}, value_type)
            offset *= max(1, self.facts.expression(operands[0])["type"].get("stride", 1))
            return base + offset if expression["operator"] == "+" else base - offset
        definitions = self.facts.definitions[key]
        if len(definitions) == 1:
            definition = next(iter(definitions))
            if definition != key:
                self.resolutions[key] = definition
                return self.address_value(definition, required)
        if identity in self.address_symbols:
            previous, value = self.address_symbols[identity]
            self.resolutions[key] = previous
            self.visited.add(key)
            return value
        if expression["type"].get("kind") != "pointer":
            raise Unresolved("DMA address requires a pointer-valued expression")
        self.visited.add(key)
        value = self.fresh(key, reason="DMA region address requires runtime binding")
        if identity.startswith("address:") or expression["class"] == "AddressOfExpr":
            self.domain_constraints.append(value != 0)
        self.address_symbols[identity] = key, value
        return value

    def dma_requirements(self, key):
        source = self.facts.sources[key]
        unresolved = [requirement for binding in source["bindings"]
                      for requirement in binding.get("unresolved_requirements", [])]
        if unresolved:
            raise Unresolved("DMA provenance requires: " + "; ".join(sorted(set(unresolved))))
        address = self.address_value(source["address"]) + source["field_offset"]
        indices = source.get("indices", [{"expression": source["index"], "stride": source["stride"]}] if "index" in source else [])
        for index in indices:
            expression = self.facts.expression(index["expression"])
            address += self.cast(self.resolve(index["expression"]), {"width": address.size()},
                                 expression["type"]) * index["stride"]
        end = address + source["size_bytes"]
        conditions = []
        bindings = []
        for binding in source["bindings"]:
            requirements = tuple(sorted({(guard["condition"], guard["branch"])
                                         for call in (binding["mapping"], binding["completion"])
                                         for guard in self.facts.guards[call]}))
            gate = z3.And(*[self.guard_value(condition) == branch for condition, branch in requirements])
            base = self.address_value(binding["buffer"], requirements)
            if "mapping_offset" in binding:
                offset_type = self.facts.expression(binding["mapping_offset"])["type"]
                base += self.cast(self.resolve(binding["mapping_offset"], requirements), {"width": base.size()}, offset_type)
            capacity = self.cast(self.resolve(binding["size"], requirements), {"width": base.size()},
                                 self.facts.expression(binding["size"])["type"])
            limit = base + capacity
            conditions.append(z3.And(gate, z3.UGE(address, base), z3.ULE(end, limit),
                                     z3.UGE(end, address), z3.UGE(limit, base)))
            self.conditional_targets.update((call, requirements) for call in (binding["mapping"], binding["completion"]))
            bindings.append({**binding, "conditions": requirements})
        self.constrain(z3.Or(*conditions))
        self.source_requirements[key] = {**source, "bindings": bindings}

    def merge_definitions(self, key, definitions):
        if key in self.facts.cyclic_definitions:
            return self.fresh(key, reason="loop-carried definitions need a recurrence")
        ordering = self.facts.definition_order[key]
        remaining = set(definitions)
        ordered = []
        while remaining:
            available = sorted(definition for definition in remaining
                               if not any(earlier in remaining and later == definition
                                          for earlier, later in ordering))
            if not available:
                return self.fresh(key, reason="definition ordering is cyclic")
            ordered.append(available[0])
            remaining.remove(available[0])
        gates, values, alternatives = [], [], []
        value_type = self.facts.expression(key)["type"]
        for definition in ordered:
            requirements = tuple(sorted({(guard["condition"], guard["branch"])
                                         for guard in self.facts.guards[self.facts.unwrap(definition)]}))
            gate = z3.And(*[self.guard_value(condition) == branch for condition, branch in requirements])
            value = self.cast(self.resolve(definition, requirements), value_type,
                              self.facts.expression(definition)["type"])
            for previous, previous_gate, previous_value in zip(ordered[:len(gates)], gates, values):
                if (previous, definition) not in ordering:
                    check = z3.Solver()
                    check.set(timeout=1000)
                    check.add(*self.domain_constraints, previous_gate, gate, previous_value != value)
                    if check.check() != z3.unsat:
                        return self.fresh(key, reason="overlapping definitions have unresolved execution order")
            gates.append(gate)
            values.append(value)
            alternatives.append({"definition": definition, "conditions": requirements})
        self.merges[key] = alternatives
        self.constrain(z3.Or(*gates))
        result = values[0]
        for gate, value in zip(gates[1:], values[1:]):
            result = z3.If(gate, value, result)
        for index, definition in enumerate(ordered):
            selected = z3.And(gates[index], *[z3.Not(gate) for gate in gates[index + 1:]])
            self.value_dependencies[key].append((definition, selected))
        for alternative in alternatives:
            for condition, _ in alternative["conditions"]:
                self.value_dependencies[key].append((condition, z3.BoolVal(True)))
        return z3.simplify(result)

    def source_dependency(self, key, source, active=None):
        active = set() if active is None else active
        if key == source or key in self.source_values and self.facts.origin(key) == source:
            return z3.BoolVal(True)
        if key in active:
            return z3.BoolVal(False)
        if (key, source) in self.dependency_cache:
            return self.dependency_cache[key, source]
        active = active | {key}
        dependencies = self.value_dependencies.get(key)
        if dependencies is None:
            dependencies = [(dependency, z3.And(*[truth(self.resolve(condition)) == branch
                                                  for condition, branch in required]))
                            for dependency, required in self.evaluations[key]]
        result = z3.simplify(z3.Or(*[z3.And(condition, self.source_dependency(dependency, source, active))
                                    for dependency, condition in dependencies]))
        self.dependency_cache[key, source] = result
        return result

    def compute(self, key):
        expression = self.facts.expression(key)
        operands = children(expression)
        value_type = expression["type"]
        numeric = integer(expression.get("constant"))
        if key in self.facts.sources:
            value = self.fresh(key, source=True)
            if self.facts.sources[key]["kind"] in {"DmaReadStreaming", "DmaReadCoherent"}:
                self.dma_requirements(key)
            return value
        if numeric is not None and 0 < value_type.get("width", 0) <= 64:
            return z3.BitVecVal(numeric, value_type["width"])
        if self.contracts is not None:
            assumed = self.contracts.apply(self, key)
            if assumed is not None:
                return assumed
        if "/conversion:" in key and 0 in operands:
            child = self.facts.expression(operands[0])
            if value_type.get("kind") == "pointer" and child["type"].get("kind") == "array":
                return self.address_value(key)
            return self.cast(self.resolve(operands[0]), value_type, child["type"])
        if expression["class"] == "StmtExpr" and 0 in operands:
            return self.resolve(operands[0])
        if expression.get("callee") in {"__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64"}:
            value = self.cast(self.resolve(operands[0]), value_type,
                              self.facts.expression(operands[0])["type"])
            return z3.Concat(*[z3.Extract(offset + 7, offset, value) for offset in range(0, value.size(), 8)])
        if expression.get("callee") in {"__builtin_expect", "__builtin_expect_with_probability"}:
            self.resolutions[key] = operands[0]
            return self.cast(self.resolve(operands[0]), value_type,
                             self.facts.expression(operands[0])["type"])
        if expression.get("callee") in {
                "__builtin_add_overflow", "__builtin_sub_overflow", "__builtin_mul_overflow"}:
            return self.overflow_builtin(key)[2]
        operator = expression.get("operator")
        if operator == "=":
            self.resolutions[key] = operands[1]
            return self.cast(self.resolve(operands[1]), value_type,
                             self.facts.expression(operands[1])["type"])
        if operator == "?":
            condition = truth(self.resolve(operands[0]))
            return z3.If(condition, self.resolve(operands[1], (operands[0], True)),
                         self.resolve(operands[2], (operands[0], False)))
        if operator in {"!", "~"} and 0 in operands:
            value = self.resolve(operands[0])
            return z3.Not(truth(value)) if operator == "!" else ~value
        if operator in {"+", "-"} and set(operands) == {0}:
            value = self.resolve(operands[0])
            if operator == "-" and value_type.get("signedness") == "Signed":
                self.constrain_signed_arithmetic(z3.BVSNegNoOverflow(value))
            return value if operator == "+" else -value
        if operator in {"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>",
                        "==", "!=", "<", "<=", ">", ">=", "&&", "||"} and set(operands) >= {0, 1}:
            left = self.resolve(operands[0])
            if operator in {"&&", "||"}:
                right = self.resolve(operands[1], (operands[0], operator == "&&"))
                return (z3.And if operator == "&&" else z3.Or)(truth(left), truth(right))
            right = self.resolve(operands[1])
            left_type = self.facts.expression(operands[0])["type"]
            right_type = self.facts.expression(operands[1])["type"]
            if value_type.get("kind") == "pointer" and operator in {"+", "-"}:
                if left_type.get("kind") == "pointer" and right_type.get("kind") != "pointer":
                    base, index = left, right
                    pointer_type, index_type = left_type, right_type
                elif operator == "+" and right_type.get("kind") == "pointer" and left_type.get("kind") != "pointer":
                    base, index = right, left
                    pointer_type, index_type = right_type, left_type
                else:
                    raise Unresolved("pointer operation has incompatible operands")
                offset = self.cast(index, {"width": base.size()}, index_type)
                stride = max(1, pointer_type.get("stride", 1))
                scaled = offset * stride
                result = base + scaled if operator == "+" else base - scaled
                nonnegative = index >= 0 if index_type.get("signedness") == "Signed" else z3.BoolVal(True)
                increases = nonnegative if operator == "+" else z3.Not(nonnegative)
                self.constrain(z3.If(increases, z3.UGE(result, base), z3.ULE(result, base)))
                self.constrain(z3.BVMulNoOverflow(offset, z3.BitVecVal(stride, base.size()), index_type.get("signedness") == "Signed"))
                return result
            if (left_type.get("kind") == "pointer" or value_type.get("kind") == "pointer") and operator not in {"==", "!="}:
                raise Unresolved(f"pointer arithmetic requires a resolved memory region: {key}")
            if z3.is_bool(left):
                left = self.cast(left, left_type)
            if z3.is_bool(right):
                right = self.cast(right, self.facts.expression(operands[1])["type"])
            if operator in {"<<", ">>"}:
                self.constrain(z3.ULT(right, left.size()))
            if left.size() != right.size():
                if operator not in {"<<", ">>"}:
                    raise Unresolved(f"missing arithmetic conversion at {key}")
                right = self.cast(right, {"width": left.size()})
            signed = left_type["signedness"] == "Signed"
            if operator == "+":
                if signed:
                    self.constrain_signed_arithmetic(z3.BVAddNoOverflow(left, right, True),
                                                     z3.BVAddNoUnderflow(left, right))
                return left + right
            if operator == "-":
                if signed:
                    self.constrain_signed_arithmetic(z3.BVSubNoOverflow(left, right),
                                                     z3.BVSubNoUnderflow(left, right, True))
                return left - right
            if operator == "*":
                if signed:
                    self.constrain_signed_arithmetic(z3.BVMulNoOverflow(left, right, True),
                                                     z3.BVMulNoUnderflow(left, right))
                return left * right
            if operator == "&": return left & right
            if operator == "|": return left | right
            if operator == "^": return left ^ right
            if operator in {"/", "%"}:
                self.constrain(right != 0)
                if signed:
                    self.constrain(z3.Not(z3.And(left == 1 << (left.size() - 1), right == -1)))
                if operator == "/": return left / right if signed else z3.UDiv(left, right)
                return z3.SRem(left, right) if signed else z3.URem(left, right)
            if operator in {"<<", ">>"}:
                if operator == "<<":
                    result = left << right
                    if signed:
                        self.constrain(z3.And(left >= 0, result >= 0, z3.LShR(result, right) == left))
                    return result
                return left >> right if signed else z3.LShR(left, right)
            if operator == "==": return left == right
            if operator == "!=": return left != right
            if operator == "<": return left < right if signed else z3.ULT(left, right)
            if operator == "<=": return left <= right if signed else z3.ULE(left, right)
            if operator == ">": return left > right if signed else z3.UGT(left, right)
            if operator == ">=": return left >= right if signed else z3.UGE(left, right)
        try:
            written = self.written_definition(key)
        except Unresolved as error:
            if value_type.get("kind") != "integer":
                raise
            return self.fresh(key, reason=str(error))
        if key in self.builtin_outputs:
            return self.overflow_builtin(self.builtin_outputs[key])[0]
        if written is not None:
            return self.cast(self.resolve(written), value_type, self.facts.expression(written)["type"])
        definitions = self.facts.definitions.get(key, set())
        if len(definitions) == 1:
            definition = next(iter(definitions))
            self.resolutions[key] = definition
            return self.cast(self.resolve(definition), value_type,
                             self.facts.expression(definition)["type"])
        if len(definitions) > 1:
            return self.merge_definitions(key, definitions)
        declaration = expression.get("declaration")
        if declaration in self.bindings and expression["class"] in {"VariableAccess", "ParameterValue"}:
            definition = self.bindings[declaration]
            self.resolutions[key] = definition
            return self.cast(self.resolve(definition), value_type,
                             self.facts.expression(definition)["type"])
        if "FieldAccess" in expression["class"] or expression["class"] in {"ArrayExpr", "PointerDereferenceExpr"}:
            local_stores = [stored for stored in self.facts.stores[key] if "predecessors" in stored]
            if local_stores:
                # The value is defined only on the stores' guarded paths. Do not
                # invent a zero initialization for paths with no reaching store.
                definitions = {stored["store"] for stored in local_stores}
                self.facts.definition_order[key].update(
                    (previous, stored["store"]) for stored in local_stores
                    for previous in stored["predecessors"] if previous in definitions)
                return self.merge_definitions(key, definitions)
            if key in self.field_reads:
                stored = self.field_reads[key]
                write, definition = stored["store"], stored["src"]
                self.visited.add(write)
                if "write_offset" in stored:
                    previous_offset = self.memory_offset_value(stored["write_offset"], stored["write_indices"])
                    current_offset = self.memory_offset_value(stored["read_offset"], stored["read_indices"])
                    self.constrain(previous_offset == current_offset)
                    self.memory_equalities.append(stored)
                self.resolutions[key] = definition
                return self.cast(self.resolve(definition), value_type,
                                 self.facts.expression(definition)["type"])
        if "Call" in expression["class"] and len(self.facts.calls[key]) == 1:
            call = self.facts.calls[key][0]
            returned = self.facts.returns[call["callee"]]
            if returned and call["callee"] != expression["function"]:
                instance = self.facts.invocation(key, call)
                arguments = {instance["declarations"][parameter["declaration"]]: operands[parameter["index"]]
                             for parameter in call["parameters"] if parameter["index"] in operands}
                self.bindings.update(arguments)
                returned = instance["returns"]
                for contextual in instance["expressions"].values():
                    stores = [stored for stored in self.facts.stores[contextual]
                              if stored.get("dominates") and stored["store"] in instance["expressions"].values()]
                    if len(stores) == 1:
                        self.field_reads[contextual] = stores[0]
                if len(returned) > 1:
                    return self.merge_definitions(key, set(returned))
                self.resolutions[key] = returned[0]
                return self.cast(self.resolve(returned[0]), value_type,
                                 self.facts.expression(returned[0])["type"])
        return self.fresh(key)

    def conditions(self, sink_expression, operand=None):
        self.conditions_complete = False
        self.condition_origins = []
        required = {sink_expression}
        function = self.facts.expression(sink_expression)["function"]
        callers = set()
        while function not in callers:
            callers.add(function)
            self.queried_callers.add(function)
            calls = [key for key in self.call_sites
                     if any(call["callee"] == function for call in self.facts.calls[key])]
            if not calls:
                break
            if len(calls) != 1:
                raise Unresolved("multiple caller invocations require distinct path contexts")
            required.add(calls[0])
            function = self.facts.expression(calls[0])["function"]
        if operand is not None:
            required.add(operand)
        pending = deque([(key, ()) for key in sorted(required)] + sorted(self.conditional_targets))
        seen = set()
        evaluated_contexts = defaultdict(set)
        activation_atoms = {}
        requirement_values = {}
        context_cache = {}
        conditions = []
        while pending:
            current, context = pending.popleft()
            if (current, context) in seen:
                continue
            seen.add((current, context))
            if context not in context_cache:
                atoms = set()
                impossible = False
                for requirement in context:
                    if requirement not in requirement_values:
                        requirement_values[requirement] = z3.simplify(truth(self.resolve(requirement[0])) == requirement[1])
                    value = requirement_values[requirement]
                    if z3.is_false(value):
                        impossible = True
                        break
                    if not z3.is_true(value):
                        identity = value.get_id()
                        activation_atoms.setdefault(identity, (requirement, value))
                        atoms.add(identity)
                normalized = tuple(sorted(activation_atoms[identity][0] for identity in atoms))
                context_cache[context] = normalized, frozenset(atoms), impossible
            context, context_set, impossible = context_cache[context]
            if impossible:
                continue
            if any(previous <= context_set for previous in evaluated_contexts[current]):
                continue
            evaluated_contexts[current] = {previous for previous in evaluated_contexts[current]
                                           if not context_set < previous}
            evaluated_contexts[current].add(context_set)
            activation = z3.simplify(z3.And(*[activation_atoms[identity][1] for identity in sorted(context_set)]))
            if z3.is_false(activation):
                continue
            if current in self.source_values:
                self.source_activations[current].append(activation)
            if current in self.environment:
                self.state_activations[current].append(activation)
            for guard in self.facts.guards[current]:
                value = truth(self.resolve(guard["condition"]))
                conditions.append(z3.Implies(activation, value if guard["branch"] else z3.Not(value)))
                self.condition_origins.append({"kind": "guard", "target": current, **guard, "activation": context})
                self.path_guards.append({**guard, "activation": context})
                pending.append((guard["condition"], context))
            for exclusion in self.facts.exit_guards[current]:
                parts = []
                for guard in exclusion["conditions"]:
                    value = truth(self.resolve(guard["condition"]))
                    parts.append(value if guard["branch"] else z3.Not(value))
                    controllers = {(controller["condition"], controller["branch"])
                                   for controller in self.facts.guards[guard["condition"]]}
                    pending.append((guard["condition"], tuple(sorted(set(context) | controllers))))
                conditions.append(z3.Implies(activation, z3.Not(z3.And(*parts))))
                self.condition_origins.append({"kind": "exit", **exclusion, "activation": context})
                self.path_exclusions.append({**exclusion, "activation": context})
            conditions.extend(z3.Implies(activation, constraint)
                              for constraint in self.semantic_constraints[current])
            self.condition_origins.extend({"kind": "operation", "target": current, "activation": context}
                                          for _ in self.semantic_constraints[current])
            for dependency, required_condition in sorted(self.evaluations[current], key=repr):
                dependency_context = context
                if required_condition:
                    dependency_context = tuple(sorted(set(context) | set(required_condition)))
                pending.append((dependency, dependency_context))
            pending.extend(self.conditional_targets - seen)
        self.condition_origins.extend({"kind": "type"} for _ in self.domain_constraints)
        self.conditions_complete = True
        return conditions + self.domain_constraints

    def environment_in(self, value):
        variables = variables_in(value)
        return {key for key, symbol in self.environment.items() if symbol.get_id() in variables}

    def source_in(self, value):
        variables = variables_in(value)
        return {key for key, symbol in self.source_values.items() if symbol.get_id() in variables}
