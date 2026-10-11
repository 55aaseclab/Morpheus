from collections import defaultdict
import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from semantics import Facts, FlowGraph, SymbolicPath, Unresolved
from assemble_sdg import assemble, write_result
from convert_to_sdg import parse_sdg


def binding_facts():
    sections = defaultdict(dict)
    value_type = {"kind": "integer", "width": 32, "signedness": "Unsigned"}
    for key in ("first", "second", "one", "two", "parameter", "state"):
        sections["expression"][key] = {
            "id": key, "text": key, "location": {}, "type": value_type,
            "function": "helper" if key == "parameter" else "probe",
            "class": "FunctionCall" if key in {"first", "second"} else "VariableAccess",
            "children": [], "declaration": key}
    for call, value in (("first", "one"), ("second", "two")):
        sections["expression"][call]["children"] = [{"position": 0, "id": value}]
        sections["call"][call] = {"call": call, "callee": "helper",
            "parameters": [{"index": 0, "declaration": "parameter"}]}
    sections["expression"]["one"]["constant"] = "1"
    sections["expression"]["two"]["constant"] = "2"
    return Facts(sections)


class ContextTests(unittest.TestCase):
    def test_shared_failure_exports_every_equivalent_witness(self):
        facts = binding_facts().sections
        facts["source"]["one"] = {"kind": "MmioRead", "size_bytes": 4}
        facts["expression"]["state"]["type"] = {"kind": "pointer", "width": 64}
        facts["sink"]["sink"] = {"operand": "state", "expression": "state", "flow_operand": "state",
                                  "function": "probe", "operation": "Dereference", "location": {}}
        paths = defaultdict(dict)
        for key in ("one", "first", "second", "state"):
            paths["flow_node"][key] = {"expressions": [key], "text": key, "location": {}}
        for call in ("first", "second"):
            for source, sink in (("one", call), (call, "state")):
                paths["flow_step"][source + sink] = {"src": source, "dst": sink}
        paths["flow"]["flow"] = {"source": "one", "source_expr": "one", "sink": "state", "sink_expr": "state"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, sections in (("facts", facts), ("paths", paths)):
                with (root / (name + ".csv")).open("w", newline="") as stream:
                    writer = csv.writer(stream)
                    writer.writerow(("section", "key", "value"))
                    for section, records in sections.items():
                        for key, value in records.items():
                            writer.writerow((section, key, json.dumps(value)))

            def failure(symbolic, sink):
                symbolic.resolve("state")
                raise Unresolved("unknown storage")

            with patch("assemble_sdg.MemoryTarget", side_effect=failure) as resolve:
                result = assemble(root / "facts.csv", root / "paths.csv")
                self.assertEqual(resolve.call_count, 1)
            self.assertEqual(result["summary"]["analyzed_contexts"], 2)
            self.assertEqual(result["summary"]["reused_unresolved_contexts"], 1)
            self.assertEqual(len(result["rules"]), 1)
            rule = result["rules"][0]
            self.assertEqual(len(rule["path"]["equivalent_contexts"]), 1)
            write_result(result, root / "output", publication_threshold="proof")
            exported = list((root / "output/sdg-unresolved").glob("*.sdg"))
            self.assertEqual(len(exported), 1)
            restored = parse_sdg(exported[0].read_text())["rule"]
            self.assertEqual(restored["path"]["equivalent_contexts"], rule["path"]["equivalent_contexts"])

            def distinct_failure(symbolic, sink):
                symbolic.resolve("parameter")
                raise Unresolved("unknown storage")

            with patch("assemble_sdg.MemoryTarget", side_effect=distinct_failure) as resolve:
                result = assemble(root / "facts.csv", root / "paths.csv")
                self.assertEqual(resolve.call_count, 2)
            self.assertEqual(len(result["rules"]), 2)

    def test_unused_bindings_share_failure_context(self):
        facts = binding_facts()
        first, second = (SymbolicPath(facts, [call]) for call in ("first", "second"))
        first.resolve("state")
        self.assertTrue(second.matches_context_dependencies(first.context_dependencies()))

    def test_read_binding_keeps_distinct_context(self):
        facts = binding_facts()
        first, second = (SymbolicPath(facts, [call]) for call in ("first", "second"))
        self.assertEqual(first.resolve("parameter").as_long(), 1)
        self.assertEqual(second.resolve("parameter").as_long(), 2)
        self.assertFalse(second.matches_context_dependencies(first.context_dependencies()))

    def test_absent_binding_is_a_context_dependency(self):
        facts = binding_facts()
        absent, bound = SymbolicPath(facts, []), SymbolicPath(facts, ["first"])
        absent.resolve("parameter")
        self.assertFalse(bound.matches_context_dependencies(absent.context_dependencies()))

    def test_caller_conditions_keep_invocation_identity(self):
        facts = binding_facts()
        first, second = (SymbolicPath(facts, [call]) for call in ("first", "second"))
        first.conditions("parameter")
        self.assertFalse(second.matches_context_dependencies(first.context_dependencies()))

    def test_selected_and_absent_field_stores_are_dependencies(self):
        facts = binding_facts()
        facts.stores["state"] = [{"store": "first", "src": "one"},
                                 {"store": "second", "src": "two"}]
        first, second, absent = (SymbolicPath(facts, witness)
                                 for witness in (["first"], ["second"], []))
        first.visited.add("state")
        self.assertFalse(second.matches_context_dependencies(first.context_dependencies()))
        self.assertFalse(absent.matches_context_dependencies(first.context_dependencies()))

    def test_both_helper_invocations_are_enumerated(self):
        sections = defaultdict(dict)
        facts = defaultdict(dict)
        for name in ("source", "first", "second", "sink"):
            sections["flow_node"][name] = {"expressions": [name], "text": name, "location": {}}
            facts["expression"][name] = {"id": name, "function": "probe", "type": {},
                                          "class": "FunctionCall" if name in {"first", "second"} else "Literal",
                                          "children": []}
        for name in ("first", "second"):
            sections["flow_step"]["entry:" + name] = {"src": "source", "dst": name}
            sections["flow_step"]["exit:" + name] = {"src": name, "dst": "sink"}
            facts["call"][name] = {"call": name, "callee": "helper", "parameters": []}
        sections["flow"]["path"] = {"source": "source", "sink": "sink"}
        graph = FlowGraph(sections)
        contexts = list(graph.contextual_flows(Facts(facts)))
        self.assertEqual(len(contexts), 2)
        self.assertEqual({tuple(flow["_witness"]) for _, flow in contexts},
                         {("source", "first", "sink"), ("source", "second", "sink")})
        self.assertEqual(len({flow["context_id"] for _, flow in contexts}), 2)

    def test_cycle_is_preserved_without_infinite_unrolling(self):
        sections = defaultdict(dict)
        for name in ("source", "loop", "sink"):
            sections["flow_node"][name] = {"expressions": [], "text": name, "location": {}}
        for source, target in (("source", "loop"), ("loop", "loop"), ("loop", "sink")):
            sections["flow_step"][source + target] = {"src": source, "dst": target}
        graph = FlowGraph(sections)
        contexts = list(graph.contexts("source", ["sink"], Facts(defaultdict(dict))))
        self.assertEqual(contexts, [["source", "loop", "sink"]])
        self.assertIn(("loop", "loop"), graph.subgraph("source", "sink")[1])


if __name__ == "__main__":
    unittest.main()
