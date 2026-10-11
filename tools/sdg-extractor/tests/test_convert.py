import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from convert_to_sdg import export_rules, parse_sdg, render_sdg


def fixture():
    nodes = {
        "source:input": {"id": "source:input", "kind": "source",
                         "source": {"kind": "MmioRead", "size_bytes": 1,
                                    "byte_order": "Runtime", "offset": 257}},
        "internal:length": {"id": "internal:length", "kind": "internal",
                            "type": {"width": 64, "signedness": "Unsigned"}},
        "sink:copy": {"id": "sink:copy", "kind": "sink", "operation": "memcpy"},
    }
    value = {"kind": "Ref", "node": "internal:length"}
    source = {"kind": "Ref", "node": "source:input"}
    edges = {
        "edge:data": {"id": "edge:data", "src": "source:input", "dst": "internal:length",
                      "head": "head_dataflow", "predicate": {"kind": "Eq", "left": value,
                      "right": {"kind": "Cast", "value": source, "type": {"width": 64}}}},
        "edge:call": {"id": "edge:call", "src": "internal:length", "dst": "sink:copy",
                      "head": "head_call", "predicate": {"kind": "Eq", "operand": "memcpy",
                                                          "value": value}},
        "edge:self": {"id": "edge:self", "src": "internal:length", "dst": "internal:length",
                      "head": "head_bound", "predicate": {"kind": "Le", "left": value,
                      "right": {"kind": "Const", "value": 255}, "signedness": "Unknown"}},
    }
    rule = {
        "id": "rule:example", "status": "valid_under_assumptions", "vars": list(nodes),
        "path": {"source": "source:input", "sink": "sink:copy", "edges": list(edges),
                 "alternatives": {"nodes": ["internal:length"], "steps": []}},
        "preconditions": {"kind": "And", "operands": [
            {"kind": "Or", "operands": [edges["edge:self"]["predicate"],
                                        {"kind": "Not", "operand": source}]}]},
        "target_state": {"src": "internal:length", "dst": "internal:length",
                         "head": "head_bound", "predicate": {"kind": "Eq", "left": value,
                         "right": {"kind": "Const", "value": 1}}},
        "mutation_hint": [{"operator": "SetValue", "var": "source:input", "value": 1}],
        "assumptions": [{"node": "internal:length", "reason": "explicit workload condition"}],
        "validation": {"result": "sat", "assumption_constraints_proven": True,
                       "assumption_proof": {"consistency": "sat", "counterexample": "unsat",
                                            "internal_witnesses_fixed": False, "proven": True},
                       "source_assignments": {"source:input": 1},
                       "assumption_ledger": [{"kind": "kernel_call", "node": "internal:length",
                                              "status": "assumed", "return": "zero"}]},
        "runtime_export": {"reason": "internal state needs runtime binding"},
        "extra_metadata": {"label": "spaces, Unicode λ, and\nnewlines"},
    }
    return rule, nodes, edges


class ExportTests(unittest.TestCase):
    def test_full_graph_round_trip(self):
        rule, nodes, edges = fixture()
        restored = parse_sdg(render_sdg(rule, nodes, edges))
        self.assertEqual(restored["rule"], rule)
        self.assertEqual({node["id"]: node for node in restored["nodes"]}, nodes)
        self.assertEqual({edge["id"]: edge for edge in restored["edges"]}, edges)
        self.assertEqual(sum(edge["src"] != edge["dst"] for edge in restored["edges"]), 2)

    def test_deterministic_output(self):
        rule, nodes, edges = fixture()
        self.assertEqual(render_sdg(rule, nodes, edges),
                         render_sdg(rule, dict(reversed(list(nodes.items()))),
                                    dict(reversed(list(edges.items())))))

    def test_status_and_assumptions_are_never_promoted(self):
        rule, nodes, edges = fixture()
        for status in ("conditional", "unresolved", "satisfiable", "valid_under_assumptions"):
            with self.subTest(status=status):
                rule["status"] = status
                self.assertEqual(parse_sdg(render_sdg(rule, nodes, edges))["rule"], rule)

    def test_unresolved_sources_are_preserved(self):
        rule, nodes, edges = fixture()
        for kind in ("MmioRead", "DmaReadStreaming", "DmaReadCoherent", "Irq"):
            with self.subTest(kind=kind):
                nodes["source:input"]["source"] = {"kind": kind, "placement_unresolved": "binding required"}
                restored = parse_sdg(render_sdg(rule, nodes, edges))
                self.assertEqual({node["id"]: node for node in restored["nodes"]}, nodes)

    def test_missing_node_or_edge_is_rejected(self):
        rule, nodes, edges = fixture()
        with self.assertRaisesRegex(ValueError, "missing node"):
            render_sdg(rule, {}, edges)
        with self.assertRaisesRegex(ValueError, "missing edge"):
            render_sdg(rule, nodes, {})

    def test_dangling_nested_predicate_is_rejected(self):
        rule, nodes, edges = fixture()
        edges["edge:data"]["predicate"]["right"]["value"]["node"] = "internal:missing"
        with self.assertRaisesRegex(ValueError, "undeclared node"):
            render_sdg(rule, nodes, edges)

    def test_duplicate_and_unknown_records_are_rejected(self):
        rule, nodes, edges = fixture()
        rendered = render_sdg(rule, nodes, edges)
        with self.assertRaisesRegex(ValueError, "duplicate field"):
            parse_sdg(rendered + 'field status "satisfiable"\n')
        node_line = next(line for line in rendered.splitlines() if line.startswith("node "))
        with self.assertRaisesRegex(ValueError, "duplicate node"):
            parse_sdg(rendered + node_line + "\n")
        with self.assertRaisesRegex(ValueError, "unknown record"):
            parse_sdg(rendered + "ignored whatever\n")

    def test_old_schema_is_rejected(self):
        rule, nodes, edges = fixture()
        rule["vars"] = list(nodes.values())
        with self.assertRaisesRegex(ValueError, "node IDs"):
            render_sdg(rule, nodes, edges)
        with self.assertRaisesRegex(ValueError, "sdg 1.2"):
            parse_sdg("rule example\nnode data mmio 0x100 1\n")

    def test_unknown_signedness_is_retained(self):
        rule, nodes, edges = fixture()
        restored = parse_sdg(render_sdg(rule, nodes, edges))
        self.assertEqual(next(edge for edge in restored["edges"] if edge["id"] == "edge:self")
                         ["predicate"]["signedness"], "Unknown")

    def test_export_is_validated_before_writing(self):
        rule, nodes, edges = fixture()
        invalid = copy.deepcopy(rule)
        invalid["id"] = "rule:invalid"
        invalid["path"]["edges"].append("edge:missing")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            with self.assertRaisesRegex(ValueError, "missing edge"):
                export_rules([rule, invalid], nodes, edges, output)
            self.assertFalse(output.exists())
            with self.assertRaisesRegex(ValueError, "duplicate rule"):
                export_rules([rule, rule], nodes, edges, output)

    def test_export_manifest_and_owned_cleanup(self):
        rule, nodes, edges = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            unrelated = output / "manual.sdg"
            unrelated.write_text("untouched")
            manifest = export_rules([rule], nodes, edges, output)
            record = manifest["rules"][0]
            self.assertEqual((record["cross_edges"], record["self_edges"], record["target_edges"]), (2, 1, 1))
            self.assertEqual(parse_sdg((output / record["file"]).read_text())["rule"], rule)
            export_rules([], nodes, edges, output)
            self.assertFalse((output / record["file"]).exists())
            self.assertEqual(unrelated.read_text(), "untouched")

    def test_cli_resolves_sibling_artifacts_and_selects_rule(self):
        rule, nodes, edges = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sdg-rules.json").write_text(json.dumps({"version": "1.2", "rules": [rule]}))
            (root / "sdg-nodes.json").write_text(json.dumps({"version": "1.2", "nodes": list(nodes.values())}))
            (root / "sdg-edges.json").write_text(json.dumps({"version": "1.2", "self_edges": [edges["edge:self"]],
                                                          "cross_edges": [edges["edge:data"], edges["edge:call"]]}))
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / "scripts/convert_to_sdg.py"),
                       "--rules", str(root / "sdg-rules.json"), "--output", str(root / "export"),
                       "--rule-id", rule["id"]]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["count"], 1)
            missing = subprocess.run(command[:-1] + ["rule:missing"], capture_output=True, text=True)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("rule IDs not found", missing.stderr)

    def test_assembler_writes_full_graph_and_separate_runtime_export(self):
        from assemble_sdg import write_result
        from semantics import identifier

        rule, nodes, edges = fixture()
        edge_records = [{name: value for name, value in edge.items() if name != "id"}
                        for edge in edges.values()]
        rule["path"]["edges"] = edge_records
        expected = copy.deepcopy(rule)
        expected["path"]["edges"] = [identifier("edge", json.dumps(edge, sort_keys=True))
                                    for edge in rule["path"]["edges"]]
        rule["runtime_export"] = {"file": "scalar.sdg"}
        expected["runtime_export"] = rule["runtime_export"]
        result = {"nodes": list(nodes.values()), "edges": edge_records, "rules": [rule],
                  "exports": {"scalar.sdg": "scalar runtime representation\n"},
                  "summary": {}, "rejected": [], "unresolved": []}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_result(result, root, publication_threshold="proof")
            manifest = json.loads((root / "sdg/manifest.json").read_text())
            self.assertEqual(manifest["count"], 1)
            text = (root / "sdg" / manifest["rules"][0]["file"]).read_text()
            self.assertEqual(parse_sdg(text)["rule"], expected)
            self.assertEqual((root / "runtime-sdg/scalar.sdg").read_text(),
                             result["exports"]["scalar.sdg"])
            self.assertFalse((root / "sdg/scalar.sdg").exists())
            self.assertEqual(result["summary"]["semantic_exports"], 1)


if __name__ == "__main__":
    unittest.main()
