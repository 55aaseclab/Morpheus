import copy
import hashlib
import json
import shutil
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from convert_to_sdg import export_rules
from runtime_package import build_package, restore_document, runtime_plan
from test_convert import fixture


class RuntimePackageTests(unittest.TestCase):
    def test_lossless_evidence_and_shared_plans(self):
        rule, nodes, edges = fixture()
        other = copy.deepcopy(rule)
        other["id"] = "rule:second"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = export_rules([rule, other], nodes, edges, root / "source")
            result = build_package(root / "source", root / "package")
            self.assertEqual(result["rules"], 2)
            self.assertEqual(result["plans"], 1)
            runtime = json.loads((root / "package/runtime.json").read_text())
            records = {r["id"]: r for r in manifest["rules"]}
            for entry in runtime["rules"]:
                actual = restore_document(root / "package/evidence.pack", entry["document"])
                self.assertEqual(actual, (root / "source" / records[entry["id"]]["file"]).read_bytes())
                self.assertEqual(hashlib.sha256(actual).hexdigest(), entry["document_sha256"])
            shutil.rmtree(root / "source")
            self.assertTrue(restore_document(root / "package/evidence.pack", runtime["rules"][0]["document"]))

    def test_export_corruption_rejected_without_partial_package(self):
        rule, nodes, edges = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = export_rules([rule], nodes, edges, root / "source")
            path = root / "source" / manifest["rules"][0]["file"]
            path.write_text(path.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                build_package(root / "source", root / "package")
            self.assertFalse((root / "package").exists())
            self.assertFalse((root / "package.partial").exists())

    def test_definitions_preserve_dependencies_and_ambiguity(self):
        rule, nodes, edges = fixture()
        plan = runtime_plan(rule, nodes, edges)
        self.assertIn("internal:length", plan["definitions"])
        self.assertIn("source:input", plan["nodes"])
        conflict = copy.deepcopy(edges["edge:data"])
        conflict["predicate"]["right"] = {"kind": "Const", "value": 4}
        edges["edge:conflict"] = conflict
        self.assertNotIn("internal:length", runtime_plan(rule, nodes, edges)["definitions"])


if __name__ == "__main__":
    unittest.main()
