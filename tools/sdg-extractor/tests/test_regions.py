from collections import defaultdict
from pathlib import Path
import sys
import unittest

import z3

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from semantics import Facts, SymbolicPath, Unresolved
from memory import MemoryTarget


def region_facts():
    sections = defaultdict(dict)
    scalar = {"kind": "integer", "width": 32, "signedness": "Unsigned", "name": "unsigned int"}
    pointer = {"kind": "pointer", "width": 64, "signedness": "Unknown", "stride": 1}
    array = {"kind": "array", "width": 256}

    def expression(key, kind, value_type, operands=(), **properties):
        sections["expression"][key] = {"id": key, "class": kind, "function": "probe", "text": key,
                                      "location": {"file": "device.c", "line": 1}, "type": value_type,
                                      "children": [{"position": position, "id": operand}
                                                   for position, operand in enumerate(operands)], **properties}

    expression("selector", "FunctionCall", scalar)
    sections["source"]["selector"] = {"kind": "MmioRead", "size_bytes": 4}
    expression("array", "VariableAccess", array, declaration="buffer", storage="automatic")
    expression("base/conversion:ArrayToPointerConversion", "ArrayToPointerConversion", pointer, ("array",))
    expression("one", "Literal", scalar, constant="1")
    expression("five", "Literal", scalar, constant="5")
    expression("first", "AddExpr", pointer, ("base/conversion:ArrayToPointerConversion", "one"), operator="+")
    expression("second", "AddExpr", pointer, ("base/conversion:ArrayToPointerConversion", "five"), operator="+")
    expression("selected", "ConditionalExpr", pointer, ("selector", "first", "second"), operator="?")
    expression("copy", "FunctionCall", pointer, ("selected", "base/conversion:ArrayToPointerConversion", "one"))
    sink = {"expression": "copy", "operand": "selected", "argument": 0, "width_expression": "one",
            "location": {"file": "device.c", "line": 1}, "operation": "memcpy"}
    return sections, sink


class RegionTests(unittest.TestCase):
    def test_opaque_pointer_does_not_invent_storage(self):
        sections, sink = region_facts()
        sections["expression"]["selected"].update({"class": "ParameterValue", "children": []})
        sections["expression"]["selected"].pop("operator")
        symbolic = SymbolicPath(Facts(sections), [])
        with self.assertRaisesRegex(Unresolved, "no resolved storage"):
            MemoryTarget(symbolic, sink)

    def test_pointer_select_keeps_both_regions_and_offsets(self):
        sections, sink = region_facts()
        symbolic = SymbolicPath(Facts(sections), [])
        memory = MemoryTarget(symbolic, sink)
        conditions = symbolic.conditions(sink["expression"], sink["operand"])
        for selector, offset in ((0, 5), (1, 1)):
            solver = z3.Solver()
            solver.add(*conditions, symbolic.source_values["selector"] == selector)
            self.assertEqual(solver.check(), z3.sat)
            access = memory.validation(solver.model())
            self.assertEqual(access["offset_bytes"], offset)
            self.assertEqual(len(access["bounds"]), 1)
            self.assertTrue(access["within_declared_bounds"])
        self.assertEqual(len(symbolic.merges["selected"]), 2)

    def test_pointer_read_uses_guarded_reaching_definitions(self):
        sections, sink = region_facts()
        sections["expression"]["selected"].update({"class": "VariableAccess", "children": []})
        sections["expression"]["selected"].pop("operator")
        for definition, branch in (("first", True), ("second", False)):
            sections["definition"][definition] = {"src": definition, "dst": "selected"}
            sections["guard"][definition] = {"condition": "selector", "target": definition, "branch": branch}
        symbolic = SymbolicPath(Facts(sections), [])
        memory = MemoryTarget(symbolic, sink)
        solver = z3.Solver()
        solver.add(*symbolic.conditions("copy", "selected"), symbolic.source_values["selector"] == 0)
        self.assertEqual(solver.check(), z3.sat)
        self.assertEqual(memory.validation(solver.model())["offset_bytes"], 5)

    def test_overlapping_pointer_definitions_remain_unresolved(self):
        sections, sink = region_facts()
        sections["expression"]["selected"].update({"class": "VariableAccess", "children": []})
        sections["expression"]["selected"].pop("operator")
        for definition in ("first", "second"):
            sections["definition"][definition] = {"src": definition, "dst": "selected"}
        with self.assertRaisesRegex(Unresolved, "overlap"):
            MemoryTarget(SymbolicPath(Facts(sections), []), sink)

    def test_pointer_null_alternative_does_not_invent_storage(self):
        sections, sink = region_facts()
        sections["expression"]["second"].update({"class": "Literal", "children": [], "constant": "0"})
        sections["expression"]["second"].pop("operator")
        symbolic = SymbolicPath(Facts(sections), [])
        memory = MemoryTarget(symbolic, sink)
        solver = z3.Solver()
        solver.add(*symbolic.conditions("copy", "selected"), symbolic.source_values["selector"] == 0)
        self.assertEqual(solver.check(), z3.sat)
        access = memory.validation(solver.model())
        self.assertFalse(access["within_declared_bounds"])
        self.assertEqual(access["bounds"][0]["size_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
