import csv
from collections import defaultdict
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent / "scripts"))

from assemble_sdg import assemble, write_result
from semantics import children, identifier, load_facts, validate_expression_references
from semantics import FlowGraph
from verify_database import verify
from target_info import capture_target, object_target, signed_overflow_mode
from rule_store import RuleStore


class FactTests(unittest.TestCase):
    def test_overflow_flags_follow_command_order(self):
        self.assertEqual(signed_overflow_mode(["cc", "-fno-strict-overflow"]), "Wrap")
        self.assertEqual(signed_overflow_mode(["cc", "-fwrapv", "-fno-wrapv"]), "Undefined")
        self.assertEqual(signed_overflow_mode(["cc", "-ftrapv", "-fwrapv"]), "Wrap")
        self.assertEqual(signed_overflow_mode(["cc", "-fwrapv", "-ftrapv"]), "Trap")
        self.assertEqual(signed_overflow_mode(["cc", "-ftrapv", "-fwrapv", "-fno-wrapv"]), "Trap")

    def test_target_byte_order_is_read_from_object(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "unit.c"
            output = Path(directory) / "unit.o"
            source.write_text("unsigned int value;\n")
            subprocess.run(["cc", "-c", str(source), "-o", str(output)], check=True)
            target = capture_target([output])
            self.assertIn(target["byte_order"], {"Little", "Big"})
            self.assertEqual(target["byte_order"], object_target(output)["byte_order"])
            self.assertEqual(len(target["evidence"][0]["sha256"]), 64)

    def test_reused_database_must_match_sources_and_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.c").write_text('#include "header.h"\n')
            (root / "header.h").write_text("typedef unsigned int length_type;\n")
            (root / "sources.txt").write_text("source.c\n")
            with zipfile.ZipFile(root / "src.zip", "w") as archive:
                for name in ("source.c", "header.h"):
                    archive.write(root / name, "snapshot/" + name)
            self.assertEqual(verify(root, root / "sources.txt", root)["matching_snapshot_files"], 2)
            (root / "header.h").write_text("typedef unsigned char length_type;\n")
            with self.assertRaisesRegex(ValueError, "differs from source: header.h"):
                verify(root, root / "sources.txt", root)

    def test_conflicting_id_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "facts.csv"
            with path.open("w", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["section", "key", "value"])
                writer.writerow(["expression", "same", '{"value": 1}'])
                writer.writerow(["expression", "same", '{"value": 2}'])
            with self.assertRaisesRegex(ValueError, "conflicting expression"):
                load_facts(path)

    def test_invalid_json_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "facts.csv"
            with path.open("w", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(["section", "key", "value"])
                writer.writerow(["expression", "key", '{"text": "raw\nnewline"}'])
            with self.assertRaises(json.JSONDecodeError):
                load_facts(path)

    def test_missing_expression_is_an_extraction_error(self):
        sections = defaultdict(dict)
        sections["expression"]["condition"] = {"children": []}
        sections["guard"]["guard"] = {"condition": "condition", "target": "missing", "branch": True}
        with self.assertRaisesRegex(ValueError, "1 undeclared expression references: missing"):
            validate_expression_references(sections)


@unittest.skipUnless(os.environ.get("SDG_TEST_FACTS"), "run run_semantic_tests.py for CodeQL integration")
class KernelSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = assemble(os.environ["SDG_TEST_FACTS"], os.environ["SDG_TEST_PATHS"], os.environ.get("SDG_TEST_TARGET"))
        cls.nodes = {node["id"]: node for node in cls.result["nodes"]}
        cls.temporary = tempfile.TemporaryDirectory()
        library = Path(cls.temporary.name) / "fixture.so"
        subprocess.run([
            "cc", "-O1", "-fno-strict-overflow", "-fno-builtin", "-shared", "-fPIC", "-Wl,-Bsymbolic",
            "-DSDG_OBSERVE_ACCESS",
            "-DSDG_OBSERVE_INDEX(index)=observe_index(index)",
            str(TESTS / "fixtures" / "semantic_paths.c"),
            str(TESTS / "fixtures" / "semantic_consumer.c"),
            str(TESTS / "fixtures" / "semantic_interrupts.c"),
            str(TESTS / "fixtures" / "semantic_dma.c"),
            str(TESTS / "fixtures" / "semantic_runtime.c"), "-o", str(library),
        ], check=True)
        cls.runtime = ctypes.CDLL(str(library))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def function(self, rule):
        if "invocation" in self.nodes[rule["path"]["source"]]:
            return self.nodes[rule["path"]["sink"]]["function"].split(":")[-1]
        return self.nodes[rule["path"]["source"]]["function"].split(":")[-1]

    def test_all_dependency_kinds_use_one_assumption_record(self):
        from contracts import CallContracts

        policy = CallContracts().policy_record()
        for rule in self.result["rules"]:
            with self.subTest(rule=rule["id"]):
                self.assertEqual(rule["assumption_policy"]["id"], policy["id"])
                self.assertEqual(rule["validation"]["assumption_policy"], rule["assumption_policy"])
                self.assertEqual(rule["validation"]["assumption_ledger"], rule["assumptions"])
                self.assertIn("unresolved_prerequisites", rule["validation"])
                self.assertIn("internal_state_witness", rule["validation"])
                self.assertFalse(rule["validation"]["assumption_proof"]["internal_witnesses_fixed"])

    def test_explicit_path_policy_publishes_with_complete_assumption_lists(self):
        from contracts import CallContracts
        from path_assumptions import verify_path_assumptions

        configuration = {"version": 2, "contracts": {}, "path_assumptions": {
            "kinds": ["kernel_path_condition", "transport_callback", "interrupt_delivery", "memory"],
            "reason": "The listed fixture path conditions hold."}}
        result = assemble(os.environ["SDG_TEST_FACTS"], os.environ["SDG_TEST_PATHS"],
                          os.environ.get("SDG_TEST_TARGET"), assumptions=configuration)
        policy = CallContracts(configuration).policy_record()
        nodes = {node["id"]: node for node in result["nodes"]}
        published = [r for r in result["rules"] if r["status"] == "valid_under_assumptions"]
        self.assertTrue(published)
        for rule in published:
            with self.subTest(rule=rule["id"]):
                self.assertTrue(rule["assumptions"])
                self.assertFalse(rule["validation"]["unresolved_prerequisites"])
                verify_path_assumptions(rule, nodes, policy)
                self.assertTrue(all(nodes[h["var"]]["kind"] == "source" for h in rule["mutation_hint"]))
        with tempfile.TemporaryDirectory() as directory:
            write_result(result, directory, publication_threshold="proof")
            payload = json.loads((Path(directory) / "sdg-rules.json").read_text())
            self.assertEqual({r["id"] for r in payload["rules"]}, {r["id"] for r in published} | {
                r["id"] for r in self.result["rules"] if "file" in r.get("runtime_export", {})})

    def test_all_generated_assignments_execute_the_target(self):
        self.assertTrue(self.result["rules"])
        for rule in self.result["rules"]:
            if self.nodes[rule["path"]["source"]]["source"]["kind"] != "MmioRead":
                continue
            with self.subTest(function=self.function(rule), rule=rule["id"]):
                if rule["status"] == "unresolved":
                    self.assertTrue(self.function(rule) == "loop_update" or
                                    self.nodes[rule["path"]["sink"]].get("argument") in {0, 1} or
                                    self.nodes[rule["path"]["sink"]].get("operation") in {"ArrayBase", "FieldAccess", "Dereference"})
                    self.assertEqual(rule["mutation_hint"], [])
                    self.assertNotIn("file", rule["runtime_export"])
                    continue
                if self.function(rule) in {"optional_loop", "conditional_store", "pointer_condition", "pointer_allocated", "guarded_pointer_null"}:
                    self.assertEqual(rule["status"], "conditional")
                    self.assertNotIn("file", rule["runtime_export"])
                    self.assertTrue(rule["validation"]["internal_state_witness"] or
                                    any(self.nodes[key].get("required_internal_state") for key in rule["vars"]))
                else:
                    self.assertEqual(rule["status"], "satisfiable")
                registers = (ctypes.c_ubyte * 512)()
                ctypes.c_uint.in_dll(self.runtime, "read_count").value = 0
                ctypes.c_uint.in_dll(self.runtime, "read_cursor").value = 0
                if self.function(rule) in {"selected_window", "selected_field_window"}:
                    observations = sorted(rule["mutation_hint"], key=lambda hint: self.nodes[hint["var"]]["location"]["line"])
                    values = (ctypes.c_ubyte * 256).in_dll(self.runtime, "read_values")
                    for index, hint in enumerate(observations):
                        values[index] = hint["value"]
                    ctypes.c_uint.in_dll(self.runtime, "read_count").value = len(observations)
                for hint in rule["mutation_hint"]:
                    source = self.nodes[hint["var"]]["source"]
                    byte_order = "big" if source.get("byte_order") == "Big" else "little"
                    value = hint["value"].to_bytes(source["size_bytes"], byte_order)
                    for index, byte in enumerate(value):
                        registers[source.get("offset", source.get("relative_offset")) + index] = byte
                observed_calls = ctypes.c_uint.in_dll(self.runtime, "observed_calls")
                observed_length = ctypes.c_size_t.in_dll(self.runtime, "observed_first_length")
                observed_calls.value = 0
                observed_index = ctypes.c_uint.in_dll(self.runtime, "observed_index")
                observed_index.value = 0xffffffff
                observed_index_mask = ctypes.c_uint.in_dll(self.runtime, "observed_index_mask")
                observed_index_mask.value = 0
                function = getattr(self.runtime, self.function(rule))
                payload = (ctypes.c_ubyte * 512)()
                argument = 100
                for key, value in rule["validation"]["internal_state_witness"].items():
                    if self.nodes[key]["name"] == "replacement":
                        argument = value
                function(registers, payload, ctypes.c_uint(argument))
                self.assertGreater(observed_calls.value, 0)
                if "memory_access" in rule["validation"]:
                    access = rule["validation"]["memory_access"]
                    self.assertTrue(access["within_declared_bounds"])
                    sink = self.nodes[rule["path"]["sink"]]
                    if sink.get("operation") == "memcpy":
                        self.assertEqual(observed_length.value, access["width_bytes"])
                        remaining = ctypes.c_size_t.in_dll(self.runtime, "observed_destination_remaining" if sink["argument"] == 0 else "observed_source_remaining").value
                        if self.function(rule).startswith("pointer_"):
                            self.assertNotEqual(remaining, ctypes.c_size_t(-1).value)
                        if remaining != ctypes.c_size_t(-1).value:
                            bound = access["bounds"][-1]
                            self.assertEqual(remaining, bound["start_bytes"] + bound["size_bytes"] - access["offset_bytes"])
                    continue
                target = rule["target_state"]["predicate"]["right"]["value"]
                if self.nodes[rule["path"]["sink"]]["operation"] == "Index":
                    self.assertLess(target, 32)
                    self.assertTrue(observed_index_mask.value & (1 << target))
                else:
                    self.assertEqual(observed_length.value, target)

    def test_required_cases_have_rules(self):
        functions = {self.function(rule) for rule in self.result["rules"]}
        self.assertTrue({"guarded_copy", "false_branch", "transformed_copy", "clamped_copy",
                         "separate_instances", "unrelated_comparison", "reversed_comparison",
                         "alternatives", "zero_exit", "short_circuit", "conditional_transform",
                         "narrowing", "signed_comparison", "macro_scopes", "optional_exit",
                         "successful_return", "optional_loop", "constant_field_guard",
                         "conditional_store", "checked_replacement", "swapped_length", "big_endian_length",
                         "control_only_copy", "multiple_returns", "separate_array_cells",
                         "indirect_value_store", "repeated_invocation", "nested_invocation",
                         "pointer_condition", "signed_negation", "separate_observations",
                         "infeasible_taint_branch", "inactive_return_branch", "anonymous_member",
                         "inactive_call_branch", "repeated_store_invocation", "signed_wrap_addition",
                         "signed_wrap_subtraction", "signed_wrap_product", "signed_wrap_negation"} <= functions, functions)
        self.assertNotIn("impossible_target", functions)
        self.assertNotIn("overwrite_same_instance", functions)
        self.assertNotIn("overwritten_array_cell", functions)
        self.assertNotIn("inconsistent_parameter", functions)
        solved = {self.function(rule) for rule in self.result["rules"] if rule["status"] != "unresolved"}
        self.assertTrue({"inactive_call_branch", "repeated_store_invocation", "signed_wrap_addition",
                         "signed_wrap_subtraction", "signed_wrap_product", "signed_wrap_negation",
                         "parameter_overwrite", "parameter_alternative"} <= solved, solved)

    def test_pointer_targets_preserve_offsets_extents_and_bindings(self):
        expected = {"pointer_destination": (0, 1, 0), "pointer_source": (1, 1, 0),
                    "pointer_stride": (0, ctypes.sizeof(ctypes.c_uint), 0),
                    "pointer_field": (0, 1, ctypes.sizeof(ctypes.c_uint)),
                    "pointer_helper": (0, 1, 0), "pointer_sparse_offset": (0, 4, 2),
                    "pointer_out_parameter": (0, 1, 0)}
        covered = set()
        for rule in self.result["rules"]:
            function = self.function(rule)
            if function not in expected or "memory_access" not in rule["validation"]:
                continue
            argument, stride, displacement = expected[function]
            if self.nodes[rule["path"]["sink"]].get("argument") != argument:
                continue
            covered.add(function)
            access = rule["validation"]["memory_access"]
            source_value = rule["validation"]["source_assignments"][rule["path"]["source"]]
            self.assertEqual(access["offset_bytes"], source_value * stride + displacement)
            self.assertEqual(rule["target_state"]["head"], "head_offset")
            self.assertTrue(access["within_declared_bounds"])
        self.assertEqual(covered, set(expected))
        allocated = [rule for rule in self.result["rules"] if self.function(rule) == "pointer_allocated"
                     and "memory_access" in rule["validation"]]
        self.assertTrue(allocated)
        for rule in allocated:
            values = {self.nodes[key]["source"]["relative_offset"]: value
                      for key, value in rule["validation"]["source_assignments"].items()}
            access = rule["validation"]["memory_access"]
            self.assertEqual(access["offset_bytes"], values[0x118])
            self.assertEqual(access["bounds"][0]["size_bytes"], values[0x114])
            self.assertEqual(rule["status"], "conditional")
            self.assertTrue(access["requirements"])
            self.assertNotIn("file", rule["runtime_export"])

    def test_guarded_regions_and_output_effects(self):
        regions = {"guarded_pointer_return", "guarded_pointer_select", "guarded_pointer_null"}
        covered = set()
        choices = {name: set() for name in regions}
        for rule in self.result["rules"]:
            function = self.function(rule)
            if function in regions and "memory_access" in rule["validation"]:
                if self.nodes[rule["path"]["sink"]].get("argument") != 0:
                    continue
                source = rule["validation"]["source_assignments"][rule["path"]["source"]]
                access = rule["validation"]["memory_access"]
                self.assertEqual(access["offset_bytes"], 1 if source else 5)
                self.assertTrue(access["within_declared_bounds"])
                covered.add(function)
                choices[function].add(bool(source))
            elif function == "guarded_output_parameter" and rule["status"] != "unresolved":
                if self.nodes[rule["path"]["sink"]].get("argument") != 2:
                    continue
                source = rule["validation"]["source_assignments"][rule["path"]["source"]]
                self.assertEqual(rule["target_state"]["predicate"]["right"]["value"], min(source + 1, 8))
                covered.add(function)
        self.assertEqual(covered, regions | {"guarded_output_parameter"})
        self.assertEqual(choices["guarded_pointer_return"], {False, True})
        self.assertEqual(choices["guarded_pointer_select"], {False, True})
        self.assertEqual(choices["guarded_pointer_null"], {True})

    def test_helper_invocations_have_distinct_value_identities(self):
        parameters = [node for node in self.nodes.values()
                      if node.get("function", "").endswith(":add_checked") and
                      node.get("name") == "value" and "invocation" in node]
        self.assertGreaterEqual(len({node["invocation"] for node in parameters}), 4)
        self.assertEqual(len({node["id"] for node in parameters}), len(parameters))
        for rule in self.result["rules"]:
            if self.function(rule) not in {"repeated_invocation", "nested_invocation"} or rule["status"] == "unresolved":
                continue
            contexts = {self.nodes[key]["invocation"] for key in rule["vars"]
                        if "invocation" in self.nodes[key] and self.nodes[key]["function"].endswith(":add_checked")}
            self.assertGreaterEqual(len(contexts), 2)

    def test_repeated_read_helper_preserves_both_observations(self):
        rules = [rule for rule in self.result["rules"] if self.function(rule) == "separate_observations" and
                 rule["status"] == "satisfiable"]
        self.assertTrue(rules)
        for rule in rules:
            observations = [self.nodes[key] for key in rule["path"]["source_observations"]]
            self.assertEqual({node["source"]["relative_offset"] for node in observations}, {0xc4, 0xc8})
            self.assertEqual(len({node["invocation"] for node in observations}), 2)

    def test_inverse_transform_and_feasible_boundaries(self):
        for rule in self.result["rules"]:
            if self.nodes[rule["path"]["source"]]["source"]["kind"] != "MmioRead":
                continue
            if rule["status"] == "unresolved":
                continue
            if "memory_access" in rule["validation"]:
                continue
            function = self.function(rule)
            target = rule["target_state"]["predicate"]["right"]["value"]
            values = rule["validation"]["source_assignments"]
            if function == "transformed_copy":
                self.assertEqual(values[rule["path"]["source"]], target + 2)
            if function == "swapped_length":
                source_value = values[rule["path"]["source"]]
                self.assertEqual(int.from_bytes(source_value.to_bytes(2, "little"), "big"), target)
            if function == "repeated_invocation":
                self.assertEqual(values[rule["path"]["source"]] + 4, target)
            if function == "nested_invocation":
                self.assertEqual(values[rule["path"]["source"]] + 3, target)
            if function == "parameter_overwrite":
                self.assertEqual(values[rule["path"]["source"]] + 3, target)
            if function == "parameter_alternative":
                self.assertEqual(values[rule["path"]["source"]], target)
            if function == "signed_negation":
                value = values[rule["path"]["source"]]
                self.assertEqual(abs(value if value < 128 else value - 256), target)
            if function == "big_endian_length":
                self.assertEqual(self.nodes[rule["path"]["source"]]["source"]["byte_order"], "Big")
                self.assertNotIn("file", rule["runtime_export"])
            if function == "zero_exit":
                self.assertNotEqual(target, 0)
            if function in {"optional_loop", "constant_field_guard", "checked_replacement", "multiple_returns"}:
                self.assertLessEqual(target, 16)
            if function == "conditional_store":
                replacements = [value for key, value in rule["validation"]["internal_state_witness"].items()
                                if self.nodes[key]["name"] == "replacement"]
                self.assertEqual(replacements, [0])
            if function == "unrelated_comparison":
                self.assertNotIn(target, {72, 73, 74})
            if function in {"guarded_copy", "false_branch", "clamped_copy", "alternatives"}:
                self.assertLessEqual(target, 32)

    def test_every_predicate_reference_is_declared(self):
        def references(value):
            if isinstance(value, dict):
                if "node" in value:
                    yield value["node"]
                for child in value.values():
                    yield from references(child)
            elif isinstance(value, list):
                for child in value:
                    yield from references(child)
        for rule in self.result["rules"]:
            declared = set(rule["vars"])
            self.assertTrue(declared <= set(self.nodes))
            self.assertTrue(set(references(rule)) <= declared)
            for key in declared:
                self.assertTrue(set(self.nodes[key].get("expressions", [])) <= declared,
                                (rule["id"], key))
        for edge in self.result["edges"]:
            self.assertIn(edge["src"], self.nodes)
            self.assertIn(edge["dst"], self.nodes)
            self.assertTrue(set(references(edge)) <= set(self.nodes))

    def test_extracted_expression_references_are_closed(self):
        sections = load_facts(os.environ["SDG_TEST_FACTS"])
        validate_expression_references(sections)
        expressions = sections["expression"]
        references = set()
        for expression in expressions.values():
            references.update(children(expression).values())
        for section, fields in {
            "guard": ("condition", "target"),
            "sink": ("expression", "operand", "flow_operand"),
            "definition": ("src", "dst"),
            "definition_order": ("use", "earlier", "later"),
            "store_use": ("store", "src", "dst"),
            "return": ("expression",),
            "call": ("call",),
        }.items():
            for record in sections[section].values():
                references.update(record[field] for field in fields)
        for exclusion in sections["exit_guard"].values():
            references.add(exclusion["target"])
            references.update(guard["condition"] for guard in exclusion["conditions"])
        self.assertFalse(references - expressions.keys(), references - expressions.keys())

    def test_mmio_offsets_require_mapping_provenance(self):
        mapped = [node for node in self.nodes.values() if node.get("source", {}).get("kind") == "MmioRead"
                  and node["function"].endswith(":mapped_window")]
        self.assertTrue(mapped)
        for node in mapped:
            self.assertEqual(node["source"]["offset"], 0xe4)
            self.assertTrue(node["source"]["mapping_bindings"])
            self.assertNotIn("placement_unresolved", node["source"])
        opaque = [node for node in self.nodes.values() if node.get("source", {}).get("kind") == "MmioRead"
                  and node["function"].endswith(":guarded_copy")]
        self.assertTrue(opaque)
        for node in opaque:
            self.assertNotIn("offset", node["source"])
            self.assertTrue(node["source"]["relative_base"])
            self.assertTrue(node["source"]["placement_unresolved"])
        exported = [rule for rule in self.result["rules"] if "file" in rule["runtime_export"]]
        self.assertTrue(exported)
        self.assertEqual({self.function(rule) for rule in exported}, {"mapped_window"})

    def test_mmio_read_sites_retain_ordered_write_context(self):
        sections = load_facts(os.environ["SDG_TEST_FACTS"])
        reads = sorted((node for node in self.nodes.values()
                        if node.get("source", {}).get("kind") == "MmioRead" and
                        node["function"].endswith(":selected_window")), key=lambda node: node["location"]["line"])
        self.assertEqual(len(reads), 2)
        self.assertEqual({node["source"]["offset"] for node in reads}, {0x24})
        first_context = reads[0]["source"]["access_context"]
        second_context = reads[1]["source"]["access_context"]
        self.assertEqual(len(first_context), 1)
        self.assertEqual(len(second_context), 2)
        first_write = first_context[0]
        later_write = next(context for context in second_context if context["write"] != first_write["write"])
        self.assertEqual(int(sections["expression"][first_write["value"]]["constant"]), 1)
        self.assertEqual(int(sections["expression"][later_write["value"]]["constant"]), 0)
        self.assertEqual(later_write["predecessors"], [first_write["write"]])
        rules = [rule for rule in self.result["rules"] if self.function(rule) == "selected_window"]
        self.assertTrue(any(rule["status"] == "satisfiable" for rule in rules))
        self.assertTrue(all("file" not in rule["runtime_export"] for rule in rules))

    def test_unknown_overflow_flags_do_not_prove_rejection(self):
        functions = {"signed_wrap_addition", "signed_wrap_subtraction", "signed_wrap_product", "signed_wrap_negation"}
        target = json.loads(Path(os.environ["SDG_TEST_TARGET"]).read_text())
        self.assertEqual(target["signed_overflow"], "Wrap")
        with tempfile.TemporaryDirectory() as directory:
            configuration = Path(directory) / "target.json"
            for mode in ("Undefined", "Unknown"):
                configuration.write_text(json.dumps({**target, "signed_overflow": mode}))
                result = assemble(os.environ["SDG_TEST_FACTS"], os.environ["SDG_TEST_PATHS"], configuration)
                nodes = {node["id"]: node for node in result["nodes"]}
                scalar = [rule for rule in result["rules"]
                          if nodes[rule["path"]["sink"]]["function"].split(":")[-1] in functions
                          and nodes[rule["path"]["sink"]].get("argument") == 2]
                if mode == "Undefined":
                    self.assertFalse(scalar)
                else:
                    self.assertEqual({nodes[rule["path"]["sink"]]["function"].split(":")[-1] for rule in scalar}, functions)
                    self.assertTrue(all(rule["status"] == "unresolved" for rule in scalar))
                    self.assertTrue(all("signed-overflow" in rule["validation"]["reason"] for rule in scalar))

    def test_mmio_context_matches_receivers_and_field_updates(self):
        sections = load_facts(os.environ["SDG_TEST_FACTS"])
        reads = sorted((node for node in self.nodes.values()
                        if node.get("source", {}).get("kind") == "MmioRead" and
                        node["function"].endswith(":selected_field_window")), key=lambda node: node["location"]["line"])
        self.assertEqual(len(reads), 2)
        self.assertEqual([len(node["source"]["access_context"]) for node in reads], [1, 2])
        self.assertEqual({int(sections["expression"][context["value"]]["constant"])
                          for node in reads for context in node["source"]["access_context"]}, {0, 1})
        for function in ("replaced_window", "copied_window"):
            replaced = [node for node in self.nodes.values()
                        if node.get("source", {}).get("kind") == "MmioRead" and
                        node["function"].endswith(":" + function)]
            self.assertEqual(len(replaced), 1)
            self.assertFalse(replaced[0]["source"]["access_context"])

    def test_unresolved_path_is_preserved(self):
        rules = [rule for rule in self.result["rules"] if self.function(rule) == "loop_update"]
        self.assertTrue(rules)
        self.assertTrue(all(rule["status"] == "unresolved" for rule in rules))
        for rule in rules:
            self.assertTrue(rule["path"]["alternatives"]["steps"])
            self.assertTrue(rule["path"]["edges"])
            self.assertTrue(rule["validation"]["reason"])

    def test_interrupt_registration_and_delivery(self):
        sources = [node for node in self.nodes.values()
                   if node.get("source", {}).get("kind") == "Irq"]
        self.assertEqual({node["source"]["handler"] for node in sources},
                         {"first_interrupt", "second_interrupt", "unused_interrupt"})
        rules = [rule for rule in self.result["rules"]
                 if self.nodes[rule["path"]["source"]].get("source", {}).get("kind") == "Irq"]
        self.assertTrue(rules)
        self.assertEqual({self.function(rule) for rule in rules}, {"first_interrupt", "second_interrupt"})
        contextual = {node["id"] for node in self.nodes.values()
                      if node.get("function", "").endswith(":interrupt_enabled") and "invocation" in node}
        self.assertTrue(contextual)
        self.assertTrue(any(contextual & set(rule["vars"]) for rule in rules))
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                sink = self.nodes[rule["path"]["sink"]]
                if rule["status"] == "unresolved":
                    self.assertIn(sink.get("argument"), {0, 1})
                    self.assertEqual(rule["status"], "unresolved")
                    self.assertNotIn("file", rule["runtime_export"])
                    continue
                self.assertEqual(rule["status"], "conditional")
                registers = (ctypes.c_ubyte * 512)()
                self.assertEqual(self.runtime.install_interrupts(registers), 0)
                observed_calls = ctypes.c_uint.in_dll(self.runtime, "observed_calls")
                observed_calls.value = 0
                for hint in rule["mutation_hint"]:
                    if hint["operator"] == "SetValue":
                        source = self.nodes[hint["var"]]["source"]
                        for index, byte in enumerate(hint["value"].to_bytes(source["size_bytes"], "little")):
                            registers[source.get("offset", source.get("relative_offset")) + index] = byte
                    else:
                        self.assertEqual(hint["operator"], "DeliverIrq")
                        self.assertEqual(self.runtime.dispatch_irq(1 if hint["handler"] == "first_interrupt" else 2), 1)
                self.assertEqual(observed_calls.value, 1)
                expected = rule["validation"]["memory_access"]["width_bytes"] if "memory_access" in rule["validation"] else rule["target_state"]["predicate"]["right"]["value"]
                self.assertEqual(ctypes.c_size_t.in_dll(self.runtime, "observed_first_length").value, expected)

    def test_sink_operands_and_unevaluated_expressions(self):
        facts = load_facts(os.environ["SDG_TEST_FACTS"])
        sinks = [sink for sink in facts["sink"].values()
                 if sink["function"].endswith(":interrupt_copy")]
        self.assertEqual({sink["argument"] for sink in sinks if sink["operation"] == "memcpy"}, {0, 1, 2})
        sources = [node.get("source", {}) for node in self.nodes.values()]
        self.assertFalse(any(source.get("offset", source.get("relative_offset")) == 0x90 for source in sources))

    def test_dma_direction_completion_and_overwrite(self):
        sources = [node for node in self.nodes.values()
                   if node.get("source", {}).get("kind") == "DmaReadStreaming" and
                   node["source"].get("provenance_status") != "conditional"]
        self.assertEqual({node["function"].split(":")[-1] for node in sources},
                         {"dma_receive", "dma_offset", "dma_nested_field", "dma_page_receive",
                          "dma_conditional_completion", "dma_alternative_completion"})
        self.assertEqual({node["source"]["offset"] for node in sources}, {0, 3, 5, 10})
        rules = [rule for rule in self.result["rules"]
                 if self.nodes[rule["path"]["source"]].get("source", {}).get("kind") == "DmaReadStreaming" and
                 self.nodes[rule["path"]["source"]]["source"].get("provenance_status") != "conditional"]
        self.assertTrue(rules)
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                if rule["status"] == "unresolved":
                    self.assertIn(self.nodes[rule["path"]["sink"]].get("argument"), {0, 1})
                    self.assertEqual(rule["status"], "unresolved")
                    self.assertEqual(rule["path"]["dependency"], "control")
                    self.assertNotIn("file", rule["runtime_export"])
                    continue
                self.assertEqual(rule["status"], "conditional")
                values = (ctypes.c_ubyte * 256).in_dll(self.runtime, "device_bytes")
                for hint in rule["mutation_hint"]:
                    source = self.nodes[hint["var"]]["source"]
                    for index, byte in enumerate(hint["value"].to_bytes(source["size_bytes"], "little")):
                        values[source["offset"] + index] = byte
                observed_calls = ctypes.c_uint.in_dll(self.runtime, "observed_calls")
                observed_calls.value = 0
                enabled = next((value for key, value in rule["validation"]["internal_state_witness"].items()
                                if self.nodes[key]["name"] == "enabled"), 0)
                if self.function(rule) == "dma_conditional_completion":
                    self.assertNotEqual(enabled, 0)
                getattr(self.runtime, self.function(rule))(ctypes.c_uint(enabled))
                self.assertEqual(observed_calls.value, 1)
                expected = rule["validation"]["memory_access"]["width_bytes"] if "memory_access" in rule["validation"] else rule["target_state"]["predicate"]["right"]["value"]
                self.assertEqual(ctypes.c_size_t.in_dll(self.runtime, "observed_first_length").value, expected)

    def test_coherent_dma_excludes_cpu_owned_fields(self):
        sources = [node for node in self.nodes.values()
                   if node.get("source", {}).get("kind") == "DmaReadCoherent"]
        self.assertEqual({node["function"].split(":")[-1] for node in sources}, {"coherent_receive"})
        self.assertEqual({node["source"]["offset"] for node in sources}, {1})
        rules = [rule for rule in self.result["rules"]
                 if self.nodes[rule["path"]["source"]].get("source", {}).get("kind") == "DmaReadCoherent"]
        self.assertTrue(rules)
        for rule in rules:
            with self.subTest(rule=rule["id"]):
                if rule["status"] == "unresolved":
                    self.assertIn(self.nodes[rule["path"]["sink"]].get("argument"), {0, 1})
                    self.assertEqual(rule["status"], "unresolved")
                    self.assertEqual(rule["path"]["dependency"], "control")
                    self.assertNotIn("file", rule["runtime_export"])
                    continue
                self.assertEqual(rule["status"], "conditional")
                self.assertNotIn("file", rule["runtime_export"])
                values = (ctypes.c_ubyte * 256).in_dll(self.runtime, "device_bytes")
                for hint in rule["mutation_hint"]:
                    source = self.nodes[hint["var"]]["source"]
                    for index, byte in enumerate(hint["value"].to_bytes(source["size_bytes"], "little")):
                        values[source["offset"] + index] = byte
                observed_calls = ctypes.c_uint.in_dll(self.runtime, "observed_calls")
                observed_calls.value = 0
                self.runtime.coherent_receive()
                self.assertEqual(observed_calls.value, 1)
                expected = rule["validation"]["memory_access"]["width_bytes"] if "memory_access" in rule["validation"] else rule["target_state"]["predicate"]["right"]["value"]
                self.assertEqual(ctypes.c_size_t.in_dll(self.runtime, "observed_first_length").value, expected)

    def test_page_pool_prerequisites_are_not_assumed(self):
        sources = [node for node in self.nodes.values()
                   if node.get("source", {}).get("provenance_status") == "conditional"]
        self.assertEqual({node["function"].split(":")[-1] for node in sources}, {"page_pool_observation"})
        self.assertTrue(sources)
        identifiers = {node["id"] for node in sources}
        for source in sources:
            for binding in source["source"]["bindings"]:
                self.assertNotIn("mapping", binding)
                self.assertIn("pool was created with PP_FLAG_DMA_MAP", binding["unresolved_requirements"])
        rules = [rule for rule in self.result["rules"] if rule["path"]["source"] in identifiers]
        self.assertTrue(rules)
        for rule in rules:
            self.assertEqual(rule["status"], "unresolved")
            self.assertEqual(rule["mutation_hint"], [])
            self.assertNotIn("file", rule["runtime_export"])

    def test_control_only_source_reaches_constant_size_sink(self):
        rules = [rule for rule in self.result["rules"] if self.function(rule) == "control_only_copy" and
                 rule["status"] == "satisfiable" and "memory_access" not in rule["validation"]]
        self.assertTrue(rules)
        for rule in rules:
            self.assertEqual(rule["path"]["dependency"], "control")
            self.assertEqual(rule["target_state"]["predicate"]["right"]["value"], 16)
            flags = rule["validation"]["source_assignments"][rule["path"]["source"]]
            self.assertTrue(flags & 8)
            self.assertFalse(flags & 16)

    def test_control_grouping_preserves_every_condition(self):
        sections = load_facts(os.environ["SDG_TEST_PATHS"])
        expected = defaultdict(set)
        expressions = {node["expression_id"]: node["id"] for node in self.nodes.values()
                       if "expression_id" in node}
        for dependency in sections["control_dependency"].values():
            key = dependency["source_expr"], identifier("sink", dependency["sink_key"])
            expected[key].add((expressions[dependency["guard"]], dependency["branch"]))
        for rule in self.result["rules"]:
            if rule["path"].get("dependency") != "control":
                continue
            key = rule["path"].get("origin_source_expression", rule["path"]["source_expression"]), rule["path"]["sink"]
            actual = {(condition["condition"], condition["branch"])
                      for condition in rule["path"]["control_conditions"]}
            self.assertEqual(actual, expected[key])

    def test_all_native_alternatives_are_retained(self):
        graph = FlowGraph(load_facts(os.environ["SDG_TEST_PATHS"]))
        for flow in graph.flows.values():
            if "impossible_target" in flow["source_expr"]:
                continue
            matching = [rule for rule in self.result["rules"]
                        if rule["path"].get("origin_source_expression", rule["path"]["source_expression"]) == flow["source_expr"] and
                        rule["path"].get("dependency") == "data"]
            if not matching:
                rejected = [entry for entry in self.result["rejected"] if entry.get("flow") == flow]
                self.assertTrue(rejected, flow)
                continue
            self.assertTrue(matching, flow)
            _, steps = graph.subgraph(flow["source"], flow["sink"])
            self.assertTrue(any(len(rule["path"]["alternatives"]["steps"]) == len(steps)
                                for rule in matching))

    def test_serialized_rules_reference_preserved_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            write_result(self.result, directory)
            edges = json.loads((Path(directory) / "sdg-edges.json").read_text())
            rules = json.loads((Path(directory) / "sdg-rules.json").read_text())
            identifiers = {edge["id"] for edge in edges["self_edges"] + edges["cross_edges"]}
            for rule in rules["rules"]:
                self.assertTrue(set(rule["path"]["edges"]) <= identifiers)

    def test_target_solver_timeout_retains_publishable_mutation_guidance(self):
        from unittest.mock import patch
        import assemble_sdg
        import z3

        original = assemble_sdg.solver_for

        class TargetTimeout:
            def __init__(self, solver):
                self.solver, self.checks = solver, 0

            def check(self):
                self.checks += 1
                return z3.unknown if self.checks == 2 else self.solver.check()

            def __getattr__(self, name):
                return getattr(self.solver, name)

        with patch("assemble_sdg.solver_for", side_effect=lambda conditions: TargetTimeout(original(conditions))):
            result = assemble(os.environ["SDG_TEST_FACTS"], os.environ["SDG_TEST_PATHS"],
                              os.environ.get("SDG_TEST_TARGET"),
                              selection={"source_function": "false_branch", "sink_argument": 2})
        timed_out = {r["id"] for r in result["rules"] if r["validation"].get("reason") == "solver timeout"}
        self.assertTrue(timed_out)
        with tempfile.TemporaryDirectory() as directory:
            write_result(result, directory)
            published = json.loads((Path(directory) / "sdg-rules.json").read_text())["rules"]
            by_id = {r["id"]:r for r in published}
            self.assertTrue(timed_out <= by_id.keys())
            for identity in timed_out:
                self.assertEqual(by_id[identity]["enhancement"]["backend"], "z3")
                self.assertFalse(by_id[identity]["publication"]["solver_success_required"])
                self.assertTrue(by_id[identity]["mutation_hint"])

    def test_interrupt_target_timeout_retains_delivery_hint(self):
        from unittest.mock import patch
        from control import interrupt_rules
        from assemble_sdg import semantic_edges, candidates
        from graph import edge_index, preserve_graph
        from semantics import Facts
        import z3

        facts = Facts(load_facts(os.environ["SDG_TEST_FACTS"]),
                      json.loads(Path(os.environ["SDG_TEST_TARGET"]).read_text()))
        sections = load_facts(os.environ["SDG_TEST_PATHS"])
        _, edges = preserve_graph(facts, FlowGraph(sections))
        solver_class = z3.Solver

        class TargetTimeout:
            def __init__(self, *args, **kwargs):
                self.solver, self.checks = solver_class(*args, **kwargs), 0

            def check(self):
                self.checks += 1
                return z3.unknown if self.checks == 2 else self.solver.check()

            def __getattr__(self, name):
                return getattr(self.solver, name)

        with patch("control.z3.Solver", TargetTimeout):
            _, _, rules, _, _ = interrupt_rules(facts, sections, semantic_edges, candidates, edge_index(edges))
        timed_out = [r for r in rules if r["validation"].get("reason") == "interrupt target solver timeout"]
        self.assertTrue(timed_out)
        for rule in timed_out:
            self.assertTrue(rule["path"]["witness"])
            self.assertTrue(any(h["operator"] == "DeliverIrq" for h in rule["mutation_hint"]))

    def test_streamed_rules_preserve_the_full_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_result(self.result, root / "memory")
            store = RuleStore(root)
            try:
                store.extend(self.result["rules"])
                write_result({**self.result, "rules": store}, root / "streamed")
                for filename in ("sdg-nodes.json", "sdg-edges.json", "sdg-rules.json", "sdg-diagnostics.json"):
                    self.assertEqual(json.loads((root / "memory" / filename).read_text()),
                                     json.loads((root / "streamed" / filename).read_text()))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
