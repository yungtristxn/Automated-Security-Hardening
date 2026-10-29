"""Regression and contract tests. No network or Windows registry access."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scapolite_ansible.compiler import COMPOUND, GPO, REGISTRY, analyze
from scapolite_ansible.emit import atomic_write, playbook

ROOT = Path(__file__).resolve().parents[1]


def registry(**changes):
    result = {
        "system": REGISTRY,
        "config": "Computer",
        "registry_key": r"Software\ScapoliteConverterTest",
        "value_name": "Example",
        "action": "DWORD:15",
    }
    result.update(changes)
    return result


def rule(ident="R1", autos=None):
    return {
        "scapolite": {"class": "rule", "version": "0.51"},
        "id": ident,
        "id_namespace": "example.test",
        "title": "Test rule",
        "implementations": [
            {"relative_id": "01", "automations": autos if autos is not None else [registry()]}
        ],
    }


def compound(*automations):
    return {"system": COMPOUND, "automations": list(automations)}


class ConverterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()

    def put(self, data=None, filename="rule.yml", text=None):
        path = self.inputs / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            text
            if text is not None
            else yaml.safe_dump(data if data is not None else rule(), sort_keys=False),
            encoding="utf-8",
        )
        return path

    def analysis(self, **kwargs):
        return analyze([str(self.inputs)], **kwargs)

    def assert_code(self, code, result=None):
        result = self.analysis() if result is None else result
        self.assertFalse(result.ok)
        self.assertIn(code, [d.code for d in result.diagnostics], result.report())

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "scapolite_ansible", *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=20,
        )

    def test_published_bitlocker_has_three_correct_operations(self):
        result = analyze([str(ROOT / "tests/fixtures/upstream/bitlocker.md")])
        self.assertTrue(result.ok, result.report())
        self.assertEqual(
            [(o.name, o.type, o.value) for o in result.operations],
            [
                ("RDVPassphrase", "dword", 1),
                ("RDVPassphraseComplexity", "dword", 1),
                ("RDVPassphraseLength", "dword", 15),
            ],
        )
        self.assertEqual(result.operations[-1].minimum, 15)
        self.assertTrue(
            all(o.path == r"HKLM:\Software\Policies\Microsoft\FVE" for o in result.operations)
        )

    def test_bundled_rule_enables_policy(self):
        result = analyze([str(ROOT / "rules")])
        self.assertTrue(result.ok, result.report())
        self.assertIn(("RDVPassphrase", 1), [(o.name, o.value) for o in result.operations])

    def test_markdown_text_and_embedded_separator(self):
        data = rule()
        data["title"] = "before---after"
        self.put(
            filename="rule.md",
            text="---\n" + yaml.safe_dump(data) + "---\n# Human text\nnot: [yaml\n",
        )
        self.assertTrue(self.analysis().ok)

    def test_recursive_case_insensitive_extensions(self):
        self.put(rule("R1"), "nested/one.YAML")
        self.put(
            filename="two.MD",
            text="---\n" + yaml.safe_dump(rule("R2", [registry(value_name="Other")])) + "---\n",
        )
        self.assertEqual(len(self.analysis().operations), 2)

    def test_invalid_front_matter(self):
        self.put(filename="rule.md", text="# No front matter")
        self.assert_code("FRONT_MATTER")

    def test_unterminated_markdown(self):
        self.put(filename="rule.md", text="---\n" + yaml.safe_dump(rule()))
        self.assert_code("FRONT_MATTER")

    def test_bom_crlf(self):
        self.put(
            filename="rule.md",
            text="\ufeff---\r\n" + yaml.safe_dump(rule()).replace("\n", "\r\n") + "---\r\nText",
        )
        self.assertTrue(self.analysis().ok)

    def test_yaml_duplicate_keys_rejected_with_line(self):
        self.put(text=yaml.safe_dump(rule()) + "id: OVERRIDE\n")
        self.assert_code("YAML")
        self.assertIsInstance(self.analysis().diagnostics[0].line, int)

    def test_indented_separator_is_not_a_front_matter_delimiter(self):
        text = (
            "---\n"
            + yaml.safe_dump(rule())
            + "description: |\n  before\n  ---\n  after\n---\nBody\n"
        )
        self.put(filename="rule.md", text=text)
        self.assertTrue(self.analysis().ok, self.analysis().report())

    def test_reader_error_is_a_diagnostic(self):
        self.put(text="id: bad\x00value")
        self.assert_code("YAML")

    def test_multiline_title_is_valid_metadata(self):
        d = rule()
        d["title"] = "First line\nSecond line\n"
        self.put(d)
        self.assertTrue(self.analysis().ok)

    def test_not_set_is_explicitly_unsupported(self):
        self.put(rule(autos=[registry(action="DWORD:NOT_SET")]))
        self.assert_code("UNSUPPORTED_ACTION")

    def test_invalid_documents_remain_accounted_for(self):
        self.put(filename="a.yml", text="x: [")
        self.put(filename="b.yml")
        report = self.analysis().report()
        self.assertEqual(report["summary"]["documents"], 2)
        self.assertEqual(report["summary"]["invalid_documents"], 1)

    def test_aliases_and_unsafe_tags_rejected(self):
        for text in [
            "a: &x [1]\nb: *x",
            "!!python/object/apply:os.system ['echo forbidden']",
            "? [x,y]\n: z",
        ]:
            with self.subTest(text=text):
                self.put(text=text)
                self.assert_code("YAML")

    def test_shapes_and_versions_rejected(self):
        for text, code in [("[]", "DOCUMENT_SHAPE"), ("", "DOCUMENT_SHAPE"), ("id: R1", "HEADER")]:
            with self.subTest(text=text):
                self.put(text=text)
                self.assert_code(code)
        for version in [0.51, "0.52", None, []]:
            with self.subTest(version=version):
                d = rule()
                d["scapolite"]["version"] = version
                self.put(d)
                self.assert_code("VERSION")
        for kind in [[], {}, "unknown"]:
            with self.subTest(kind=kind):
                d = rule()
                d["scapolite"]["class"] = kind
                self.put(d)
                self.assert_code("DOCUMENT_CLASS")

    def test_identifier_and_title_required(self):
        for field in ["id", "id_namespace", "title"]:
            with self.subTest(field=field):
                d = rule()
                d.pop(field)
                self.put(d)
                self.assertFalse(self.analysis().ok)

    def test_on_off_names_are_strings(self):
        self.put(text=yaml.safe_dump(rule()).replace("value_name: Example", "value_name: on"))
        self.assertEqual(self.analysis().operations[0].name, "on")

    def test_invalid_utf8_and_size(self):
        p = self.put()
        p.write_bytes(b"\xff")
        self.assert_code("INPUT_READ")
        p.write_bytes(b"#" * (1024 * 1024 + 1))
        self.assert_code("INPUT_SIZE")

    def test_directory_read_error_propagates(self):
        self.put()
        with patch("scapolite_ansible.parser.os.walk", side_effect=PermissionError("denied")):
            self.assert_code("INPUT_READ")

    def test_duplicate_document_identity(self):
        self.put(filename="a.yml")
        self.put(filename="b.yml")
        self.assert_code("DUPLICATE_ID")

    def test_non_rules_accounted_for(self):
        self.put()
        for kind in ["group", "collection", "profile"]:
            d = rule(kind)
            d["scapolite"]["class"] = kind
            self.put(d, kind + ".yml")
        r = self.analysis()
        self.assertTrue(r.ok)
        self.assertEqual([d["status"] for d in r.documents].count("non_rule"), 3)

    def test_no_rule_is_error(self):
        d = rule()
        d["scapolite"]["class"] = "profile"
        self.put(d)
        self.assert_code("NO_RULES")

    def test_unknown_rule_metadata_is_not_silently_ignored(self):
        d = rule()
        d["target_os"] = "SomethingElse"
        self.put(d)
        self.assert_code("UNSUPPORTED_FIELD")

    def test_unsupported_system_scope_actions(self):
        for changes, code in [
            ({"system": "unknown"}, "UNSUPPORTED_SYSTEM"),
            ({"config": "User"}, "UNSUPPORTED_SCOPE"),
            ({"config": "Both"}, "UNSUPPORTED_SCOPE"),
            ({"action": "QWORD:1"}, "UNSUPPORTED_ACTION"),
            ({"action": "DELETE"}, "UNSUPPORTED_ACTION"),
            ({"action": True}, "FIELD_TYPE"),
        ]:
            with self.subTest(changes=changes):
                self.put(rule(autos=[registry(**changes)]))
                self.assert_code(code)

    def test_unknown_effectful_fields_rejected(self):
        for field in ["state", "values", "hive", "view", "when"]:
            with self.subTest(field=field):
                self.put(rule(autos=[registry(**{field: "unused"})]))
                self.assert_code("UNSUPPORTED_FIELD")

    def test_registry_path_validation(self):
        for key in [
            "HKLM:\\Software",
            "HKEY_LOCAL_MACHINE\\Software",
            "\\Software",
            "Software\\",
            "Software\\..\\X",
            "Software//X",
            "Software\\\\X",
        ]:
            with self.subTest(key=key):
                self.put(rule(autos=[registry(registry_key=key)]))
                self.assert_code("REGISTRY_PATH")

    def test_dword_bounds(self):
        for value in ["-1", "4294967296", "1.5", "0xFF", "true", ""]:
            with self.subTest(value=value):
                self.put(rule(autos=[registry(action="DWORD:" + value)]))
                self.assert_code("DWORD_RANGE")
        for value in [0, 4294967295]:
            self.put(rule(autos=[registry(action=f"DWORD:{value}")]))
            self.assertEqual(self.analysis().operations[0].value, value)

    def test_sz_and_default_value(self):
        for value in ["", "abc:xyz", "Grüße", r"%ProgramFiles%\app"]:
            with self.subTest(value=value):
                self.put(rule(autos=[registry(value_name="", action="SZ:" + value)]))
                op = self.analysis().operations[0]
                self.assertEqual((op.name, op.type, op.value), ("", "string", value))

    def test_value_name_must_be_explicit(self):
        auto = registry()
        auto.pop("value_name")
        self.put(rule(autos=[auto]))
        self.assert_code("VALUE_NAME")

    def test_templates_and_control_characters_rejected(self):
        for field in ["registry_key", "value_name", "action"]:
            for value in ["{{ lookup('env', 'PATH') }}", "{% if x %}", "{# text #}", "bad\nline"]:
                with self.subTest(field=field, value=value):
                    self.put(rule(autos=[registry(**{field: value})]))
                    self.assertFalse(self.analysis().ok)

    def test_bounds_require_valid_dword_and_remediation(self):
        for limits in [
            {"min": True},
            {"min": "15"},
            {"max": -1},
            {"min": 20},
            {"min": 18, "max": 10},
            {"max": 2**40},
            [],
        ]:
            with self.subTest(limits=limits):
                self.put(rule(autos=[registry(constraints=limits)]))
                self.assert_code("CONSTRAINTS")
        self.put(rule(autos=[registry(constraints={"equal_to": 15})]))
        self.assert_code("UNSUPPORTED_FIELD")
        self.put(rule(autos=[registry(action="SZ:x", constraints={"min": 1})]))
        self.assert_code("CONSTRAINTS")

    def test_compound_is_all_or_nothing(self):
        self.put(rule(autos=[compound(registry(), registry(config="Both"))]))
        r = self.analysis()
        self.assert_code("UNSUPPORTED_SCOPE", r)
        self.assertEqual(r.operations, [])

    def test_nested_compounds(self):
        self.put(rule(autos=[compound(compound(registry()))]))
        self.assertEqual(len(self.analysis().operations), 1)

    def test_deep_compound_rejected(self):
        item = registry()
        for _ in range(18):
            item = compound(item)
        self.put(rule(autos=[item]))
        self.assert_code("NESTING")

    def test_empty_compound_and_bad_shapes(self):
        for item, code in [
            (compound(), "COMPOUND"),
            (None, "AUTOMATION_SHAPE"),
        ]:
            self.put(rule(autos=[item]))
            self.assert_code(code)

    def test_high_level_description_requires_concrete_operations(self):
        gpo = {"system": GPO, "ui_path": "Computer Configuration\\Example", "value": "Enabled"}
        self.put(rule(autos=[gpo]))
        self.assert_code("NO_CONCRETE_IMPLEMENTATION")
        self.put(rule(autos=[gpo, registry()]))
        self.assertTrue(self.analysis().ok)
        self.put(rule(autos=[compound(gpo, registry())]))
        self.assert_code("UNSUPPORTED_SYSTEM")

    def test_legacy_migration_diagnostic(self):
        self.put(rule(autos=[{"system": GPO, "registry_key": "Software\\X", "values": {"V": 1}}]))
        self.assert_code("LEGACY_FORMAT")

    def test_implementation_selection_is_explicit(self):
        d = rule()
        alt = copy.deepcopy(d["implementations"][0])
        alt["relative_id"] = "02"
        alt["automations"][0]["action"] = "DWORD:20"
        d["implementations"].append(alt)
        self.put(d)
        self.assert_code("IMPLEMENTATION_SELECTION")
        r = self.analysis(choices={"example.test/R1": "02"})
        self.assertTrue(r.ok)
        self.assertEqual(r.operations[0].value, 20)
        self.assert_code(
            "IMPLEMENTATION_SELECTION", self.analysis(choices={"example.test/R1": "03"})
        )

    def test_duplicate_implementation_id(self):
        d = rule()
        d["implementations"].append(copy.deepcopy(d["implementations"][0]))
        self.put(d)
        self.assert_code("DUPLICATE_IMPLEMENTATION")

    def test_rule_selection_excludes_unsupported(self):
        self.put(rule("Good"), "a.yml")
        self.put(rule("Bad", [registry(config="Both")]), "b.yml")
        r = self.analysis(rules={"example.test/Good"})
        self.assertTrue(r.ok)
        self.assertEqual(r.report()["summary"]["excluded_rules"], 1)
        self.assert_code("RULE_NOT_FOUND", self.analysis(rules={"example.test/Missing"}))
        self.assert_code(
            "UNUSED_IMPLEMENTATION",
            self.analysis(rules={"example.test/Good"}, choices={"example.test/Bad": "01"}),
        )

    def test_case_insensitive_conflicts_and_deduplication(self):
        self.put(rule("A"), "a.yml")
        self.put(
            rule(
                "B",
                [registry(registry_key=r"software\scapoliteconvertertest", value_name="example")],
            ),
            "b.yml",
        )
        r = self.analysis()
        self.assertTrue(r.ok)
        self.assertEqual(len(r.operations), 1)
        self.assertEqual(len(r.operations[0].origins), 2)
        self.put(rule("B", [registry(action="DWORD:1")]), "b.yml")
        self.assert_code("CONFLICT")

    def test_constraint_conflicts(self):
        self.put(rule("A", [registry(constraints={"min": 15})]), "a.yml")
        self.put(rule("B"), "b.yml")
        self.assert_code("CONFLICT")

    def test_output_order_is_independent_of_input_order(self):
        a = self.put(rule("A"), "a.yml")
        b = self.put(rule("B", [registry(value_name="Other")]), "b.yml")
        self.assertEqual(
            playbook(analyze([str(a), str(b)]).operations),
            playbook(analyze([str(b), str(a)]).operations),
        )

    def test_constraints_read_the_value_being_written(self):
        self.put(rule(autos=[registry(constraints={"min": 10, "max": 20})]))
        tasks = yaml.safe_load(playbook(self.analysis().operations))[0]["tasks"]
        read = next(t for t in tasks if "ansible.windows.win_reg_stat" in t)
        write = next(t for t in tasks if "ansible.windows.win_regedit" in t)
        for field in ("path", "name"):
            self.assertEqual(
                read["ansible.windows.win_reg_stat"][field],
                write["ansible.windows.win_regedit"][field],
            )
        self.assertLess(tasks.index(read), tasks.index(write))
        self.assertIn(read["register"], write["when"])

    def test_cli_success_and_report(self):
        self.put()
        out = self.root / "out.yml"
        report = self.root / "report.json"
        p = self.cli("compile", self.inputs, "-o", out, "--report", report)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(yaml.safe_load(out.read_text())[0]["hosts"], "windows")
        self.assertTrue(json.loads(report.read_text())["output_written"])

    def test_cli_partial_failure_keeps_old_output(self):
        self.put(filename="good.yml")
        self.put(filename="bad.yml", text="x: [")
        out = self.root / "out.yml"
        out.write_bytes(b"old-output")
        p = self.cli("compile", self.inputs, "-o", out)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(out.read_bytes(), b"old-output")

    def test_cli_missing_and_empty_inputs(self):
        for p in [self.inputs, self.root / "missing"]:
            r = self.cli("compile", p, "-o", self.root / "out.yml")
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertFalse((self.root / "out.yml").exists())

    def test_cli_unwritable_output(self):
        self.put()
        out = self.root / "out.yml"
        out.mkdir()
        p = self.cli("compile", self.inputs, "-o", out)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("OUTPUT_WRITE", p.stderr)

    def test_cli_unwritable_report_does_not_publish_playbook(self):
        self.put()
        report = self.root / "report"
        report.mkdir()
        out = self.root / "out.yml"
        p = self.cli("compile", self.inputs, "-o", out, "--report", report)
        self.assertEqual(p.returncode, 3)
        self.assertFalse(out.exists())

    def test_cli_output_failure_updates_report(self):
        self.put()
        out = self.root / "out"
        out.mkdir()
        report = self.root / "report.json"
        p = self.cli("compile", self.inputs, "-o", out, "--report", report)
        self.assertEqual(p.returncode, 3)
        evidence = json.loads(report.read_text())
        self.assertFalse(evidence["ok"])
        self.assertFalse(evidence["output_written"])

    def test_unicode_inspection_output(self):
        self.put(rule(autos=[registry(action="SZ:中文")]))
        p = self.cli("inspect", self.inputs)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["operations"][0]["value"], "中文")

    def test_cli_path_collisions_rejected(self):
        self.put()
        for extra in [
            ["-o", self.inputs / "generated.yml"],
            ["-o", self.root / "same", "--report", self.root / "same"],
            ["-o", self.root / "out", "--report", self.inputs / "report.json"],
        ]:
            p = self.cli("compile", self.inputs, *extra)
            self.assertEqual(p.returncode, 2, p.stderr)

    def test_cli_inspect_reports_unsupported_and_exits_nonzero(self):
        self.put(rule(autos=[registry(config="Both")]))
        p = self.cli("inspect", self.inputs)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(json.loads(p.stdout)["summary"]["unsupported_rules"], 1)

    def test_atomic_replace_failure_preserves_old_file(self):
        target = self.root / "out.yml"
        target.write_bytes(b"original")
        with patch("scapolite_ansible.emit.os.replace", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                atomic_write(target, "new")
        self.assertEqual(target.read_bytes(), b"original")
        self.assertEqual(list(self.root.glob(".scapolite-*")), [])

    def test_compatibility_command(self):
        self.put()
        p = subprocess.run(
            [
                sys.executable,
                str(ROOT / "converter/scapolite2ansible.py"),
                "-i",
                str(self.inputs),
                "-o",
                str(self.root / "out.yml"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == "__main__":
    unittest.main()
