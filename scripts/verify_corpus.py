"""Verify the pinned external research corpus without vendoring its GPL content.

An independent extraction checks every compiled operation against its source.
No generated playbook is executed.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import yaml

from scapolite_ansible.compiler import analyze
from scapolite_ansible.emit import playbook

COMMIT = "e3a8b93ab054e38b2b545e611ff9d9073e35c5f2"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Checkout of tum-i4/disa-windows-server-2019")
    parser.add_argument("--output-dir", type=Path, default=Path("local/corpus-validation"))
    args = parser.parse_args()
    head = subprocess.check_output(
        ["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != COMMIT:
        parser.error(f"Expected corpus commit {COMMIT}; got {head}")
    corpus = args.source / "scapolite"
    result = analyze([str(corpus)])
    summary = result.report()["summary"]
    assert summary["documents"] == 422 and summary["selected_rules"] == 205, summary
    # This pinned dataset is the compatibility baseline for the documented subset.
    assert summary["supported_rules"] == 40, summary
    selected = {d["rule"] for d in result.documents if d["status"] == "supported"}
    compiled = analyze([str(corpus)], selected)
    assert compiled.ok, compiled.report()
    expected = []

    def visit(items):
        for item in items:
            if item["system"] == "org.scapolite.automation.compound":
                yield from visit(item["automations"])
            elif item["system"] == "org.scapolite.implementation.windows_registry":
                assert item["config"] == "Computer"
                kind, value = item["action"].split(":", 1)
                assert kind in {"DWORD", "SZ"}
                yield (
                    "HKLM:\\" + item["registry_key"],
                    item["value_name"],
                    "dword" if kind == "DWORD" else "string",
                    int(value) if kind == "DWORD" else value,
                )

    for row in result.documents:
        if row["rule"] not in selected:
            continue
        # Independent reader intentionally does not call the production parser.
        lines = (corpus / row["source"]).read_text(encoding="utf-8").splitlines()
        end = lines.index("---", 1)
        data = yaml.safe_load("\n".join(lines[1:end]))
        assert len(data["implementations"]) == 1
        expected.extend(visit(data["implementations"][0]["automations"]))
    actual = [(o.path, o.name, o.type, o.value) for o in compiled.operations]
    assert sorted(actual) == sorted(set(expected)), (actual, expected)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "selected.yml").write_text(playbook(compiled.operations), encoding="utf-8")
    (args.output_dir / "selection.txt").write_text(
        "\n".join(sorted(selected)) + "\n", encoding="utf-8"
    )
    (args.output_dir / "inspection.json").write_text(
        json.dumps(result.report(), indent=2), encoding="utf-8"
    )
    evidence = {
        "ok": True,
        "source_commit": head,
        **summary,
        "verified_operations": len(actual),
        "selected_compile_ok": compiled.ok,
        "windows_execution": False,
    }
    (args.output_dir / "results.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence))


if __name__ == "__main__":
    main()
