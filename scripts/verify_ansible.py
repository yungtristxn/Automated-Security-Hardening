"""Linux controller checks: real module resolution and real Ansible conditions.

No Windows hosts are contacted. The conditions use simulated win_reg_stat data.
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
from scapolite_ansible.model import Origin, RegistryOperation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("local/ansible-validation"))
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    inventory = out / "syntax-inventory.ini"
    inventory.write_text("[windows]\nfixture ansible_host=192.0.2.1\n", encoding="utf-8")
    commands = []

    def run(command):
        p = subprocess.run(command, capture_output=True, text=True, timeout=120)
        commands.append(
            {"command": command, "exit": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
        )
        if p.returncode:
            raise RuntimeError(p.stdout + p.stderr)

    try:
        for label, path in [
            ("bundled", root / "rules"),
            ("upstream", root / "tests/fixtures/upstream/bitlocker.md"),
            ("acceptance", root / "tests/integration/registry-fixture.yml"),
        ]:
            analysis = analyze([str(path)])
            if not analysis.ok:
                raise RuntimeError(json.dumps(analysis.report()))
            target = out / (label + ".yml")
            target.write_text(playbook(analysis.operations), encoding="utf-8")
            run(["ansible-playbook", "-i", str(inventory), str(target), "--syntax-check"])

        tasks = []
        # Expected results are explicit so the test does not repeat the emitter's logic.
        for label, lower, upper, desired, cases in [
            (
                "minimum",
                15,
                None,
                15,
                [(None, True), ("15", True), (14, True), (15, False), (16, False)],
            ),
            (
                "maximum",
                None,
                10,
                10,
                [(None, True), ("10", True), (9, False), (10, False), (11, True)],
            ),
            ("range", 10, 20, 15, [(9, True), (10, False), (15, False), (20, False), (21, True)]),
            ("zero", 0, 0, 0, [(None, True), (0, False), (1, True)]),
        ]:
            op = RegistryOperation(
                r"HKLM:\Software\ScapoliteConverterAcceptance",
                label,
                "dword",
                desired,
                lower,
                upper,
                [Origin("fixture", "example.test/conditions", "01", "test")],
            )
            generated = yaml.safe_load(playbook([op]))[0]["tasks"]
            read = next(t for t in generated if "ansible.windows.win_reg_stat" in t)
            write = next(t for t in generated if "ansible.windows.win_regedit" in t)
            var = read["register"]
            condition = write["when"]
            for value, expected in cases:
                state = {"exists": value is not None}
                if value is not None:
                    state.update(
                        type="REG_SZ" if isinstance(value, str) else "REG_DWORD", value=value
                    )
                tasks.append(
                    {
                        "name": f"{label}: {value!r}",
                        "ansible.builtin.assert": {
                            "that": [f"({condition}) == {'true' if expected else 'false'}"],
                            "quiet": True,
                        },
                        "vars": {var: state},
                    }
                )
        condition_file = out / "conditions.yml"
        condition_file.write_text(
            yaml.safe_dump(
                [
                    {
                        "name": "Evaluate generated conditions with simulated registry results",
                        "hosts": "localhost",
                        "gather_facts": False,
                        "tasks": tasks,
                    }
                ],
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(condition_file)])
        run(
            [
                "ansible-playbook",
                "-i",
                str(inventory),
                str(root / "tests/integration/windows-fixture.yml"),
                "--syntax-check",
            ]
        )
        report = {
            "ok": True,
            "syntax_playbooks": 4,
            "condition_cases": len(tasks),
            "windows_execution": False,
            "commands": commands,
        }
    except Exception as exc:
        report = {"ok": False, "error": str(exc), "windows_execution": False, "commands": commands}
    (out / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "commands"}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
