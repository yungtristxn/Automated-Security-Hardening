"""Opt-in disposable Windows VM acceptance. Never runs in pull-request CI."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scapolite_ansible.compiler import analyze
from scapolite_ansible.emit import playbook


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument(
        "--limit", required=True, help="Exactly one disposable Windows inventory host"
    )
    parser.add_argument("--confirm-disposable", action="store_true", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("local/windows-validation"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    analysis = analyze([str(root / "tests/integration/registry-fixture.yml")])
    if not analysis.ok:
        raise RuntimeError(analysis.report())
    generated = out / "generated.yml"
    generated.write_text(playbook(analysis.operations), encoding="utf-8")
    fixture = root / "tests/integration/windows-fixture.yml"
    history = []
    common = [
        "-i",
        str(args.inventory.resolve()),
        "--limit",
        args.limit,
        "-e",
        "scapolite_disposable_vm=true",
    ]

    def run(path, extra=None, require_unchanged=False):
        command = ["ansible-playbook", *common, str(path), *(extra or [])]
        process = subprocess.run(command, capture_output=True, text=True, timeout=300)
        history.append(
            {
                "playbook": str(path),
                "arguments": extra or [],
                "exit": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr,
            }
        )
        if process.returncode:
            raise RuntimeError(process.stdout + process.stderr)
        recap = process.stdout.split("PLAY RECAP")[-1]
        matches = re.findall(r"changed=(\d+).*unreachable=(\d+).*failed=(\d+)", recap)
        if len(matches) != 1 or any(int(n) for n in matches[0][1:]):
            raise RuntimeError(
                "Expected exactly one reachable successful host in the Ansible recap"
            )
        if require_unchanged and int(matches[0][0]):
            raise RuntimeError("Idempotence failed: repeated apply changed the target")

    def state(mode, scenario):
        run(fixture, ["-e", f"fixture_mode={mode}", "-e", f"fixture_scenario={scenario}"])

    report = {"ok": False, "windows_execution": True}
    try:
        for scenario in ("absent", "wrong_type", "outside", "compliant"):
            state("Seed", scenario)
            run(generated, ["--check", "--diff"], require_unchanged=scenario == "compliant")
            state("Baseline", scenario)
            run(generated, require_unchanged=scenario == "compliant")
            state("Applied", scenario)
            run(generated, require_unchanged=True)
            state("Applied", scenario)
        report["ok"] = True
        report["scenarios"] = 4
    except Exception as exc:
        report["error"] = str(exc)
    finally:
        try:
            state("Cleanup", "absent")
            state("Baseline", "absent")
            report["fixture_cleanup_verified"] = True
        except Exception as exc:
            report["ok"] = False
            report["cleanup_error"] = str(exc)
        report["runs"] = history
        (out / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "runs"}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
