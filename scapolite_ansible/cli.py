import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import __version__
from .compiler import analyze
from .emit import atomic_write, playbook
from .model import Diagnostic


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(
        description="Compile a validated Scapolite 0.51 Windows registry subset"
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "compile"):
        command = commands.add_parser(name)
        command.add_argument("inputs", nargs="*", help="Scapolite files or directories")
        command.add_argument(
            "-i", "--input", action="append", default=[], help="Additional input file/directory"
        )
        command.add_argument(
            "--rule", action="append", help="Select namespace/id; repeat for multiple rules"
        )
        command.add_argument("--implementation", action="append", default=[], metavar="RULE=ID")
        command.add_argument(
            "--report", type=Path, help="Write a JSON report, including validation failures"
        )
        if name == "compile":
            command.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = args.inputs + args.input
    if not inputs:
        parser.error("at least one input file/directory is required")
    choices = {}
    for choice in args.implementation:
        rule, sep, impl = choice.partition("=")
        if not sep or not rule or not impl or rule in choices:
            parser.error("--implementation must be a unique namespace/id=relative_id")
        choices[rule] = impl
    output = getattr(args, "output", None)
    destinations = [p.resolve() for p in (output, args.report) if p is not None]
    if len(set(destinations)) != len(destinations):
        parser.error("playbook and report must use different paths")
    for target in destinations:
        for source in map(lambda p: Path(p).resolve(), inputs):
            if target == source or (source.is_dir() and target.is_relative_to(source)):
                parser.error("output/report must be outside the input files and directories")
    result = analyze(inputs, set(args.rule) if args.rule is not None else None, choices)
    report = result.report()
    report["command"] = args.command
    report["output_written"] = False
    try:
        # A preliminary report cannot claim that a previous playbook is new.
        if args.report:
            atomic_write(args.report, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        if args.command == "compile" and result.ok:
            rendered = playbook(result.operations)
            atomic_write(output, rendered)
            report["output_written"] = True
            report["output_sha256"] = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
            if args.report:
                atomic_write(args.report, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    except OSError as exc:
        report["ok"] = False
        report["diagnostics"].append(
            Diagnostic("OUTPUT_WRITE", str(exc), str(output or args.report)).to_dict()
        )
        if args.report:
            try:
                atomic_write(args.report, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
            except OSError:
                pass  # The original I/O failure is reported on stderr and through exit 3.
        for d in report["diagnostics"]:
            print(f"{d['source']}: {d['code']}: {d['message']}", file=sys.stderr)
        return 3
    if args.command == "inspect":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for d in result.diagnostics:
            print(
                f"{d.source}:{d.line or '?'}: {d.code} [{d.rule or '-'} / {d.field}]: {d.message}",
                file=sys.stderr,
            )
        if result.ok:
            print(
                f"Compiled {report['summary']['supported_rules']} rules into {len(result.operations)} registry operations: {output}"
            )
    return 0 if result.ok else 2
