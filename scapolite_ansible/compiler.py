"""Validate and select complete implementations, then normalize registry writes."""

import re

from .model import Analysis, Diagnostic, Document, InvalidInput, Origin, RegistryOperation
from .parser import IDENTIFIER, discover, load_document

REGISTRY = "org.scapolite.implementation.windows_registry"
COMPOUND = "org.scapolite.automation.compound"
GPO = "org.scapolite.implementation.win_gpo"
ANNOTATIONS = {"relative_id", "description", "verification_status", "checksum"}


def literal(doc: Document, value, field: str, empty=False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        doc.fail(
            "FIELD_TYPE",
            "Expected a string" + (" (may be empty)" if empty else " that is not empty"),
            field,
        )
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        doc.fail("CONTROL_CHARACTER", "Control characters are unsupported", field)
    if any(token in value for token in ("{{", "{%", "{#")):
        doc.fail("TEMPLATE", "Ansible/Jinja templates are not supported in literal input", field)
    return value


def fields(doc: Document, obj: dict, allowed: set[str], field: str) -> None:
    unknown = sorted(set(obj) - allowed)
    if unknown:
        doc.fail(
            "UNSUPPORTED_FIELD",
            f"Unsupported field(s): {', '.join(unknown)}",
            f"{field}.{unknown[0]}",
        )


def automation(
    doc: Document, item, field: str, implementation: str, depth=0
) -> list[RegistryOperation]:
    if depth > 16:
        doc.fail("NESTING", "Compound nesting exceeds 16 levels", field)
    if not isinstance(item, dict):
        doc.fail("AUTOMATION_SHAPE", "Automation must be a mapping", field)
    system = item.get("system")
    if system == COMPOUND:
        fields(doc, item, {"system", "automations"} | ANNOTATIONS, field)
        children = item.get("automations")
        if not isinstance(children, list) or not children:
            doc.fail(
                "COMPOUND", "Compound requires a nonempty automations list", f"{field}.automations"
            )
        return [
            op
            for i, child in enumerate(children)
            for op in automation(doc, child, f"{field}.automations[{i}]", implementation, depth + 1)
        ]
    if system != REGISTRY:
        doc.fail(
            "UNSUPPORTED_SYSTEM", f"Unsupported automation system: {system!r}", f"{field}.system"
        )
    fields(
        doc,
        item,
        {"system", "config", "registry_key", "value_name", "action", "constraints"} | ANNOTATIONS,
        field,
    )
    if item.get("config") != "Computer":
        doc.fail(
            "UNSUPPORTED_SCOPE",
            "Only config: Computer is supported; User/Both need explicit user-target semantics",
            f"{field}.config",
        )
    key = literal(doc, item.get("registry_key"), f"{field}.registry_key")
    parts = key.split("\\")
    if (
        ":" in key
        or "/" in key
        or any(p in {"", ".", ".."} for p in parts)
        or re.match(r"(?i)^(HKLM|HKCU|HKU|HKCR|HKCC|HKEY_.*)$", parts[0])
    ):
        doc.fail(
            "REGISTRY_PATH",
            "Expected a relative HKLM key without a hive, empty segments, . or ..",
            f"{field}.registry_key",
        )
    if "value_name" not in item:
        doc.fail(
            "VALUE_NAME",
            "value_name is required; use an explicit empty string for the default value",
            f"{field}.value_name",
        )
    name = literal(doc, item["value_name"], f"{field}.value_name", empty=True)
    action = literal(doc, item.get("action"), f"{field}.action")
    kind, separator, payload = action.partition(":")
    if not separator or kind not in {"DWORD", "SZ"}:
        doc.fail(
            "UNSUPPORTED_ACTION",
            "Supported actions are DWORD:<decimal> and SZ:<literal>",
            f"{field}.action",
        )
    if kind == "DWORD":
        if payload == "NOT_SET":
            doc.fail(
                "UNSUPPORTED_ACTION",
                "DWORD:NOT_SET requires deletion semantics, outside this set-only subset",
                f"{field}.action",
            )
        if not re.fullmatch(r"[0-9]+", payload) or len(payload) > 10 or int(payload) > 0xFFFFFFFF:
            doc.fail(
                "DWORD_RANGE",
                "DWORD must be a decimal integer from 0 to 4294967295",
                f"{field}.action",
            )
        value = int(payload)
    else:
        value = payload
    limits = item.get("constraints", {})
    if not isinstance(limits, dict):
        doc.fail("CONSTRAINTS", "constraints must be a mapping", f"{field}.constraints")
    fields(doc, limits, {"min", "max"}, f"{field}.constraints")
    if limits and kind != "DWORD":
        doc.fail("CONSTRAINTS", "min/max constraints require DWORD", f"{field}.constraints")
    for bound, number in limits.items():
        if type(number) is not int or not 0 <= number <= 0xFFFFFFFF:
            doc.fail(
                "CONSTRAINTS",
                "Bounds must be DWORD-range decimal integers",
                f"{field}.constraints.{bound}",
            )
    minimum, maximum = limits.get("min"), limits.get("max")
    if kind == "DWORD" and not (limits.get("min", 0) <= value <= limits.get("max", 0xFFFFFFFF)):
        doc.fail(
            "CONSTRAINTS", "The remediation value must satisfy min/max", f"{field}.constraints"
        )
    return [
        RegistryOperation(
            "HKLM:\\" + key,
            name,
            "dword" if kind == "DWORD" else "string",
            value,
            minimum,
            maximum,
            [Origin(doc.source, doc.key, implementation, field)],
        )
    ]


def compile_rule(doc: Document, choice: str | None) -> tuple[list[RegistryOperation], list[str]]:
    fields(
        doc,
        doc.data,
        {
            "scapolite",
            "id",
            "id_namespace",
            "title",
            "rule",
            "description",
            "rationale",
            "applicability",
            "implementations",
            "checks",
            "crossrefs",
            "history",
        },
        "",
    )
    if not isinstance(doc.data.get("title"), str) or not doc.data["title"].strip():
        doc.fail("FIELD_TYPE", "title must be a nonempty string", "title")
    implementations = doc.data.get("implementations")
    if not isinstance(implementations, list) or not implementations:
        doc.fail(
            "IMPLEMENTATIONS", "A rule needs a nonempty implementations list", "implementations"
        )
    ids = []
    for i, implementation in enumerate(implementations):
        where = f"implementations[{i}]"
        if not isinstance(implementation, dict):
            doc.fail("IMPLEMENTATION_SHAPE", "Implementation must be a mapping", where)
        ident = implementation.get("relative_id")
        if not isinstance(ident, str) or not IDENTIFIER.fullmatch(ident):
            doc.fail(
                "IMPLEMENTATION_ID",
                "relative_id must be a nonempty string identifier",
                where + ".relative_id",
            )
        if ident in ids:
            doc.fail(
                "DUPLICATE_IMPLEMENTATION",
                f"Duplicate implementation ID: {ident}",
                where + ".relative_id",
            )
        ids.append(ident)
    if choice is None and len(ids) > 1:
        doc.fail(
            "IMPLEMENTATION_SELECTION",
            "Multiple implementations; select one using --implementation namespace/id=relative_id",
            "implementations",
        )
    if choice is not None and choice not in ids:
        doc.fail("IMPLEMENTATION_SELECTION", f"Unknown implementation: {choice}", "implementations")
    index = ids.index(choice) if choice is not None else 0
    selected = implementations[index]
    base = f"implementations[{index}]"
    fields(doc, selected, {"relative_id", "description", "automations"}, base)
    autos = selected.get("automations")
    if not isinstance(autos, list) or not autos:
        doc.fail(
            "AUTOMATIONS", "Implementation needs a nonempty automations list", base + ".automations"
        )
    operations = []
    notes = []
    for i, item in enumerate(autos):
        field = f"{base}.automations[{i}]"
        if isinstance(item, dict) and item.get("system") == GPO:
            if "registry_key" in item or "values" in item:
                doc.fail(
                    "LEGACY_FORMAT",
                    "Legacy win_gpo registry mapping: migrate to windows_registry with config, value_name and typed action (see docs/FORMAT.md)",
                    field,
                )
            fields(
                doc,
                item,
                {
                    "system",
                    "ui_path",
                    "value",
                    "constraints",
                    "error",
                    "error_class",
                    "error_hint",
                    "candidates",
                }
                | ANNOTATIONS,
                field,
            )
            if not isinstance(item.get("ui_path"), str) or not item["ui_path"].strip():
                doc.fail(
                    "GPO_DESCRIPTION", "ui_path must be a nonempty description", field + ".ui_path"
                )
            if "value" not in item:
                doc.fail("GPO_DESCRIPTION", "A descriptive win_gpo entry must include value", field)
            notes.append(
                "High-level win_gpo is not translated; the concrete representation in this implementation is used."
            )
            continue
        operations.extend(automation(doc, item, field, ids[index]))
    if not operations:
        doc.fail(
            "NO_CONCRETE_IMPLEMENTATION",
            "No supported concrete registry implementation; GPO paths are not translated",
            base,
        )
    if doc.data.get("applicability"):
        notes.append(
            "Source applicability is not evaluated; choosing suitable target machines is the operator's responsibility."
        )
    if doc.data.get("checks"):
        notes.append(
            "Source checks are not executed or translated; this is not an OVAL/compliance engine."
        )
    return operations, sorted(set(notes))


def analyze(
    inputs: list[str], rules: set[str] | None = None, choices: dict[str, str] | None = None
) -> Analysis:
    result = Analysis()
    choices = choices or {}
    try:
        files, base = discover(inputs)
    except (InvalidInput, OSError) as exc:
        result.diagnostics.append(
            exc.diagnostic
            if isinstance(exc, InvalidInput)
            else Diagnostic("INPUT_READ", str(exc), ", ".join(inputs))
        )
        return result
    seen: dict[str, str] = {}
    found_rules = set()
    candidates = []
    for path in files:
        source = path.relative_to(base).as_posix()
        try:
            doc = load_document(path, source)
            if doc.key in seen:
                doc.fail(
                    "DUPLICATE_ID",
                    f"Duplicate document identity, also defined in {seen[doc.key]}",
                    "id",
                )
            seen[doc.key] = source
            row = {
                "source": source,
                "sha256": doc.sha256,
                "rule": doc.key,
                "class": doc.data["scapolite"]["class"],
                "status": "non_rule",
            }
            result.documents.append(row)
            if row["class"] != "rule":
                continue
            found_rules.add(doc.key)
            if rules is not None and doc.key not in rules:
                row["status"] = "excluded"
                continue
            row["status"] = "unsupported"
            operations, notes = compile_rule(doc, choices.get(doc.key))
            row.update(
                status="supported",
                notes=notes,
                operation_count=len(operations),
                implementation=operations[0].origins[0].implementation,
            )
            candidates.extend(operations)
        except InvalidInput as exc:
            if not any(row["source"] == source for row in result.documents):
                result.documents.append(
                    {
                        "source": source,
                        "rule": exc.diagnostic.rule,
                        "class": None,
                        "status": "invalid",
                    }
                )
            result.diagnostics.append(exc.diagnostic)
    for key in sorted((rules or set()) - found_rules):
        result.diagnostics.append(
            Diagnostic("RULE_NOT_FOUND", f"Selected rule not found: {key}", "<selection>", rule=key)
        )
    selected = found_rules if rules is None else rules & found_rules
    for key in sorted(choices.keys() - selected):
        result.diagnostics.append(
            Diagnostic(
                "UNUSED_IMPLEMENTATION",
                f"Implementation choice is not for a selected rule: {key}",
                "<selection>",
                rule=key,
            )
        )
    if not selected and not result.diagnostics:
        result.diagnostics.append(
            Diagnostic("NO_RULES", "No rule documents selected", "<selection>")
        )
    merged: dict[tuple, RegistryOperation] = {}
    for op in sorted(candidates, key=lambda o: (o.key, o.path, o.name, o.origins[0].rule)):
        previous = merged.get(op.key)
        if previous is None:
            merged[op.key] = op
        elif previous.semantics != op.semantics:
            origin = op.origins[0]
            result.diagnostics.append(
                Diagnostic(
                    "CONFLICT",
                    f"Conflicting registry operation for {op.path} / {op.name!r}; also requested by {previous.origins[0].rule}",
                    origin.source,
                    origin.field,
                    rule=origin.rule,
                )
            )
        else:
            previous.origins.extend(op.origins)
    result.operations = list(merged.values())
    return result
