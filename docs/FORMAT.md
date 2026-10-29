# Input format

## Example

```yaml
scapolite:
  class: rule
  version: '0.51'
id: minimum_length
id_namespace: org.example
title: Minimum password length
implementations:
  - relative_id: '01'
    automations:
      - system: org.scapolite.implementation.windows_registry
        config: Computer
        registry_key: Software\Example
        value_name: MinimumLength
        action: DWORD:15
        constraints:
          min: 15
```

This example emits an HKLM registry operation. An existing DWORD of 15 or higher
is retained; otherwise the playbook writes 15.

## Files and selection

Inputs may be YAML files or Markdown with a YAML preamble enclosed by column-zero
`---` delimiters. Text after the closing delimiter is documentation. Delimiters
inside quoted text or indented block scalars are not treated as boundaries.

Directories are scanned recursively for `.md`, `.yml` and `.yaml`, ignoring case.
`.git`, `.venv` and `__pycache__` are excluded. Symlinks found within an input tree
cause an error; explicitly supplied file paths are resolved normally. Files must
be UTF-8 (BOM allowed), at most 1 MiB. Duplicate mapping keys, aliases, merge keys
and non-string keys are rejected. Plain `on/off/yes/no` and dates remain strings.

Supported document version: the string `'0.51'`. Rule identity is `id_namespace/id`.
Identifiers and implementation IDs allow ASCII letters, digits, `.`, `:`, `-` and `_`.
Duplicate identities are errors. Groups, collections and profiles are counted but
not expanded; at least one rule must be selected.

Supplying a directory selects every rule. Repeat `--rule namespace/id` to narrow
the selection. Malformed documents and duplicate identities still fail the run.
For rules with multiple implementations, choose one explicitly:

```sh
scapolite-ansible compile guide --rule org.example/R1 --implementation org.example/R1=02 -o generated/playbook.yml
```

Rules accept identity fields, `scapolite`, `title`, `rule`, `description`,
`rationale`, `applicability`, `implementations`, `checks`, `crossrefs` and `history`.
Unknown fields are rejected. Applicability and checks are not evaluated; the
operator is responsible for selecting suitable targets.

## Operations

`org.scapolite.implementation.windows_registry` supports:

| Field | Supported values |
| --- | --- |
| `config` | `Computer` |
| `registry_key` | Relative HKLM path; no hive prefix, `/`, empty components, `.` or `..` |
| `value_name` | Required string; `''` targets the default value |
| `action` | `DWORD:<decimal>` from 0 to 4294967295, or `SZ:<literal text>` |
| `constraints` | Optional integer `min` and/or `max`, for DWORD only |

Operations set values (`state: present`). Deletion, including `DWORD:NOT_SET`,
and other registry types/scopes are unsupported. The remediation value must satisfy
its bounds. Without constraints it is enforced exactly; with constraints a correctly
typed value already within bounds is retained. Unknown constraints fail compilation.

Control characters and Jinja delimiters (`{{`, `{%`, `{#`) are rejected in emitted
paths, names and data. Optional annotations are `relative_id`, `description`,
`verification_status` and `checksum`; unknown operation fields are rejected.

`org.scapolite.automation.compound` contains a nonempty `automations` list. Every
child must be supported; nesting is limited to 16 levels. Unsupported children
fail the whole selected implementation.

A top-level `win_gpo` description with `ui_path` and `value` may accompany concrete
operations in the same implementation. It is not translated or checked for
equivalence. GPO-only implementations and GPO entries inside compounds are rejected.

Identical writes to the same case-insensitive key/value name are deduplicated and
retain their origins. Different values, types or constraints for that location
are conflicts. File order cannot resolve a conflict.

## Output and errors

`inspect` prints JSON. Both commands accept `--report PATH`. Reports include source
hashes, selection status, operations, origins and diagnostics with source locations.
An inspect report may describe supported operations while reporting `ok: false`.

| Exit code | Meaning |
| --- | --- |
| 0 | The selected input is supported and the requested command succeeded |
| 2 | Invalid arguments/input, unsupported rule, conflict or empty selection |
| 3 | Output/report I/O failed |

Compile validates the selection before atomically replacing the playbook.
Validation failures preserve old output. Always check the exit code:
`output_written` and a successful `output_sha256` identify the current artifact.
Report and playbook writes are separate; a report failure after playbook publication
can leave a new playbook with exit code 3.

Output/report paths must differ and be outside the input tree, so generated files
cannot overwrite or be re-read as sources.

## Migrating older input

The original `win_gpo` plus `registry_key`/`values` mapping produces `LEGACY_FORMAT`.
Convert each entry to a typed `windows_registry` operation, declare `config: Computer`
and group multiple operations in a compound. Choose registry types explicitly.

The bundled `rules/passwortrichtlinie.yml` shows the migrated BitLocker example,
including `RDVPassphrase=1`. The original command remains supported:

```sh
python converter/scapolite2ansible.py -i rules -o generated/hardening.yml
```
