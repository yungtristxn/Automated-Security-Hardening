# Scapolite to Ansible

Convert Scapolite 0.51 security rules—YAML with optional Markdown documentation—into
Ansible playbooks for Windows. The converter validates selected rules, rejects
conflicting settings and reports where each registry operation came from.

## Quick start

From a checkout, with Python 3.12 or newer:

```sh
python -m venv .venv
```

Activate with `.venv\Scripts\Activate.ps1` in PowerShell or
`source .venv/bin/activate` in bash/zsh, then run:

```sh
python -m pip install .
scapolite-ansible inspect rules
scapolite-ansible compile rules -o generated/hardening.yml --report generated/report.json
```

These commands inspect the [bundled BitLocker rule](rules/passwortrichtlinie.yml)
and create:

- `generated/hardening.yml`: a playbook for the policy-enable, complexity and length values.
- `generated/report.json`: rule status, source locations and the generated operations.

Generation runs on Windows and Linux without connecting to a target machine.

To select a rule from a larger guide:

```sh
scapolite-ansible compile path/to/guide --rule namespace/RULE_ID -o generated/selected.yml
```

Validation errors leave any previous playbook untouched. Always check the command's
exit code before applying output; an old file may still exist after a failed run.
See [input format, selection and migration](docs/FORMAT.md) for the full contract.

## Scope

- Reads YAML and Markdown with YAML front matter, including nested rule directories.
- Supports `windows_registry` with `config: Computer`, `DWORD` and `SZ`, plus compounds.
- Retains correctly typed values within `min`/`max` bounds; otherwise applies the rule's value.
- Reports unsupported rules, conflicting writes and source locations in JSON.

User/Both scopes, deletion, other registry types, GPO translation, SecEdit, audit
policies, scripts and profile expansion are not supported. Existing GPO descriptions
may accompany concrete operations, but their equivalence is not checked. Source
applicability and OVAL checks are not evaluated.

## Applying a playbook

On a Linux Ansible controller, install the execution dependencies:

```sh
python -m pip install -r requirements-controller.txt
ansible-galaxy collection install -r collections/requirements.yml
```

Copy the [example inventory](inventory.ini) to `local/inventory.ini`, replace its
placeholders and configure the Windows target for HTTPS WinRM with a trusted
server certificate. Review the playbook, preview its changes, then apply:

```sh
ansible-playbook -i local/inventory.ini generated/hardening.yml --ask-pass --check --diff
ansible-playbook -i local/inventory.ini generated/hardening.yml --ask-pass
```

**Live Windows application and idempotence are not yet verified for this version.**
The [testing guide](docs/VALIDATION.md) covers controller setup, regression tests,
upstream fixtures and the disposable-VM harness. CI runs validation only.

The BitLocker example configures policy values, not drive encryption. Domain GPOs
can override local changes.

## Background

Based on Patrick Stoeckle's
[*A Holistic Approach for Security Configuration*](https://mediatum.ub.tum.de/doc/1720520/o8whmro5ta7zmi35mvbv3ehon.dissertation-stoeckle.pdf)
and the authors' [Scapolite examples](https://github.com/tum-i4/CODASPY2022).
Upstream fixture attribution is in `tests/fixtures/upstream`. Historical guides
serve as test data, not current deployment recommendations.

[Apache-2.0 license](LICENSE).
