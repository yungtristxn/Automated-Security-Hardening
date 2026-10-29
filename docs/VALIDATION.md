# Testing

## Python tests

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python -m ruff check scapolite_ansible converter scripts tests
python -m ruff format --check scapolite_ansible converter scripts tests
```

The suite covers input parsing, supported operations, selection, conflicts and CLI
failure behavior. The upstream BitLocker fixture checks the complete policy mapping.

## Ansible integration

On Linux:

```sh
python -m pip install -r requirements-controller.txt
ansible-galaxy collection install -r collections/requirements.yml
python scripts/verify_ansible.py
```

This checks module resolution and playbook syntax, then evaluates generated
conditions with simulated registry results. Cases cover missing values, wrong
types, min/max boundaries and preservation of stricter compliant values.
It does not contact Windows. Results are saved under `local/ansible-validation`.

## Upstream compatibility

The Server 2019 research corpus is fetched separately, with its original license:

```sh
git clone https://github.com/tum-i4/disa-windows-server-2019.git local/server2019-corpus
git -C local/server2019-corpus checkout --detach e3a8b93ab054e38b2b545e611ff9d9073e35c5f2
python scripts/verify_corpus.py local/server2019-corpus
ansible-playbook -i 'windows,' local/corpus-validation/selected.yml --syntax-check
```

The pinned corpus is a compatibility baseline. The verifier checks the supported
selection and independently compares each emitted path, value name, type and data
against the source. Reports and generated output go under `local/corpus-validation`.

## Package installation

```sh
python -m build
```

Install the wheel in a fresh virtual environment and compile the bundled example
from outside the checkout. CI performs this check alongside Windows/Linux Python
tests and Linux Ansible checks. CI does not deploy to Windows targets.

## Windows VM tests

**Not yet run for version 0.1.0.** Syntax checks and simulated conditions do not
prove registry application or idempotence on Windows.

Use a disposable Windows x64 VM with a snapshot, administrator access and HTTPS
WinRM. The private inventory must contain exactly one `windows` host. Supply
credentials through the controller's Ansible Vault configuration or equivalent.

```sh
python scripts/verify_windows.py --inventory local/lab.yml --limit disposable-win --confirm-disposable
```

The harness uses `HKLM:\Software\ScapoliteConverterAcceptance`. It tests absent,
wrongly typed, out-of-bounds and already-compliant values. Each case checks that
`--check` leaves state unchanged, applies the generated playbook, verifies types
and values through .NET registry APIs, and requires a second apply to make no changes.
It removes the test key afterwards. Logs are saved under `local/windows-validation`.

Restore the snapshot after testing. Actual BitLocker policy behavior needs a
separate test on a suitable Windows build; the registry harness does not prove it.
