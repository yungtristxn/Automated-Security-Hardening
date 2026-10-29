#!/usr/bin/env python3
"""Compatibility command for the original -i INPUT -o OUTPUT invocation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scapolite_ansible.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["compile", *sys.argv[1:]]))
