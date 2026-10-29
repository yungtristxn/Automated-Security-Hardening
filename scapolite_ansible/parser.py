"""Input discovery and strict YAML front matter; no executable YAML tags/aliases."""

import hashlib
import os
import re
from pathlib import Path

import yaml

from .model import Diagnostic, Document, InvalidInput

MAX_BYTES = 1024 * 1024
EXTENSIONS = {".md", ".yml", ".yaml"}
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]+\Z")


class MarkedMap(dict):
    pass


class StrictLoader(yaml.SafeLoader):
    line_offset = 0

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.constructor.ConstructorError(
                None, None, "YAML aliases are not supported", event.start_mark
            )
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        mapping = MarkedMap()
        mapping.line = node.start_mark.line + self.line_offset + 1
        mapping.lines = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    None, None, "Mapping keys must be strings", key_node.start_mark
                )
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    None, None, f"Duplicate mapping key: {key}", key_node.start_mark
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
            mapping.lines[key] = key_node.start_mark.line + self.line_offset + 1
        return mapping


# on/off/yes/no and dates stay strings; leading-zero integers are not octal.
StrictLoader.yaml_implicit_resolvers = {
    key: [
        (tag, pattern)
        for tag, pattern in entries
        if tag
        not in {"tag:yaml.org,2002:bool", "tag:yaml.org,2002:int", "tag:yaml.org,2002:timestamp"}
    ]
    for key, entries in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$", re.IGNORECASE), list("tTfF")
)
StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"^[-+]?(?:0|[1-9][0-9]*)$"), list("-+0123456789")
)
StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, StrictLoader.construct_mapping
)


def discover(inputs: list[str]) -> tuple[list[Path], Path]:
    if not inputs:
        raise InvalidInput(Diagnostic("NO_INPUT", "At least one input is required", "<selection>"))
    paths = [Path(p).resolve() for p in inputs]
    files: set[Path] = set()
    roots = []
    for path in paths:
        if not path.exists():
            raise InvalidInput(Diagnostic("INPUT_NOT_FOUND", "Input does not exist", str(path)))
        roots.append(path if path.is_dir() else path.parent)
        if path.is_file():
            if path.suffix.lower() not in EXTENSIONS:
                raise InvalidInput(
                    Diagnostic("INPUT_EXTENSION", "Expected .md, .yml or .yaml", str(path))
                )
            files.add(path)
        elif path.is_dir():

            def on_error(error):
                raise error

            for directory, dirs, names in os.walk(path, followlinks=False, onerror=on_error):
                for name in dirs + names:
                    candidate = Path(directory) / name
                    if candidate.is_symlink():
                        raise InvalidInput(
                            Diagnostic(
                                "INPUT_SYMLINK",
                                "Symlinks inside an input directory are unsupported; supply explicit files instead",
                                str(candidate),
                            )
                        )
                dirs[:] = sorted(d for d in dirs if d not in {".git", ".venv", "__pycache__"})
                for name in names:
                    candidate = Path(directory) / name
                    if candidate.suffix.lower() in EXTENSIONS and not candidate.is_symlink():
                        files.add(candidate)
        else:
            raise InvalidInput(Diagnostic("INPUT_KIND", "Expected a file or directory", str(path)))
    if not files:
        raise InvalidInput(Diagnostic("NO_INPUT", "No Scapolite input files found", str(paths[0])))
    try:
        base = Path(os.path.commonpath(roots))
    except ValueError:
        raise InvalidInput(
            Diagnostic("INPUT_ROOT", "Inputs must share a filesystem root", str(paths[0]))
        ) from None
    return sorted(files, key=lambda p: p.as_posix()), base


def load_document(path: Path, source: str) -> Document:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InvalidInput(Diagnostic("INPUT_SIZE", "Input exceeds the 1 MiB limit", source))
        text = raw.decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise InvalidInput(Diagnostic("INPUT_READ", str(exc), source)) from exc
    lines = text.splitlines(keepends=True)
    offset = 0
    yaml_text = text
    if lines and lines[0].rstrip("\r\n \t") == "---":
        closing = next(
            (i for i in range(1, len(lines)) if lines[i].rstrip("\r\n \t") == "---"), None
        )
        if closing is not None:
            yaml_text = "".join(lines[1:closing])
            offset = 1
        elif path.suffix.lower() == ".md":
            raise InvalidInput(
                Diagnostic(
                    "FRONT_MATTER", "Markdown requires a closing --- delimiter", source, line=1
                )
            )
    elif path.suffix.lower() == ".md":
        raise InvalidInput(
            Diagnostic(
                "FRONT_MATTER", "Markdown must start with a --- YAML preamble", source, line=1
            )
        )
    loader = None
    try:
        loader = StrictLoader(yaml_text)
        loader.line_offset = offset
        data = loader.get_single_data()
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        mark = getattr(exc, "problem_mark", None)
        raise InvalidInput(
            Diagnostic(
                "YAML",
                getattr(exc, "problem", str(exc)),
                source,
                line=mark.line + offset + 1 if mark else None,
            )
        ) from exc
    finally:
        if loader is not None:
            loader.dispose()
    if not isinstance(data, dict):
        raise InvalidInput(
            Diagnostic("DOCUMENT_SHAPE", "The YAML root must be a mapping", source, line=offset + 1)
        )
    doc = Document(source, data, hashlib.sha256(raw).hexdigest())
    header = data.get("scapolite")
    if not isinstance(header, dict):
        doc.fail("HEADER", "scapolite must be a mapping", "scapolite")
    if header.get("version") != "0.51":
        doc.fail("VERSION", "Supported version is the string '0.51'", "scapolite.version")
    if not isinstance(header.get("class"), str) or header["class"] not in {
        "rule",
        "group",
        "collection",
        "profile",
    }:
        doc.fail("DOCUMENT_CLASS", "Unknown Scapolite document class", "scapolite.class")
    for name in ("id", "id_namespace"):
        if not isinstance(data.get(name), str) or not IDENTIFIER.fullmatch(data[name]):
            doc.fail(
                "IDENTIFIER",
                "Expected a nonempty identifier using letters, digits, dot, colon, dash or underscore",
                name,
            )
    return doc
