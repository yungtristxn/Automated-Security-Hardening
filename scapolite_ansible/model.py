from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    source: str
    field: str = ""
    line: int | None = None
    rule: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class InvalidInput(Exception):
    def __init__(self, diagnostic: Diagnostic):
        self.diagnostic = diagnostic
        super().__init__(diagnostic.message)


@dataclass
class Document:
    source: str
    data: dict
    sha256: str

    @property
    def key(self) -> str:
        return f"{self.data['id_namespace']}/{self.data['id']}"

    def fail(self, code: str, message: str, field: str = "") -> None:
        import re

        value: Any = self.data
        line = getattr(value, "line", 1)
        for token in re.findall(r"[^.\[\]]+", field):
            if isinstance(value, dict):
                line = getattr(value, "lines", {}).get(token, line)
                value = value.get(token)
            elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
                value = value[int(token)]
                line = getattr(value, "line", line)
            else:
                break
        key = None
        if isinstance(self.data.get("id"), str) and isinstance(self.data.get("id_namespace"), str):
            key = self.key
        raise InvalidInput(Diagnostic(code, message, self.source, field, line, key))


@dataclass(frozen=True)
class Origin:
    source: str
    rule: str
    implementation: str
    field: str


@dataclass
class RegistryOperation:
    path: str
    name: str
    type: str
    value: int | str
    minimum: int | None = None
    maximum: int | None = None
    origins: list[Origin] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        return self.path.casefold(), self.name.casefold()

    @property
    def semantics(self) -> tuple:
        return self.type, self.value, self.minimum, self.maximum

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Analysis:
    documents: list[dict] = field(default_factory=list)
    operations: list[RegistryOperation] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.diagnostics

    def report(self) -> dict:
        from . import __version__

        return {
            "report_version": 1,
            "converter_version": __version__,
            "ok": self.ok,
            "summary": {
                "documents": len(self.documents),
                "selected_rules": sum(
                    d["status"] in ("supported", "unsupported") for d in self.documents
                ),
                "supported_rules": sum(d["status"] == "supported" for d in self.documents),
                "unsupported_rules": sum(d["status"] == "unsupported" for d in self.documents),
                "excluded_rules": sum(d["status"] == "excluded" for d in self.documents),
                "invalid_documents": sum(d["status"] == "invalid" for d in self.documents),
                "operations": len(self.operations),
            },
            "documents": self.documents,
            "operations": [o.to_dict() for o in self.operations],
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }
