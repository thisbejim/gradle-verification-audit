from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class Diagnostic:
    code: str
    severity: Severity
    message: str
    path: str
    line: int | None = None
    column: int | None = None
    hint: str | None = None
    component: str | None = None
    artifact: str | None = None

    def as_json(self) -> dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.value
        return value


@dataclass
class AuditResult:
    path: str
    diagnostics: list[Diagnostic]
    components: int = 0
    artifacts: int = 0
    checksums: int = 0

    @property
    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == Severity.WARNING]

    @property
    def infos(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == Severity.INFO]

    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "path": self.path,
            "summary": {
                "components": self.components,
                "artifacts": self.artifacts,
                "checksums": self.checksums,
                "errors": len(self.errors),
                "warnings": len(self.warnings),
                "infos": len(self.infos),
            },
            "diagnostics": [d.as_json() for d in self.diagnostics],
        }
