from __future__ import annotations

import json
from typing import Any

from .model import AuditResult, Diagnostic, Severity


def _location(diagnostic: Diagnostic) -> str:
    return f"{diagnostic.path}:{diagnostic.line}" if diagnostic.line else diagnostic.path


def text_report(result: AuditResult) -> str:
    status = "PASS" if not result.errors else "FAIL"
    lines = [
        f"{status} gradle-verification-audit — {len(result.errors)} errors, {len(result.warnings)} warnings, {len(result.infos)} infos",
        f"Scanned {result.components} component(s), {result.artifacts} artifact(s), {result.checksums} verifier(s).",
    ]
    for diagnostic in result.diagnostics:
        location = _location(diagnostic)
        lines.append(
            f"{diagnostic.severity.value.upper():7} {diagnostic.code} {location} — {diagnostic.message}"
        )
        if diagnostic.hint:
            lines.append(f"         hint: {diagnostic.hint}")
    return "\n".join(lines)


def json_report(result: AuditResult) -> str:
    return json.dumps(result.as_json(), indent=2, sort_keys=True) + "\n"


def sarif_report(result: AuditResult) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for diagnostic in result.diagnostics:
        rules.setdefault(
            diagnostic.code,
            {
                "id": diagnostic.code,
                "shortDescription": {"text": diagnostic.message},
                "help": {"text": diagnostic.hint or diagnostic.message},
            },
        )
        level = (
            "error"
            if diagnostic.severity == Severity.ERROR
            else "warning"
            if diagnostic.severity == Severity.WARNING
            else "note"
        )
        location: dict[str, Any] = {"uri": diagnostic.path}
        if diagnostic.line:
            location["region"] = {"startLine": diagnostic.line}
        results.append(
            {
                "ruleId": diagnostic.code,
                "level": level,
                "message": {"text": diagnostic.message},
                "locations": [{"physicalLocation": location}],
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "gradle-verification-audit", "rules": list(rules.values())}
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
