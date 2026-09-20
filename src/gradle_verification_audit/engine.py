from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .model import AuditResult, Diagnostic, Severity
from .parser import GRADLE_NAMESPACE, ParsedDocument, line_for, local_name, parse_document

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
_STRONG_HASHES = {"sha256", "sha512"}


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(element) if local_name(child.tag) == name]


def _child(element: ET.Element, name: str) -> ET.Element | None:
    return next(iter(_children(element, name)), None)


def _component_key(component: ET.Element) -> tuple[str, str, str]:
    return (
        component.attrib.get("group", ""),
        component.attrib.get("name", ""),
        component.attrib.get("version", ""),
    )


def _component_label(component: ET.Element) -> str:
    group, name, version = _component_key(component)
    return f"{group}:{name}:{version}"


def _diag(
    document: ParsedDocument,
    path: str,
    element: ET.Element,
    code: str,
    severity: Severity,
    message: str,
    *,
    hint: str | None = None,
    component: str | None = None,
    artifact: str | None = None,
) -> Diagnostic:
    return Diagnostic(
        code=code,
        severity=severity,
        message=message,
        path=path,
        line=line_for(document, element) or (1 if element is document.root else None),
        hint=hint,
        component=component,
        artifact=artifact,
    )


def _root_diagnostics(document: ParsedDocument, path: str) -> list[Diagnostic]:
    root = document.root
    diagnostics: list[Diagnostic] = []
    if local_name(root.tag) != "verification-metadata":
        diagnostics.append(
            _diag(
                document,
                path,
                root,
                "GVA001",
                Severity.ERROR,
                "root element must be <verification-metadata>",
            )
        )
    elif document.namespace != GRADLE_NAMESPACE:
        diagnostics.append(
            _diag(
                document,
                path,
                root,
                "GVA002",
                Severity.WARNING,
                "root namespace is not Gradle's dependency-verification namespace",
                hint=f'use xmlns="{GRADLE_NAMESPACE}"',
            )
        )
    return diagnostics


def _configuration_diagnostics(
    document: ParsedDocument, path: str, root: ET.Element
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    configuration = _child(root, "configuration")
    if configuration is None:
        return diagnostics
    keyring_format = _child(configuration, "keyring-format")
    if keyring_format is not None and (keyring_format.text or "").strip() not in {
        "armored",
        "binary",
    }:
        diagnostics.append(
            _diag(
                document,
                path,
                keyring_format,
                "GVA301",
                Severity.ERROR,
                f"unsupported keyring-format {(keyring_format.text or '').strip()!r}",
                hint="use 'armored' or 'binary'",
            )
        )
    key_servers = _child(configuration, "key-servers")
    if key_servers is not None:
        for server in _children(key_servers, "key-server"):
            if not server.attrib.get("uri", "").strip():
                diagnostics.append(
                    _diag(
                        document,
                        path,
                        server,
                        "GVA302",
                        Severity.ERROR,
                        "key-server is missing its uri attribute",
                    )
                )
    trusted_keys = _child(configuration, "trusted-keys")
    seen_keys: set[tuple[str, str]] = set()
    if trusted_keys is not None:
        for key in _children(trusted_keys, "trusted-key"):
            identifier = key.attrib.get("id", "").strip()
            group = key.attrib.get("group", "").strip()
            if not identifier:
                diagnostics.append(
                    _diag(
                        document,
                        path,
                        key,
                        "GVA303",
                        Severity.ERROR,
                        "trusted-key is missing its id attribute",
                    )
                )
            elif not _HEX.fullmatch(identifier) or len(identifier) not in {16, 40}:
                diagnostics.append(
                    _diag(
                        document,
                        path,
                        key,
                        "GVA304",
                        Severity.ERROR,
                        f"trusted-key id must be 16 or 40 hexadecimal characters, got {identifier!r}",
                    )
                )
            identity = (identifier.lower(), group)
            if identity in seen_keys:
                diagnostics.append(
                    _diag(
                        document,
                        path,
                        key,
                        "GVA305",
                        Severity.ERROR,
                        f"duplicate trusted-key {identifier}",
                    )
                )
            seen_keys.add(identity)
    trusted_artifacts = _child(configuration, "trusted-artifacts")
    if trusted_artifacts is not None:
        for trust in _children(trusted_artifacts, "trust"):
            selectors = {
                name: value
                for name, value in trust.attrib.items()
                if name in {"group", "name", "version", "file"}
            }
            if not selectors:
                diagnostics.append(
                    _diag(
                        document,
                        path,
                        trust,
                        "GVA306",
                        Severity.ERROR,
                        "trusted-artifacts rule has no group, name, version, or file selector",
                    )
                )
            regex = trust.attrib.get("regex")
            if regex is not None and regex not in {"true", "false"}:
                diagnostics.append(
                    _diag(
                        document,
                        path,
                        trust,
                        "GVA307",
                        Severity.ERROR,
                        "trust regex must be 'true' or 'false'",
                    )
                )
            if regex == "true" and "file" in trust.attrib:
                try:
                    re.compile(trust.attrib["file"])
                except re.error as exc:
                    diagnostics.append(
                        _diag(
                            document,
                            path,
                            trust,
                            "GVA308",
                            Severity.ERROR,
                            f"invalid trust file regex: {exc}",
                        )
                    )
    return diagnostics


def _artifact_diagnostics(
    document: ParsedDocument,
    path: str,
    component: ET.Element,
    artifact: ET.Element,
    secure: bool,
) -> tuple[list[Diagnostic], int]:
    diagnostics: list[Diagnostic] = []
    component_label = _component_label(component)
    artifact_name = artifact.attrib.get("name", "").strip()
    if not artifact_name:
        diagnostics.append(
            _diag(
                document,
                path,
                artifact,
                "GVA103",
                Severity.ERROR,
                f"artifact in {component_label} is missing its name attribute",
                component=component_label,
            )
        )
    checksums = [
        child
        for child in list(artifact)
        if local_name(child.tag) in _HASH_LENGTHS or local_name(child.tag) == "pgp"
    ]
    seen_algorithms: set[str] = set()
    count = 0
    has_strong = False
    for checksum in checksums:
        algorithm = local_name(checksum.tag)
        if algorithm in seen_algorithms:
            diagnostics.append(
                _diag(
                    document,
                    path,
                    checksum,
                    "GVA105",
                    Severity.ERROR,
                    f"duplicate {algorithm} verifier on artifact {artifact_name or '<unnamed>'}",
                    component=component_label,
                    artifact=artifact_name or None,
                )
            )
        seen_algorithms.add(algorithm)
        count += 1
        value = checksum.attrib.get("value", "").strip()
        if algorithm in _HASH_LENGTHS:
            expected = _HASH_LENGTHS[algorithm]
            if len(value) != expected or not _HEX.fullmatch(value):
                diagnostics.append(
                    _diag(
                        document,
                        path,
                        checksum,
                        "GVA201",
                        Severity.ERROR,
                        f"{algorithm} value for {artifact_name or '<unnamed>'} must be {expected} hexadecimal characters",
                        hint="copy the digest emitted by Gradle after independently reviewing the artifact",
                        component=component_label,
                        artifact=artifact_name or None,
                    )
                )
            if algorithm in _STRONG_HASHES:
                has_strong = True
            if algorithm in {"md5", "sha1"}:
                diagnostics.append(
                    _diag(
                        document,
                        path,
                        checksum,
                        "GVA202",
                        Severity.ERROR if secure else Severity.WARNING,
                        f"{algorithm} is not a modern collision-resistant verifier for {artifact_name or '<unnamed>'}",
                        hint="prefer sha256 or sha512; keep weak hashes only for documented legacy compatibility",
                        component=component_label,
                        artifact=artifact_name or None,
                    )
                )
        else:
            if not value or not _HEX.fullmatch(value) or len(value) not in {16, 40, 64}:
                diagnostics.append(
                    _diag(
                        document,
                        path,
                        checksum,
                        "GVA203",
                        Severity.ERROR,
                        f"pgp value for {artifact_name or '<unnamed>'} must be a 16, 40, or 64 character hexadecimal key id",
                        component=component_label,
                        artifact=artifact_name or None,
                    )
                )
        origin = checksum.attrib.get("origin", "")
        if origin.lower().startswith("generated by gradle"):
            diagnostics.append(
                _diag(
                    document,
                    path,
                    checksum,
                    "GVA204",
                    Severity.INFO,
                    f"{algorithm} for {artifact_name or '<unnamed>'} is marked as generated by Gradle",
                    hint="review generated digests against a trusted artifact source before merging",
                    component=component_label,
                    artifact=artifact_name or None,
                )
            )
    if not checksums:
        diagnostics.append(
            _diag(
                document,
                path,
                artifact,
                "GVA206",
                Severity.ERROR if secure else Severity.WARNING,
                f"artifact {artifact_name or '<unnamed>'} has no checksum or PGP verifier",
                hint="add sha256/sha512 or document a matching trusted-artifacts rule",
                component=component_label,
                artifact=artifact_name or None,
            )
        )
    elif secure and not has_strong:
        diagnostics.append(
            _diag(
                document,
                path,
                artifact,
                "GVA207",
                Severity.ERROR,
                f"artifact {artifact_name or '<unnamed>'} has no sha256 or sha512 verifier",
                hint="secure policy requires a modern checksum in addition to any legacy verifier",
                component=component_label,
                artifact=artifact_name or None,
            )
        )
    return diagnostics, count


def audit_file(path: str | Path, *, secure: bool = False) -> AuditResult:
    requested = Path(path)
    if requested.is_dir():
        requested = requested / "gradle" / "verification-metadata.xml"
    display_path = str(requested)
    if not requested.exists():
        diagnostic = Diagnostic(
            "GVA000", Severity.ERROR, "verification metadata file does not exist", display_path
        )
        return AuditResult(display_path, [diagnostic])
    try:
        document = parse_document(requested)
    except (OSError, UnicodeDecodeError, ET.ParseError, ValueError) as exc:
        diagnostic = Diagnostic(
            "GVA000", Severity.ERROR, f"cannot parse verification metadata: {exc}", display_path
        )
        return AuditResult(display_path, [diagnostic])

    diagnostics = _root_diagnostics(document, display_path)
    diagnostics.extend(_configuration_diagnostics(document, display_path, document.root))
    components_parent = _child(document.root, "components")
    if components_parent is None:
        diagnostics.append(
            _diag(
                document,
                display_path,
                document.root,
                "GVA003",
                Severity.WARNING,
                "metadata has no <components> section",
            )
        )
        return AuditResult(display_path, diagnostics)

    components = _children(components_parent, "component")
    seen_components: set[tuple[str, str, str]] = set()
    artifacts_total = 0
    checksums_total = 0
    for component in components:
        component_key = _component_key(component)
        component_label = _component_label(component)
        missing = [
            name for name, value in zip(("group", "name", "version"), component_key) if not value
        ]
        if missing:
            diagnostics.append(
                _diag(
                    document,
                    display_path,
                    component,
                    "GVA101",
                    Severity.ERROR,
                    f"component is missing {', '.join(missing)} attribute(s)",
                    component=component_label,
                )
            )
        if component_key in seen_components:
            diagnostics.append(
                _diag(
                    document,
                    display_path,
                    component,
                    "GVA102",
                    Severity.ERROR,
                    f"duplicate component {component_label}",
                )
            )
        seen_components.add(component_key)
        artifacts = _children(component, "artifact")
        artifact_names: set[str] = set()
        if not artifacts:
            diagnostics.append(
                _diag(
                    document,
                    display_path,
                    component,
                    "GVA104",
                    Severity.WARNING,
                    f"component {component_label} has no artifact entries",
                    hint="confirm this is intentional; Gradle verifies individual artifacts",
                    component=component_label,
                )
            )
        for artifact in artifacts:
            artifact_name = artifact.attrib.get("name", "").strip()
            if artifact_name and artifact_name in artifact_names:
                diagnostics.append(
                    _diag(
                        document,
                        display_path,
                        artifact,
                        "GVA106",
                        Severity.ERROR,
                        f"duplicate artifact {artifact_name} in {component_label}",
                        component=component_label,
                        artifact=artifact_name,
                    )
                )
            artifact_names.add(artifact_name)
            found, count = _artifact_diagnostics(
                document, display_path, component, artifact, secure
            )
            diagnostics.extend(found)
            artifacts_total += 1
            checksums_total += count
    return AuditResult(display_path, diagnostics, len(components), artifacts_total, checksums_total)
