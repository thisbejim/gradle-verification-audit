from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

GRADLE_NAMESPACE = "https://schema.gradle.org/dependency-verification"
_TAG_RE = re.compile(
    r"<\s*(verification-metadata|configuration|keyring-format|components|component|artifact|"
    r"sha256|sha512|sha1|md5|pgp|trust|trusted-key|key-servers|key-server)\b"
)


@dataclass
class ParsedDocument:
    root: ET.Element
    lines: dict[int, int]
    namespace: str | None


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _tag_lines(text: str) -> dict[str, deque[int]]:
    lines: dict[str, deque[int]] = defaultdict(deque)
    for match in _TAG_RE.finditer(text):
        lines[match.group(1)].append(text.count("\n", 0, match.start()) + 1)
    return lines


def parse_document(path: Path) -> ParsedDocument:
    raw = path.read_bytes()
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("DOCTYPE and ENTITY declarations are not accepted")
    text = raw.decode("utf-8")
    root = ET.fromstring(text)
    queues = _tag_lines(text)
    lines: dict[int, int] = {}
    for element in root.iter():
        name = local_name(element.tag)
        if queues.get(name):
            lines[id(element)] = queues[name].popleft()
    namespace = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else None
    return ParsedDocument(root=root, lines=lines, namespace=namespace)


def line_for(document: ParsedDocument, element: ET.Element) -> int | None:
    return document.lines.get(id(element))
