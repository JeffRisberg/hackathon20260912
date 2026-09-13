"""Trim runaway model output that repeats the same syntax."""

from __future__ import annotations

import re

_MARKERS = re.compile(r"\n(?=(?:VERDICT|STATUS|FILE|FINDING|ISSUES|<<<<<<< SEARCH)\s*:)", re.I)
_HUNK_END = ">>>>>>> REPLACE"


def collapse_repeats(text: str) -> str:
    body = (text or "").strip()
    if not body:
        return ""
    body = _cut_protocol(body)
    body = _dedupe_lines(body)
    body = _cut_repeated_window(body)
    return body.strip()


def _cut_protocol(text: str) -> str:
    if "<<<<<<< SEARCH" in text and _HUNK_END in text:
        start = text.find("<<<<<<< SEARCH")
        end = text.find(_HUNK_END, start)
        if end != -1:
            head = text[:start]
            return (head + text[start : end + len(_HUNK_END)]).strip()
    verdict = re.search(r"^VERDICT\s*:", text, re.I | re.M)
    if verdict:
        rest = text[verdict.start() :]
        parts = [part for part in _MARKERS.split(rest, maxsplit=3) if part.strip()]
        if len(parts) >= 2:
            return (parts[0].rstrip() + "\n" + parts[1].lstrip()).strip()
        first_para = rest.split("\n\n", 1)[0]
        return first_para.strip()
    return text


def _dedupe_lines(text: str) -> str:
    kept: list[str] = []
    prev = None
    repeats = 0
    for line in text.splitlines():
        if line == prev:
            repeats += 1
            if repeats >= 1:
                continue
        else:
            repeats = 0
            prev = line
        kept.append(line)
    return "\n".join(kept)


def _cut_repeated_window(text: str) -> str:
    lines = text.splitlines()
    size = len(lines)
    for width in range(min(12, size // 2), 2, -1):
        for index in range(0, size - 2 * width + 1):
            block = lines[index : index + width]
            nxt = lines[index + width : index + 2 * width]
            if block == nxt and any(line.strip() for line in block):
                return "\n".join(lines[: index + width])
    return text
