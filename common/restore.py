"""Restore DVWA patch targets to the stock snapshot."""

from __future__ import annotations

from common.mission import CATALOG, DEFAULT_REPO, DIFFICULTIES, target_for

PRISTINE = DEFAULT_REPO / ".pristine"
RESTORED_FILES = tuple(target_for(spec, level) for spec in CATALOG for level in DIFFICULTIES)


def restore_dvwa() -> list[str]:
    restored: list[str] = []
    for rel in RESTORED_FILES:
        source = PRISTINE / rel
        target = DEFAULT_REPO / rel
        if not source.is_file():
            raise FileNotFoundError(f"Missing pristine snapshot: {rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        restored.append(rel)
    return restored


# Older host code imported this name.
restore_snykgoof = restore_dvwa
