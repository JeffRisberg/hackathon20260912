"""Import a DVWA tree and restore patch targets to the stock snapshot."""

from __future__ import annotations

import io
import shutil
import uuid
import zipfile
from pathlib import Path

from common.mission import (
    CATALOG,
    DEFAULT_REPO,
    DIFFICULTIES,
    ROOT,
    find_dvwa_root,
    require_dvwa_root,
    target_for,
)

PRISTINE = DEFAULT_REPO / ".pristine"
IMPORT_DIR = ROOT / ".imported"
MAX_ZIP_BYTES = 80 * 1024 * 1024
RESTORED_FILES = tuple(target_for(spec, level) for spec in CATALOG for level in DIFFICULTIES)


def snapshot_pristine(repo: Path) -> list[str]:
    wrote: list[str] = []
    for rel in RESTORED_FILES:
        live = repo / rel
        snap = repo / ".pristine" / rel
        if snap.is_file() or not live.is_file():
            continue
        snap.parent.mkdir(parents=True, exist_ok=True)
        snap.write_text(live.read_text(encoding="utf-8"), encoding="utf-8")
        wrote.append(rel)
    return wrote


def restore_dvwa(repo: Path | None = None) -> list[str]:
    root = Path(repo) if repo is not None else DEFAULT_REPO
    restored: list[str] = []
    for rel in RESTORED_FILES:
        source = root / ".pristine" / rel
        target = root / rel
        if not source.is_file():
            if not (root / rel).is_file():
                continue
            raise FileNotFoundError(f"Missing pristine snapshot: {rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        restored.append(rel)
    if not restored:
        raise FileNotFoundError("No baseline source files are available to restore.")
    return restored


def import_repo_path(path: str) -> Path:
    text = (path or "").strip()
    if text:
        candidate = Path(text).expanduser()
        if not candidate.is_absolute():
            maybe = ROOT / candidate
            if maybe.exists():
                candidate = maybe
        if candidate.is_file() and candidate.suffix.lower() == ".zip":
            return import_repo_zip(candidate.read_bytes(), candidate.name)
    root = require_dvwa_root(text)
    snapshot_pristine(root)
    return root


def import_repo_zip(data: bytes, filename: str = "dvwa.zip") -> Path:
    if not data:
        raise ValueError("The zip was empty.")
    if len(data) > MAX_ZIP_BYTES:
        raise ValueError("That zip is larger than 80 MB.")
    dest = IMPORT_DIR / uuid.uuid4().hex[:8]
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            _extract_zip(archive, dest)
    except zipfile.BadZipFile as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise ValueError(f"Could not read {filename}: {exc}") from exc
    found = find_dvwa_root(dest)
    if found is None:
        shutil.rmtree(dest, ignore_errors=True)
        raise ValueError("This archive is not a compatible DVWA application.")
    snapshot_pristine(found)
    return found


def _extract_zip(archive: zipfile.ZipFile, dest: Path) -> None:
    for info in archive.infolist():
        name = Path(info.filename)
        if name.is_absolute() or ".." in name.parts:
            continue
        archive.extract(info, dest)


# Older host code imported this name.
restore_snykgoof = restore_dvwa
