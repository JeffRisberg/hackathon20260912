"""Pick the repo regions that actually match a bug, instead of dumping the tree."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    "target",
    ".idea",
    ".vscode",
}
SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".woff",
    ".woff2",
    ".mp4",
    ".pyc",
    ".so",
    ".dylib",
    ".bin",
    ".lock",
    ".min.js",
    ".map",
}
SOURCE_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".rs",
    ".c",
    ".h",
    ".cpp",
    ".cc",
    ".cs",
    ".kt",
    ".swift",
    ".vue",
    ".svelte",
    ".sql",
    ".html",
    ".json",
    ".yml",
    ".yaml",
}
STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "this",
    "that",
    "from",
    "into",
    "your",
    "have",
    "has",
    "was",
    "were",
    "are",
    "bug",
    "fix",
    "issue",
    "error",
    "report",
    "please",
    "should",
    "would",
    "could",
    "file",
    "files",
    "code",
    "repo",
    "repository",
    "vulnerability",
    "vulnerable",
    "proposed",
    "patch",
    "change",
    "function",
    "class",
    "method",
    "line",
    "lines",
    "user",
    "users",
    "request",
    "response",
    "when",
    "then",
    "than",
    "they",
    "them",
    "their",
    "there",
    "here",
    "about",
    "after",
    "before",
    "using",
    "used",
    "because",
    "where",
    "which",
    "while",
    "need",
    "needs",
    "also",
    "just",
    "like",
}
VULN_HINTS: dict[str, tuple[str, ...]] = {
    "sql": (
        "execute(",
        "executemany(",
        "raw(",
        "cursor",
        "query(",
        "select ",
        "insert ",
        "update ",
        "delete ",
        "sqlite",
        "psycopg",
        "sqlalchemy",
        "f\"select",
        "f'select",
        ".format(",
        "%s",
    ),
    "xss": (
        "innerhtml",
        "dangerouslysetinnerhtml",
        "v-html",
        "document.write",
        "html(",
        "markupsafe",
    ),
    "command": (
        "subprocess",
        "os.system",
        "os.popen",
        "shell=true",
        "eval(",
        "exec(",
        "popen(",
    ),
    "path": (
        "open(",
        "path(",
        "send_file",
        "os.path.join",
        "pathlib",
        "..",
        "filename",
    ),
    "ssrf": ("requests.get", "requests.post", "urlopen", "httpx", "urllib", "aiohttp"),
    "auth": ("password", "passwd", "secret", "token", "jwt", "session", "authorize", "login"),
    "idor": ("user_id", "userid", "request.args", "request.query", "params["),
    "pickle": ("pickle.loads", "yaml.load", "unserialize", "marshal.loads"),
}
VULN_ALIASES = {
    "sqli": "sql",
    "sql injection": "sql",
    "injection": "sql",
    "cross-site": "xss",
    "cross site": "xss",
    "rce": "command",
    "command injection": "command",
    "path traversal": "path",
    "directory traversal": "path",
    "lfi": "path",
    "local file": "path",
    "ssrf": "ssrf",
    "idor": "idor",
    "auth": "auth",
    "authentication": "auth",
    "jwt": "auth",
    "deserialization": "pickle",
    "pickle": "pickle",
}
DUMP_RE = re.compile(r"^--- (.+?) ---\s*$", re.M)
PATH_RE = re.compile(r"(?:[\w.-]+/)+[\w.-]+\.[A-Za-z0-9]+")
FILE_RE = re.compile(r"\b[\w.-]+\.(?:py|js|ts|tsx|jsx|go|java|rb|php|rs|c|h|cpp|cs|kt|swift|vue|sql|html)\b")
STACK_RE = re.compile(r"""(?:File|at)\s+["'(]?([\w./\\-]+\.\w+)["')]?(?:,\s*line\s+|:)(\d+)""", re.I)
IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")
QUOTED_RE = re.compile(r"""["'`]([^"'`]{3,80})["'`]""")
MAX_SCAN_FILES = 600
MAX_READ_BYTES = 200_000
MAX_FOCUS_FILES = 8
MAX_BRIEF_CHARS = 24_000
CONTEXT_LINES = 8


@dataclass
class CodeFile:
    path: str
    content: str


@dataclass
class FocusHit:
    path: str
    score: int
    start: int
    end: int
    snippet: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class FocusedRepo:
    summary: str
    brief: str
    hits: list[dict]
    scanned: int


def focus_repo(repo: str, bug: str, files: list[dict] | None = None) -> FocusedRepo:
    collected = _collect(repo, files)
    if not collected:
        text = (repo or "").strip()[:MAX_BRIEF_CHARS]
        return FocusedRepo(
            summary="No source files were found, so the raw repository text will be used.",
            brief=text or "(empty repository)",
            hits=[],
            scanned=0,
        )

    signals = _signals(bug)
    ranked = _rank(collected, signals)
    hits = ranked[:MAX_FOCUS_FILES]
    if not hits:
        hits = _fallback_hits(collected)

    brief = _render_brief(collected, hits, bug, signals)
    names = [hit.path for hit in hits]
    if hits and hits[0].score > 0:
        summary = "Focused on " + ", ".join(names) + " because they match the bug."
    else:
        summary = "No strong match, so the most likely source files were included: " + ", ".join(names)
    return FocusedRepo(
        summary=summary,
        brief=brief,
        hits=[
            {
                "path": hit.path,
                "lines": f"{hit.start}-{hit.end}",
                "score": hit.score,
                "why": hit.reasons[:4],
            }
            for hit in hits
        ],
        scanned=len(collected),
    )


def _collect(repo: str, files: list[dict] | None) -> list[CodeFile]:
    collected: list[CodeFile] = []
    for item in files or []:
        path = str(item.get("name") or item.get("path") or "").strip().replace("\\", "/")
        content = str(item.get("content") or "")
        if path and content.strip() and not _skip_path(path):
            collected.append(CodeFile(path, content))
    if collected:
        return collected[:MAX_SCAN_FILES]

    text = (repo or "").strip()
    if not text:
        return []
    path = Path(text.splitlines()[0].replace("Local repository ", "").rstrip(":"))
    try:
        path = path.expanduser()
        if path.is_dir():
            return _read_dir(path)
        if path.is_file():
            return [CodeFile(path.name, path.read_text(encoding="utf-8", errors="replace"))]
    except OSError:
        pass
    return _parse_dump(text)


def _read_dir(root: Path) -> list[CodeFile]:
    collected: list[CodeFile] = []
    for path in sorted(root.rglob("*")):
        if len(collected) >= MAX_SCAN_FILES:
            break
        if not path.is_file():
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        if _skip_path(rel):
            continue
        try:
            if path.stat().st_size > MAX_READ_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "\x00" in text:
            continue
        collected.append(CodeFile(rel, text))
    return collected


def _parse_dump(text: str) -> list[CodeFile]:
    matches = list(DUMP_RE.finditer(text))
    if not matches:
        if text.strip():
            return [CodeFile("repository.txt", text)]
        return []
    files: list[CodeFile] = []
    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        path = match.group(1).strip().replace("\\", "/")
        body = text[start:end].strip()
        if path and body and not _skip_path(path):
            files.append(CodeFile(path, body))
    return files


def _skip_path(path: str) -> bool:
    parts = Path(path).parts
    if any(part in SKIP_DIRS for part in parts):
        return True
    lower = path.lower()
    return any(lower.endswith(suffix) for suffix in SKIP_SUFFIXES)


def _signals(bug: str) -> dict:
    text = bug or ""
    lowered = text.lower()
    paths = [m.replace("\\", "/") for m in PATH_RE.findall(text)]
    paths += [m.replace("\\", "/") for m in FILE_RE.findall(text)]
    stacks = [(path.replace("\\", "/"), int(line)) for path, line in STACK_RE.findall(text)]
    quoted = [m.strip() for m in QUOTED_RE.findall(text) if m.strip().lower() not in STOPWORDS]
    idents: list[str] = []
    for token in IDENT_RE.findall(text):
        if token.lower() in STOPWORDS or token.isdigit():
            continue
        if len(token) < 4 and not any(ch.isupper() for ch in token[1:]):
            continue
        idents.append(token)
    families = set()
    for alias, family in VULN_ALIASES.items():
        if alias in lowered:
            families.add(family)
    patterns: list[str] = []
    for family in families:
        patterns.extend(VULN_HINTS[family])
    return {
        "paths": _unique(paths),
        "stacks": stacks,
        "quoted": _unique(quoted),
        "idents": _unique(idents)[:40],
        "families": sorted(families),
        "patterns": _unique(patterns),
        "words": _unique(
            word
            for word in re.findall(r"[a-zA-Z_]{4,}", lowered)
            if word not in STOPWORDS
        )[:30],
    }


def _rank(files: list[CodeFile], signals: dict) -> list[FocusHit]:
    hits: list[FocusHit] = []
    for item in files:
        score = 0
        reasons: list[str] = []
        path_l = item.path.lower()
        name = Path(item.path).name.lower()
        content_l = item.content.lower()

        for mentioned in signals["paths"]:
            if mentioned.lower() in path_l or Path(mentioned).name.lower() == name:
                score += 120
                reasons.append(f"bug names {mentioned}")

        for stack_path, _line in signals["stacks"]:
            if Path(stack_path).name.lower() == name or stack_path.lower() in path_l:
                score += 160
                reasons.append(f"stack mentions {stack_path}")

        for ident in signals["idents"]:
            ident_l = ident.lower()
            if ident_l == Path(item.path).stem.lower() or ident_l in name:
                score += 50
                reasons.append(f"file matches {ident}")
            elif re.search(rf"\b{re.escape(ident)}\b", item.content):
                score += 12
                reasons.append(f"contains {ident}")

        for quote in signals["quoted"]:
            if quote.lower() in content_l:
                score += 24
                reasons.append(f'contains "{quote[:40]}"')

        pattern_hits = 0
        for pattern in signals["patterns"]:
            if pattern in content_l:
                pattern_hits += 1
        if pattern_hits:
            score += min(40, pattern_hits * 8)
            reasons.append("matches " + "/".join(signals["families"]))

        if any(part in path_l for part in ("test", "spec", "mock", "fixture")):
            score -= 6
        if score > 0 and Path(item.path).suffix.lower() in SOURCE_SUFFIXES:
            score += 2

        if score < 10:
            continue
        start, end, snippet = _excerpt(item, signals)
        hits.append(
            FocusHit(
                path=item.path,
                score=score,
                start=start,
                end=end,
                snippet=snippet,
                reasons=_unique(reasons),
            )
        )
    hits.sort(key=lambda hit: (-hit.score, hit.path))
    return hits


def _excerpt(item: CodeFile, signals: dict) -> tuple[int, int, str]:
    lines = item.content.splitlines() or [""]
    needles: list[str] = []
    needles.extend(ident.lower() for ident in signals["idents"])
    needles.extend(quote.lower() for quote in signals["quoted"])
    needles.extend(pattern.lower() for pattern in signals["patterns"])
    needles.extend(word for word in signals["words"] if len(word) >= 5)
    preferred = {line for _path, line in signals["stacks"] if Path(_path).name.lower() == Path(item.path).name.lower()}

    marks: list[int] = []
    for idx, line in enumerate(lines, start=1):
        low = line.lower()
        if idx in preferred or (needles and any(needle in low for needle in needles)):
            marks.append(idx)
    if not marks:
        end = min(len(lines), 50)
        return 1, end, "\n".join(lines[:end])

    windows: list[tuple[int, int]] = []
    for mark in marks[:12]:
        start = max(1, mark - CONTEXT_LINES)
        end = min(len(lines), mark + CONTEXT_LINES)
        if windows and start <= windows[-1][1] + 2:
            windows[-1] = (windows[-1][0], max(windows[-1][1], end))
        else:
            windows.append((start, end))

    chunks = []
    for start, end in windows[:3]:
        body = "\n".join(f"{i:>4} | {lines[i - 1]}" for i in range(start, end + 1))
        chunks.append(body)
    snippet = "\n...\n".join(chunks)
    return windows[0][0], windows[-1][1], snippet


def _fallback_hits(files: list[CodeFile]) -> list[FocusHit]:
    preferred = []
    for item in files:
        name = Path(item.path).name.lower()
        weight = 0
        if name in {"main.py", "app.py", "index.js", "index.ts", "server.py", "routes.py"}:
            weight += 8
        if Path(item.path).suffix.lower() in SOURCE_SUFFIXES:
            weight += 2
        if weight:
            preferred.append((weight, item))
    chosen = [item for _weight, item in sorted(preferred, key=lambda pair: (-pair[0], pair[1].path))][:4]
    if not chosen:
        chosen = files[:3]
    hits = []
    for item in chosen:
        start, end, snippet = _excerpt(item, {"idents": [], "quoted": [], "patterns": [], "words": [], "stacks": []})
        hits.append(FocusHit(item.path, 0, start, end, snippet, ["likely source file"]))
    return hits


def _render_brief(files: list[CodeFile], hits: list[FocusHit], bug: str, signals: dict) -> str:
    tree = "\n".join(f"- {item.path}" for item in files[:80])
    more = f"\n- … {len(files) - 80} more files" if len(files) > 80 else ""
    regions = []
    for hit in hits:
        why = f" ({', '.join(hit.reasons[:3])})" if hit.reasons else ""
        regions.append(f"### {hit.path}:{hit.start}-{hit.end}{why}\n{hit.snippet}")
    body = "\n\n".join(regions)
    if len(body) > MAX_BRIEF_CHARS:
        body = body[:MAX_BRIEF_CHARS] + "\n…"
    families = ", ".join(signals["families"]) or "unspecified"
    return (
        f"The host searched {len(files)} files and kept only the regions that match this bug "
        f"({families}). Cite file and line numbers when you talk about a change.\n\n"
        f"Repository files:\n{tree}{more}\n\n"
        f"Relevant code:\n{body}"
    )


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out
