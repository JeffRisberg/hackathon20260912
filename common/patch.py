"""Parse SEARCH/REPLACE patches and apply them inside one repo."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path

ALLOWED_SUFFIXES = {".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".ejs", ".hbs", ".dust", ".json"}
BLOCKED_PARTS = {".git", "node_modules", "exploits", ".venv", "venv", ".fix-loop"}

FILE_RE = re.compile(
    r"^(?:FILE|PATH)\s*:\s*(?P<path>\S+)",
    re.I | re.M,
)
HUNK_RE = re.compile(
    r"<<<<<<< SEARCH\n(?P<search>.*?)\n=======\n(?P<replace>.*?)\n>>>>>>> REPLACE",
    re.S,
)
STATUS_RE = re.compile(r"^STATUS\s*:\s*(?P<value>\w+)", re.I | re.M)
SUMMARY_RE = re.compile(r"^SUMMARY\s*:\s*(?P<value>.+)$", re.I | re.M)
VERDICT_RE = re.compile(r"^VERDICT\s*:\s*(?P<value>[\w-]+)", re.I | re.M)
ISSUES_RE = re.compile(r"^(?:ISSUES|FINDING)\s*:\s*(?P<value>[\s\S]+)$", re.I | re.M)

IDENTIFY_EXEC_RE = re.compile(
    r"""exec\s*\(\s*(['"`])identify\b""",
    re.I,
)
IDENTIFY_CONCAT_RE = re.compile(
    r"""exec\s*\(\s*(['"`]identify\s*['"`]\s*\+|\s*['"`]identify[^'"`]*['"`]\s*\+)""",
    re.I,
)
URL_IN_EXEC_RE = re.compile(r"exec\s*\([^;]{0,200}\+\s*url", re.I)
IDENTIFY_EXECFILE_RE = re.compile(
    r"""execFile\s*\(\s*['"`]identify['"`]\s*,\s*\[\s*url\b""",
    re.I,
)
IDENTIFY_PLUS_URL_RE = re.compile(r"identify[^;\n]{0,80}\+\s*url|url\s*\+\s*[^;\n]{0,40}identify", re.I)


@dataclass
class Hunk:
    search: str
    replace: str


@dataclass
class Patch:
    status: str
    summary: str
    path: str
    hunks: list[Hunk] = field(default_factory=list)
    raw: str = ""


@dataclass
class ApplyResult:
    ok: bool
    path: str
    message: str
    before: str = ""
    after: str = ""


@dataclass
class Review:
    verdict: str
    issues: str
    raw: str = ""


@dataclass(frozen=True)
class Check:
    id: str
    label: str
    ok: bool
    detail: str = ""


def parse_patch(text: str) -> Patch:
    body = _strip_fences(text or "")
    status_match = STATUS_RE.search(body)
    summary_match = SUMMARY_RE.search(body)
    file_match = FILE_RE.search(body)
    hunks = [
        Hunk(search=match.group("search"), replace=match.group("replace"))
        for match in HUNK_RE.finditer(body)
    ]
    return Patch(
        status=(status_match.group("value") if status_match else "propose").lower(),
        summary=(summary_match.group("value").strip() if summary_match else ""),
        path=_clean_path(file_match.group("path") if file_match else ""),
        hunks=hunks,
        raw=body,
    )


def parse_review(text: str) -> Review:
    body = _strip_fences(text or "")
    verdict_match = VERDICT_RE.search(body)
    issues_match = ISSUES_RE.search(body)
    verdict = (verdict_match.group("value") if verdict_match else "").lower()
    if verdict in {"closed", "accept", "patched", "defended", "safe"}:
        verdict = "accept"
    elif verdict in {"still-open", "open", "reject", "vulnerable", "exposed"}:
        verdict = "reject"
    else:
        lowered = body.lower()
        if re.search(r"\b(closed|accept(ed|ing)?|defended)\b", lowered) and not re.search(
            r"\b(still-open|reject|vulnerable|exposed)\b", lowered
        ):
            verdict = "accept"
        else:
            verdict = "reject"
    issues = issues_match.group("value").strip() if issues_match else body.strip()
    return Review(verdict=verdict, issues=issues, raw=body)


def apply_patch(repo: Path, patch: Patch) -> ApplyResult:
    if not patch.path:
        return ApplyResult(False, "", "Patch is missing FILE: the host-named path")
    if not patch.hunks:
        return ApplyResult(False, patch.path, "Patch has no <<<<<<< SEARCH / REPLACE blocks")

    try:
        target = _safe_target(repo, patch.path)
    except ValueError as exc:
        return ApplyResult(False, patch.path, str(exc))

    try:
        before = target.read_text(encoding="utf-8")
    except OSError as exc:
        return ApplyResult(False, patch.path, f"Could not read {patch.path}: {exc}")

    after = before
    for index, hunk in enumerate(patch.hunks, start=1):
        if not hunk.search:
            return ApplyResult(False, patch.path, f"Hunk {index} has an empty SEARCH block")
        count = after.count(hunk.search)
        if count == 0:
            return ApplyResult(
                False,
                patch.path,
                f"Hunk {index} SEARCH did not match {patch.path}. Copy the current file exactly.",
            )
        if count > 1:
            return ApplyResult(
                False,
                patch.path,
                f"Hunk {index} SEARCH matched {count} times. Make the SEARCH unique.",
            )
        after = after.replace(hunk.search, hunk.replace, 1)

    if after == before:
        return ApplyResult(False, patch.path, "Patch made no change")

    _backup_once(repo, target, before)
    try:
        target.write_text(after, encoding="utf-8")
    except OSError as exc:
        return ApplyResult(False, patch.path, f"Could not write {patch.path}: {exc}", before, after)
    return ApplyResult(True, _rel(repo, target), "Applied patch to disk", before, after)


def _item(check_id: str, label: str, failed: bool, fail_detail: str, pass_detail: str) -> Check:
    return Check(check_id, label, ok=not failed, detail=fail_detail if failed else pass_detail)


def evaluate_checks(exploit_id: str, source: str) -> list[Check]:
    if exploit_id == "exec-command-injection":
        leftover = verify_exec_injection(source)
        return [
            _item(
                "ping-shell",
                "IP never reaches ping",
                bool(leftover),
                leftover[0] if leftover else "",
                "IP is constrained before ping",
            )
        ]
    if exploit_id == "sqli":
        failed = bool(
            re.search(r"WHERE user_id = ['\"]?\$id", source)
            and not re.search(r"bindParam|bindValue|->prepare\s*\(", source)
        )
        return [
            _item(
                "sql-bind",
                "User id is bound",
                failed,
                "user id is still interpolated into the SQL string",
                "user id is bound or not interpolated",
            )
        ]
    if exploit_id == "open-redirect":
        failed = bool(
            re.search(
                r"header\s*\(\s*[\"']location:\s*[\"']\s*\.\s*\$_GET\s*\[\s*['\"]redirect['\"]",
                source,
                re.I,
            )
        )
        return [
            _item(
                "redirect-allowlist",
                "Redirect is allowlisted",
                failed,
                "still redirects to the raw redirect query value",
                "redirect no longer follows the raw query",
            )
        ]
    if exploit_id == "file-inclusion":
        failed = bool(
            re.search(r"\$file\s*=\s*\$_GET\s*\[\s*['\"]page['\"]", source)
            and not re.search(r"in_array\s*\(\s*\$file", source)
        )
        return [
            _item(
                "include-allowlist",
                "Include path is allowlisted",
                failed,
                "page query still becomes $file with no allowlist",
                "include path is allowlisted",
            )
        ]
    if exploit_id == "unrestricted-upload":
        failed = bool(re.search(r"move_uploaded_file\s*\(", source) and not re.search(r"imagecreatefrom", source))
        return [
            _item(
                "upload-reencode",
                "Upload is re-encoded",
                failed,
                "upload still stores the original uploaded file",
                "upload no longer stores the original file",
            )
        ]
    if exploit_id == "xss-reflected":
        failed = bool(re.search(r"\$_GET\s*\[\s*['\"]name['\"]", source) and not re.search(r"htmlspecialchars\s*\(", source))
        return [
            _item(
                "xss-escape",
                "Name is HTML-escaped",
                failed,
                "name query is still written into HTML unsanitized",
                "name is escaped before HTML",
            )
        ]
    if exploit_id == "identify-command-injection":
        leftover = verify_command_injection(source)
        return [
            _item(
                "identify-exec",
                "URL never reaches identify",
                bool(leftover),
                leftover[0] if leftover else "",
                "identify no longer takes the user URL",
            )
        ]
    if exploit_id == "nosql-login":
        user = bool(re.search(r"User\.find\(\s*\{\s*username:\s*req\.body\.username", source))
        password = bool(re.search(r"password:\s*req\.body\.password", source))
        return [
            _item("nosql-user", "Username is a plain string", user, "login still passes req.body.username into User.find", "username is not a raw query object"),
            _item("nosql-pass", "Password is a plain string", password, "login still passes req.body.password into the query", "password is not a raw query object"),
        ]
    if exploit_id == "zip-slip":
        failed = bool(re.search(r"extractAllTo\s*\(", source))
        return [_item("zip-slip", "Archive paths are checked", failed, "still extracts the archive with extractAllTo", "archive is not extracted blindly")]
    if exploit_id == "prototype-pollution":
        failed = bool(re.search(r"_\.merge\s*\(\s*message\s*,\s*req\.body\.message", source))
        return [_item("merge", "Message fields are copied", failed, "still merges req.body.message into the message object", "untrusted merge is gone")]
    if exploit_id == "st-path-traversal":
        failed = bool(re.search(r"\bst\s*\(\s*\{[^}]*path:\s*['\"]\./public['\"]", source))
        return [_item("static-serve", "Public files use express.static", failed, "still serves public files with st()", "st() is no longer serving public")]
    return [_item("unknown", "Known sink", True, "unknown exploit", "")]


def check_payloads(exploit_id: str, source: str) -> list[dict]:
    return [
        {"id": item.id, "label": item.label, "ok": item.ok, "detail": item.detail}
        for item in evaluate_checks(exploit_id, source)
    ]


def matrix_event(
    exploit_id: str,
    source: str,
    round_no: int,
    phase: str,
    verdict: str = "",
    finding: str = "",
    patch_ok: bool | None = None,
    max_rounds: int = 8,
) -> dict:
    return {
        "type": "matrix",
        "round": round_no,
        "phase": phase,
        "verdict": verdict,
        "finding": finding,
        "patch_ok": patch_ok,
        "checks": check_payloads(exploit_id, source),
        "max_rounds": max_rounds,
    }


def verify_exploit(exploit_id: str, source: str) -> list[str]:
    return [item.detail for item in evaluate_checks(exploit_id, source) if not item.ok]


def verify_exec_injection(source: str) -> list[str]:
    if not re.search(r"shell_exec\s*\(\s*['\"]ping", source):
        return []
    raw_ip = re.search(
        r"\$target\s*=\s*(?:trim\s*\(\s*)?\$_REQUEST\s*\[\s*['\"]ip['\"]",
        source,
    )
    guarded = re.search(
        r"is_numeric\s*\(\s*\$octet|escapeshellarg\s*\(\s*\$target|FILTER_VALIDATE_IP",
        source,
    )
    if raw_ip and not guarded:
        return ["ping still concatenates the raw ip into shell_exec"]
    return []


def verify_command_injection(source: str) -> list[str]:
    issues: list[str] = []
    if IDENTIFY_EXEC_RE.search(source) or IDENTIFY_CONCAT_RE.search(source):
        issues.append("still shells out to identify")
    if URL_IN_EXEC_RE.search(source):
        issues.append("still concatenates url into exec()")
    if IDENTIFY_EXECFILE_RE.search(source) or IDENTIFY_PLUS_URL_RE.search(source):
        issues.append("still passes the user URL to identify")
    return issues


def changed_lines(before: str, after: str) -> list[int]:
    marks: list[int] = []
    matcher = difflib.SequenceMatcher(a=before.splitlines(), b=after.splitlines())
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "insert"}:
            marks.extend(range(j1 + 1, j2 + 1))
    return marks


def diff_rows(before: str | None, after: str) -> list[dict]:
    new_lines = after.splitlines()
    if before is None:
        return [{"kind": "ctx", "n": index, "text": line} for index, line in enumerate(new_lines, start=1)]
    old_lines = before.splitlines()
    rows: list[dict] = []
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for index, line in enumerate(new_lines[j1:j2], start=j1 + 1):
                rows.append({"kind": "ctx", "n": index, "text": line})
        elif tag == "delete":
            for index, line in enumerate(old_lines[i1:i2], start=i1 + 1):
                rows.append({"kind": "del", "n": index, "text": line})
        elif tag == "insert":
            for index, line in enumerate(new_lines[j1:j2], start=j1 + 1):
                rows.append({"kind": "add", "n": index, "text": line})
        else:
            for index, line in enumerate(old_lines[i1:i2], start=i1 + 1):
                rows.append({"kind": "del", "n": index, "text": line})
            for index, line in enumerate(new_lines[j1:j2], start=j1 + 1):
                rows.append({"kind": "add", "n": index, "text": line})
    return rows


def file_payload(path: str, content: str, before: str | None = None, label: str = "", round_no: int | None = None) -> dict:
    event = {
        "type": "file",
        "path": path,
        "content": content,
        "changed": changed_lines(before, content) if before is not None else [],
        "diff": diff_rows(before, content),
        "label": label,
    }
    if round_no is not None:
        event["round"] = round_no
    return event


def live_file(repo: Path, relpath: str) -> str:
    try:
        target = _safe_target(repo, relpath)
        return target.read_text(encoding="utf-8")
    except (OSError, ValueError):
        return ""


def _safe_target(repo: Path, relpath: str) -> Path:
    cleaned = _clean_path(relpath)
    repo = repo.resolve()
    target = (repo / cleaned).resolve()
    if not str(target).startswith(str(repo) + "/") and target != repo:
        raise ValueError(f"Refusing path outside the repo: {relpath}")
    if any(part in BLOCKED_PARTS for part in target.relative_to(repo).parts):
        raise ValueError(f"Refusing blocked path: {relpath}")
    if target.suffix.lower() not in ALLOWED_SUFFIXES:
        raise ValueError(f"Refusing file type: {relpath}")
    if not target.is_file():
        raise ValueError(f"File does not exist: {cleaned}")
    return target


def _backup_once(repo: Path, target: Path, before: str) -> None:
    backup_dir = repo / ".fix-loop"
    backup_dir.mkdir(exist_ok=True)
    stamp = backup_dir / (target.name + ".orig")
    if not stamp.exists():
        stamp.write_text(before, encoding="utf-8")


def _clean_path(path: str) -> str:
    text = (path or "").strip().replace("\\", "/").lstrip("./")
    for prefix in ("DVWA/", "dvwa/", "SnykGoof/", "snykgoof/"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    return text


def _rel(repo: Path, target: Path) -> str:
    return str(target.relative_to(repo.resolve())).replace("\\", "/")


def _strip_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", stripped)
        if stripped.endswith("```"):
            stripped = stripped[: -3].rstrip()
    return stripped
