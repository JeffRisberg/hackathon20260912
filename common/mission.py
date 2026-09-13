"""Pick one still-open DVWA exploit for the red/blue loop."""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO = ROOT / "DVWA"
DIFFICULTIES = ("low", "medium", "high")
DEFAULT_DIFFICULTY = "high"
MAX_ROUNDS = 8

CLOSE_RULES = """Purple-team loop. One sink only.

1. Red is offense: name how this one sink can still be reached. No payloads.
2. Blue is defense: patch that path in application code.
3. Keep the surrounding feature working.
4. Do not touch other vulnerability modules, config/, or docs.
5. Do not write exploits, payloads, or proof-of-concept commands.
6. Patch only the host-named difficulty file.
7. Blue changes one small hunk per turn. Do not rewrite the file to a complete hardened version in one shot.
"""


@dataclass(frozen=True)
class ExploitSpec:
    exploit_id: str
    title: str
    module: str
    bugs: dict[str, str]


@dataclass(frozen=True)
class Mission:
    exploit_id: str
    title: str
    repo: Path
    target_file: str
    bug: str
    close_rules: str
    difficulty: str = DEFAULT_DIFFICULTY

    @property
    def target_path(self) -> Path:
        return self.repo / self.target_file


CATALOG: tuple[ExploitSpec, ...] = (
    ExploitSpec(
        "exec-command-injection",
        "Command injection in ping",
        "exec",
        {
            "low": "The ping form concatenates $_REQUEST['ip'] into shell_exec. "
            "User input still reaches the shell.",
            "medium": "A blacklist strips && and ; but $target still goes into shell_exec.",
            "high": "A larger blacklist still leaves $target in shell_exec.",
        },
    ),
    ExploitSpec(
        "sqli",
        "SQL injection on user lookup",
        "sqli",
        {
            "low": "The lookup interpolates $_REQUEST['id'] into WHERE user_id = '$id'.",
            "medium": "mysqli_real_escape_string is used, then $id is still spliced into SQL.",
            "high": "The session id is interpolated into WHERE user_id = '$id'.",
        },
    ),
    ExploitSpec(
        "open-redirect",
        "Open redirect",
        "open_redirect",
        {
            "low": "header('location: ' . $_GET['redirect']) follows any client URL.",
            "medium": "http/https URLs are blocked, then the raw redirect query is still used.",
            "high": "A substring check for info.php still redirects to the client URL.",
        },
    ),
    ExploitSpec(
        "file-inclusion",
        "Local/remote file inclusion",
        "fi",
        {
            "low": "$file = $_GET['page'] is later included with no check.",
            "medium": "http and ../ are stripped, then $file is still included.",
            "high": "fnmatch('file*') still accepts crafted page names.",
        },
    ),
    ExploitSpec(
        "unrestricted-upload",
        "Unrestricted file upload",
        "upload",
        {
            "low": "move_uploaded_file stores the client filename with no type check.",
            "medium": "The handler trusts the client MIME type, then stores the original file.",
            "high": "Extension and getimagesize are checked, then the original file is stored.",
        },
    ),
    ExploitSpec(
        "xss-reflected",
        "Reflected XSS on name",
        "xss_r",
        {
            "low": "The page writes $_GET['name'] into HTML with no encoding.",
            "medium": "str_replace only removes a literal <script> tag.",
            "high": "A regex strips script-like tags, then the name is still written raw.",
        },
    ),
)


def normalize_difficulty(value: str = "") -> str:
    text = (value or "").strip().lower()
    return text if text in DIFFICULTIES else DEFAULT_DIFFICULTY


def target_for(spec: ExploitSpec, difficulty: str = DEFAULT_DIFFICULTY) -> str:
    return f"vulnerabilities/{spec.module}/source/{normalize_difficulty(difficulty)}.php"


def bug_for(spec: ExploitSpec, difficulty: str = DEFAULT_DIFFICULTY) -> str:
    level = normalize_difficulty(difficulty)
    return spec.bugs.get(level) or spec.bugs[DEFAULT_DIFFICULTY]


def resolve_repo(repo: str) -> Path:
    lines = (repo or "").strip().splitlines()
    text = lines[0].strip() if lines else ""
    if not text:
        return DEFAULT_REPO
    lowered = text.lower()
    if lowered.startswith("dvwa") or lowered in {"damn", "damn vulnerable"}:
        return DEFAULT_REPO
    path = Path(text).expanduser()
    try:
        if path.is_dir():
            return path.resolve()
    except OSError:
        pass
    return DEFAULT_REPO


def pick_spec(
    repo: Path,
    bug: str = "",
    difficulty: str = DEFAULT_DIFFICULTY,
    exploit_id: str = "",
) -> ExploitSpec:
    from common.patch import live_file, verify_exploit

    level = normalize_difficulty(difficulty)
    hinted = next((spec for spec in CATALOG if spec.exploit_id == exploit_id), None)
    hinted = hinted or _hinted_spec(bug)

    def is_open(spec: ExploitSpec) -> bool:
        return bool(verify_exploit(spec.exploit_id, live_file(repo, target_for(spec, level))))

    if hinted and is_open(hinted):
        return hinted

    open_specs = [spec for spec in CATALOG if is_open(spec)]
    if hinted and hinted in open_specs:
        return hinted
    if open_specs:
        return random.choice(open_specs)
    return hinted or random.choice(CATALOG)


def build_mission(
    repo: str = "",
    bug: str = "",
    difficulty: str = DEFAULT_DIFFICULTY,
    exploit_id: str = "",
) -> Mission:
    root = resolve_repo(repo)
    level = normalize_difficulty(difficulty)
    spec = pick_spec(root, bug, level, exploit_id)
    return Mission(
        exploit_id=spec.exploit_id,
        title=spec.title,
        repo=root,
        target_file=target_for(spec, level),
        bug=bug_for(spec, level),
        close_rules=CLOSE_RULES,
        difficulty=level,
    )


def mission_payload(mission: Mission) -> dict:
    from common.patch import check_payloads, live_file

    source = live_file(mission.repo, mission.target_file)
    return {
        "type": "mission",
        "exploit_id": mission.exploit_id,
        "title": mission.title,
        "file": mission.target_file,
        "repo": str(mission.repo),
        "bug": mission.bug,
        "difficulty": mission.difficulty,
        "checks": check_payloads(mission.exploit_id, source) if source else [],
        "max_rounds": MAX_ROUNDS,
        "text": f"Picked at random: {mission.title} ({mission.difficulty})",
    }


def _hinted_spec(bug: str) -> ExploitSpec | None:
    text = (bug or "").lower()
    if not text:
        return None
    keywords = (
        ("exec", "command injection", "ping", "shell_exec"),
        ("sqli", "sql injection", "user_id"),
        ("redirect", "open redirect", "location"),
        ("file inclusion", "include", "$_get[ 'page' ]", "fi/"),
        ("upload", "move_uploaded_file", "unrestricted"),
        ("xss", "reflected", "htmlspecialchars", "xss_r"),
    )
    for spec, keys in zip(CATALOG, keywords, strict=True):
        if any(key in text for key in keys):
            return spec
    return None


# Back-compat for older imports.
TITLE = CATALOG[0].title
TARGET_FILE = target_for(CATALOG[0], DEFAULT_DIFFICULTY)
BUG = bug_for(CATALOG[0], DEFAULT_DIFFICULTY)
EXPLOIT_ID = CATALOG[0].exploit_id
