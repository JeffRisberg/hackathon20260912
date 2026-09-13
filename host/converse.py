"""Host that runs the iterative purple-team loop on one exploit."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import AsyncIterator
from typing import Any

from common.client import card_to_dict, discover, send_text
from common.llm import llm_status
from common.mission import MAX_ROUNDS, Mission, build_mission, mission_payload
from common.patch import (
    apply_patch,
    file_payload,
    live_file,
    matrix_event,
    parse_patch,
    parse_review,
    verify_exploit,
)
from host.select import focus_repo

HUNTER_URL = "http://127.0.0.1:10020"
ANALYZER_URL = "http://127.0.0.1:10021"
PAUSE_SECONDS = 4.0
PAUSE_STEP = 0.25


def _failed(text: str) -> bool:
    lowered = text.lower()
    return (
        lowered.startswith("gemini is out of quota")
        or lowered.startswith("claude is out of quota")
        or lowered.startswith("red is out of quota")
        or lowered.startswith("blue is out of quota")
        or lowered.startswith("gemini error")
        or lowered.startswith("claude error")
        or lowered.startswith("red error")
        or lowered.startswith("blue error")
        or lowered.startswith("gemini could not")
        or lowered.startswith("claude could not")
        or lowered.startswith("red could not")
        or lowered.startswith("blue could not")
    )


def _numbered(source: str) -> str:
    lines = source.splitlines() or [""]
    return "\n".join(f"{index:>4} | {line}" for index, line in enumerate(lines, start=1))


def _blue_prompt(mission, source: str, finding: str, run_id: str = "") -> str:
    numbered = _numbered(source)
    extra = (
        f"\nRed offense just reported this path:\n{finding}\n\n"
        "Defend that path. STATUS: defend or revise."
        if finding
        else "\nRed has not spoken yet. Defend the named sink. STATUS: defend."
    )
    return (
        f"Fresh run {run_id or 'new'}. No prior conversation. You are Blue, defense.\n"
        f"Mission: {mission.title}\n"
        f"Repo: {mission.repo}\n"
        f"File you may change: {mission.target_file}\n\n"
        f"{mission.bug.strip()}\n\n"
        f"{mission.close_rules.strip()}\n\n"
        f"Line map for {mission.target_file}:\n{numbered}\n\n"
        f"Unnumbered source. Copy SEARCH from this block only:\n"
        f"----- BEGIN FILE -----\n{source}\n----- END FILE -----\n"
        f"{extra}\n\n"
        "Reply with this exact shape:\n"
        "STATUS: defend|revise\n"
        "SUMMARY: what you changed and why it blocks Red\n"
        f"FILE: {mission.target_file}\n"
        "<<<<<<< SEARCH\n"
        "exact current lines\n"
        "=======\n"
        "replacement lines\n"
        ">>>>>>> REPLACE\n"
        "Copy SEARCH from the unnumbered source exactly. One hunk only. "
        "Do not rewrite the whole file. Do not write an exploit."
    )


def _red_prompt(mission, source: str, summary: str, gate: list[str], run_id: str = "") -> str:
    numbered = _numbered(source)
    gate_text = (
        "Host gate still sees the sink:\n- " + "\n- ".join(gate)
        if gate
        else "Host gate currently sees no remaining sink pattern."
    )
    return (
        f"Fresh run {run_id or 'new'}. No prior conversation. You are Red, offense.\n"
        f"Mission: {mission.title}\n"
        f"Repo: {mission.repo}\n"
        f"File under probe: {mission.target_file}\n\n"
        f"{mission.bug.strip()}\n\n"
        f"{mission.close_rules.strip()}\n\n"
        f"Blue's last defense: {summary or '(no patch yet)'}\n"
        f"{gate_text}\n\n"
        f"Current {mission.target_file}:\n{numbered}\n\n"
        "Probe only this one sink. Reply with:\n"
        "VERDICT: still-open|closed\n"
        "FINDING: remaining offensive path with file and line, "
        "or say the path is gone.\n"
        "Never write the word none. Do not write a payload or exploit."
    )


def _chat_text(
    speaker: str,
    raw: str,
    summary: str = "",
    issues: str = "",
    verdict: str = "",
) -> str:
    if speaker == "claude":
        return summary or raw
    clean = (issues or "").strip()
    if verdict == "accept":
        if not clean or clean.lower() in {"none", "n/a", "nil"}:
            return "Closed. Offense can no longer reach this sink."
        return f"Closed. {clean}"
    if verdict == "reject":
        return clean or raw
    if clean.lower() in {"none", "n/a", "nil"}:
        return "Review finished."
    return clean or raw


def _stopped(cancel: asyncio.Event | None) -> bool:
    return bool(cancel and cancel.is_set())


async def _pause(cancel: asyncio.Event | None, seconds: float = PAUSE_SECONDS) -> bool:
    remaining = seconds
    while remaining > 0:
        if _stopped(cancel):
            return True
        step = min(PAUSE_STEP, remaining)
        await asyncio.sleep(step)
        remaining -= step
    return _stopped(cancel)


async def talk(
    repo: str = "",
    bug: str = "",
    files: list[dict[str, Any]] | None = None,
    mission: Mission | None = None,
    cancel: asyncio.Event | None = None,
    run_id: str = "",
) -> AsyncIterator[dict[str, Any]]:
    mission = mission or build_mission(repo, bug)
    yield mission_payload(mission)
    yield {
        "type": "status",
        "text": (
            f"{llm_status()}. Fresh run {run_id or 'new'}. "
            f"Purple-team loop on {mission.title} ({mission.difficulty}). "
            f"Red probes {mission.target_file}. Blue patches one hunk at a time. "
            f"They stop when Red says closed and the host gate is clear."
        ),
    }

    focused = focus_repo(str(mission.repo), mission.bug, files)
    yield {
        "type": "focus",
        "text": f"{focused.summary} Working only {mission.target_file}.",
        "files": focused.hits,
        "scanned": focused.scanned,
    }

    opened = live_file(mission.repo, mission.target_file)
    if opened:
        yield file_payload(mission.target_file, opened, label="Opened the live file")

    hunter_card = await discover(HUNTER_URL)
    analyzer_card = await discover(ANALYZER_URL)
    yield {
        "type": "ready",
        "hunter": card_to_dict(hunter_card),
        "analyzer": card_to_dict(analyzer_card),
    }

    last_summary = ""
    finding = ""
    for round_no in range(1, MAX_ROUNDS + 1):
        if _stopped(cancel):
            yield {"type": "done", "closed": False, "aborted": True, "text": "Emergency stop. The agents were aborted."}
            return
        source = live_file(mission.repo, mission.target_file)
        if not source:
            yield {"type": "error", "text": f"Could not read {mission.target_path}"}
            return

        gate = verify_exploit(mission.exploit_id, source)
        yield {"type": "typing", "from": "gemini"}
        if _stopped(cancel):
            yield {"type": "done", "closed": False, "aborted": True, "text": "Emergency stop. The agents were aborted."}
            return
        red_raw = await send_text(HUNTER_URL, _red_prompt(mission, source, last_summary, gate, run_id))
        if _failed(red_raw):
            yield {"type": "error", "text": red_raw}
            return
        review = parse_review(red_raw)
        finding = review.issues
        yield {
            "type": "chat",
            "from": "gemini",
            "text": _chat_text(
                "gemini",
                red_raw,
                issues=review.issues,
                verdict=review.verdict,
            ),
            "round": round_no,
        }
        yield {
            "type": "verdict",
            "verdict": review.verdict,
            "gate": gate,
            "text": _chat_text("gemini", review.raw, issues=review.issues, verdict=review.verdict),
            "round": round_no,
        }
        yield matrix_event(
            mission.exploit_id,
            source,
            round_no,
            "probe",
            verdict=review.verdict,
            finding=review.issues,
            max_rounds=MAX_ROUNDS,
        )

        if review.verdict == "accept" and not gate:
            yield {
                "type": "done",
                "closed": True,
                "text": f"Purple-team loop closed. Red found no remaining path in {mission.target_file}.",
                "path": str(mission.target_path),
            }
            return

        if review.verdict == "accept" and gate:
            finding = "Host still sees the sink. Remaining: " + "; ".join(gate)

        if await _pause(cancel):
            yield {"type": "done", "closed": False, "aborted": True, "text": "Emergency stop. The agents were aborted."}
            return

        yield {"type": "typing", "from": "claude"}
        if _stopped(cancel):
            yield {"type": "done", "closed": False, "aborted": True, "text": "Emergency stop. The agents were aborted."}
            return
        blue_raw = await send_text(ANALYZER_URL, _blue_prompt(mission, source, finding, run_id))
        if _failed(blue_raw):
            yield {"type": "error", "text": blue_raw}
            return
        patch = parse_patch(blue_raw)
        if len(patch.hunks) > 1:
            patch.hunks = patch.hunks[:1]
        last_summary = patch.summary
        applied = apply_patch(mission.repo, patch)
        if applied.ok:
            yield file_payload(
                applied.path or mission.target_file,
                applied.after or live_file(mission.repo, mission.target_file),
                before=applied.before,
                label=f"Blue defended {applied.path or mission.target_file}",
                round_no=round_no,
            )
        yield {
            "type": "patch",
            "ok": applied.ok,
            "path": applied.path or mission.target_file,
            "text": applied.message,
            "round": round_no,
        }
        yield {
            "type": "chat",
            "from": "claude",
            "text": _chat_text("claude", blue_raw, summary=patch.summary),
            "round": round_no,
        }
        after = applied.after or live_file(mission.repo, mission.target_file)
        yield matrix_event(
            mission.exploit_id,
            after or source,
            round_no,
            "defend",
            finding=applied.message,
            patch_ok=applied.ok,
            max_rounds=MAX_ROUNDS,
        )
        if not applied.ok:
            finding = applied.message
        if round_no < MAX_ROUNDS:
            if await _pause(cancel):
                yield {"type": "done", "closed": False, "aborted": True, "text": "Emergency stop. The agents were aborted."}
                return

    yield {
        "type": "done",
        "closed": False,
        "text": (
            f"Stopped after {MAX_ROUNDS} purple-team rounds without a clean close. "
            f"Latest {mission.target_file} is still on disk."
        ),
        "path": str(mission.target_path),
    }


async def run_cli(repo: str, bug: str) -> None:
    async for event in talk(repo, bug):
        kind = event["type"]
        if kind == "mission":
            print(f"\nPicked: {event['title']} ({event['file']})\n")
        elif kind == "status":
            print(f"\n{event['text']}\n")
        elif kind == "focus":
            print(event["text"])
        elif kind == "typing":
            print(f"{event['from']} is typing...")
        elif kind == "chat":
            print(f"\n{event['from']}: {event['text']}")
        elif kind == "patch":
            print(f"\n[patch] {event['text']}")
        elif kind == "verdict":
            print(f"\n[verdict] {event['verdict']} gate={event.get('gate') or 'clear'}")
        elif kind == "error":
            print(f"\n{event['text']}")
        elif kind == "done":
            print(f"\n--- {event['text']} ---")


def main() -> None:
    parser = argparse.ArgumentParser(description="Purple-team loop: Red probes, Blue patches, one DVWA sink")
    parser.add_argument("--repo", default="", help="Repository path (defaults to DVWA)")
    parser.add_argument("--bug", default="", help="Bug report (defaults to the identify command injection)")
    args = parser.parse_args()
    asyncio.run(run_cli(args.repo, args.bug))


if __name__ == "__main__":
    main()
