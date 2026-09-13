"""Host that discovers two A2A agents and has them debate a fix."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from common.client import card_to_dict, discover, send_text
from common.llm import llm_status
from host.select import focus_repo

HUNTER_URL = "http://127.0.0.1:10020"
ANALYZER_URL = "http://127.0.0.1:10021"
TURNS = 6
PAUSE_SECONDS = 2.0
MAX_CHARS = 120_000


def _failed(text: str) -> bool:
    lowered = text.lower()
    return (
        lowered.startswith("gemini is out of quota")
        or lowered.startswith("claude is out of quota")
        or lowered.startswith("gemini error")
        or lowered.startswith("claude error")
        or lowered.startswith("gemini could not")
        or lowered.startswith("claude could not")
    )


def _transcript(history: list[tuple[str, str]]) -> str:
    if not history:
        return "(no messages yet)"
    return "\n".join(f"{speaker}: {text}" for speaker, text in history)


def materialize(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    path = Path(text).expanduser()
    try:
        if path.is_file():
            body = path.read_text(encoding="utf-8", errors="replace")
            return f"{path.name}\n{body[:MAX_CHARS]}"
    except OSError:
        return text
    return text[:MAX_CHARS]


def _prompt(focused: str, bug: str, history: list[tuple[str, str]], speaker: str) -> str:
    brief = (
        f"{focused}\n\n"
        f"Bug / proposed fix:\n{bug}"
    )
    if not history:
        return (
            f"{brief}\n\n"
            "You are Agent Blue chatting with Agent Red (Gemini). "
            "Use only the focused regions unless you must mention another file. "
            "Propose a concrete fix and name the file and lines. "
            "Two to four short sentences, like a person talking. "
            "No lists, headings, markdown, or signature."
        )
    other = "Gemini" if speaker == "claude" else "Claude"
    role = (
        "Challenge the last proposed fix. Point out a hole, a risk, or a missing test in those regions."
        if speaker == "gemini"
        else "Respond to Agent Red's challenge. Adjust the fix or defend it, still naming file and lines."
    )
    return (
        f"{brief}\n\n"
        f"You are chatting with {other}. Conversation so far:\n"
        f"{_transcript(history)}\n\n"
        f"{role} Reply in 2-4 short sentences. Sound like a person, "
        "not a report. No lists, headings, markdown, or signature."
    )


async def talk(
    repo: str,
    bug: str,
    files: list[dict[str, Any]] | None = None,
) -> AsyncIterator[dict[str, Any]]:
    bug = materialize(bug)
    yield {
        "type": "status",
        "text": f"{llm_status()}. Matching the bug to specific files, then they take turns.",
    }
    focused = focus_repo(repo, bug, files)
    yield {
        "type": "focus",
        "text": focused.summary,
        "files": focused.hits,
        "scanned": focused.scanned,
    }

    hunter_card = await discover(HUNTER_URL)
    analyzer_card = await discover(ANALYZER_URL)
    yield {
        "type": "ready",
        "hunter": card_to_dict(hunter_card),
        "analyzer": card_to_dict(analyzer_card),
    }

    history: list[tuple[str, str]] = []
    for turn in range(TURNS):
        speaker = "claude" if turn % 2 == 0 else "gemini"
        url = ANALYZER_URL if speaker == "claude" else HUNTER_URL
        yield {"type": "typing", "from": speaker}
        reply = await send_text(url, _prompt(focused.brief, bug, history, speaker))
        if _failed(reply):
            yield {"type": "error", "text": reply}
            return
        history.append((speaker, reply))
        yield {"type": "chat", "from": speaker, "text": reply}
        if turn < TURNS - 1:
            await asyncio.sleep(PAUSE_SECONDS)

    yield {"type": "done", "text": history[-1][1] if history else ""}


async def run_cli(repo: str, bug: str) -> None:
    async for event in talk(repo, bug):
        kind = event["type"]
        if kind == "status":
            print(f"\n{event['text']}\n")
        elif kind == "focus":
            print(event["text"])
            for hit in event.get("files") or []:
                print(f"  {hit['path']}:{hit['lines']}")
        elif kind == "typing":
            print(f"{event['from']} is typing...")
        elif kind == "chat":
            print(f"\n{event['from']}: {event['text']}")
        elif kind == "error":
            print(f"\n{event['text']}")
        elif kind == "done":
            print("\n--- conversation over ---")


def main() -> None:
    parser = argparse.ArgumentParser(description="Have Claude and Gemini debate a fix")
    parser.add_argument("--repo", default="", help="Repository path, URL, or pasted files")
    parser.add_argument("--bug", default="", help="Bug report or proposed fix")
    args = parser.parse_args()
    asyncio.run(run_cli(args.repo, args.bug))


if __name__ == "__main__":
    main()
