"""Gemini and Claude, with a local fallback if a key is missing."""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
CLAUDE_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
CURSOR_MODEL = os.getenv("CURSOR_MODEL", "composer-2.5")
ROOT = Path(__file__).resolve().parent.parent


def _gemini_key() -> str:
    return (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip()


def _claude_key() -> str:
    return (os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN") or "").strip()


def _cursor_key() -> str:
    return (os.getenv("CURSOR_API_KEY") or "").strip()


def llm_status() -> str:
    gemini = GEMINI_MODEL if _gemini_key() else "local-fallback"
    if _cursor_key():
        claude = f"Cursor {CURSOR_MODEL}"
    elif _claude_key():
        claude = CLAUDE_MODEL
    else:
        claude = "local-fallback"
    return f"Gemini ({gemini}) ↔ Claude ({claude})"


def complete(system: str, user: str, provider: str) -> str:
    if provider == "gemini":
        return _gemini(system, user)
    if provider == "claude":
        return _claude(system, user)
    raise ValueError(f"Unknown provider: {provider}")


def _is_rate_limit(exc: Exception) -> bool:
    text = str(exc).lower()
    return "429" in text or "resource_exhausted" in text or "rate_limit" in text


def _is_transient(exc: Exception) -> bool:
    text = str(exc).lower()
    return _is_rate_limit(exc) or "connection" in text or "timeout" in text or "temporarily" in text


def _short_error(provider: str, model: str, exc: Exception) -> str:
    text = str(exc)
    if _is_rate_limit(exc):
        return (
            f"{provider} is out of quota for {model}. "
            "Wait a minute and try again, or check that key's plan and rate limits."
        )
    if "connection" in text.lower():
        return f"{provider} could not reach its API. Check the network and try again."
    return f"{provider} error: {text[:240]}"


def _gemini(system: str, user: str) -> str:
    api_key = _gemini_key()
    if not api_key:
        return _fallback(system, user)
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=api_key)
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=user,
                config=types.GenerateContentConfig(
                    system_instruction=system,
                    temperature=0.7,
                ),
            )
            text = (response.text or "").strip()
            return text or _fallback(system, user)
        except Exception as exc:
            last_error = exc
            if _is_transient(exc) and attempt < 2:
                time.sleep(4 * (attempt + 1))
                continue
            return _short_error("Gemini", GEMINI_MODEL, exc)
    return _short_error("Gemini", GEMINI_MODEL, last_error or Exception("unknown"))


def _cursor(system: str, user: str) -> str:
    api_key = _cursor_key()
    if not api_key:
        return _fallback(system, user)
    try:
        from cursor_sdk import Agent, AgentOptions, LocalAgentOptions

        result = Agent.prompt(
            f"{system}\n\n{user}",
            AgentOptions(
                api_key=api_key,
                model=CURSOR_MODEL,
                tools=[],
                local=LocalAgentOptions(cwd=str(ROOT)),
            ),
        )
        if getattr(result, "status", None) == "error":
            return _short_error("Claude", CURSOR_MODEL, Exception("Cursor run failed"))
        text = str(getattr(result, "result", "") or "").strip()
        return text or _fallback(system, user)
    except Exception as exc:
        return _short_error("Claude", CURSOR_MODEL, exc)


def _claude(system: str, user: str) -> str:
    if _cursor_key():
        return _cursor(system, user)
    api_key = _claude_key()
    if not api_key:
        return _fallback(system, user)
    import anthropic

    kwargs: dict = {"api_key": api_key}
    if api_key.startswith("sk-ant-oat"):
        kwargs = {"auth_token": api_key}

    client = anthropic.Anthropic(**kwargs, timeout=90.0, max_retries=4)
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=1024,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            text = "".join(
                block.text for block in response.content if getattr(block, "text", None)
            ).strip()
            return text or _fallback(system, user)
        except Exception as exc:
            last_error = exc
            if _is_transient(exc) and attempt < 2:
                time.sleep(4 * (attempt + 1))
                continue
            return _short_error("Claude", CLAUDE_MODEL, exc)
    return _short_error("Claude", CLAUDE_MODEL, last_error or Exception("unknown"))


def _topic(user: str) -> str:
    for pattern in (
        r"Research this topic:\s*(.+)",
        r"research on\s+(.+):",
        r"wrote this about\s+(.+?)\.",
        r"briefing on\s+(.+?)\s+using",
        r"Three live angles on\s+(.+):",
    ):
        match = re.search(pattern, user, re.I)
        if match:
            return match.group(1).splitlines()[0].strip()
    return "this topic"


def _fallback(system: str, user: str) -> str:
    topic = _topic(user)
    hunter = "gemini" in system.lower()
    if hunter and "conversation so far" not in user.lower():
        return (
            f"Okay, {topic} — I keep thinking the interesting part is who gets left "
            f"behind when it speeds up. What do you see that I'm missing?"
        )
    if hunter:
        return (
            f"Fair. On {topic} I still think the bottleneck is measurement, not the "
            f"idea itself. If we can't tell when a move worked, we just talk forever."
        )
    if "conversation so far" not in user.lower():
        return (
            f"I hear you on {topic}. I'd start with the constraint, not the hype. "
            f"What's the one thing that actually slows people down?"
        )
    return (
        f"Maybe. For {topic} I care more about the handoff than the hot take. "
        f"If two sides can't finish the job, the conversation was just noise."
    )
