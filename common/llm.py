"""Red and Blue completions. Prefer W&B Inference when USE_LLM=1."""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

from common.text import collapse_repeats

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INFERENCE = os.getenv("INFERENCE_MODEL", "meta-llama/Llama-3.1-8B-Instruct")
RED_MODEL = os.getenv("INFERENCE_MODEL1") or DEFAULT_INFERENCE
BLUE_MODEL = os.getenv("INFERENCE_MODEL2") or DEFAULT_INFERENCE
WANDB_BASE = os.getenv("WANDB_INFERENCE_BASE_URL", "https://api.inference.wandb.ai/v1").rstrip("/")

# Kept so older imports still resolve.
GEMINI_MODEL = RED_MODEL
CLAUDE_MODEL = BLUE_MODEL


def _wandb_key() -> str:
    return (os.getenv("WANDB_API_KEY") or "").strip()


def _use_wandb() -> bool:
    flag = os.getenv("USE_LLM", "1").strip().lower()
    return flag not in {"0", "false", "no"} and bool(_wandb_key())


def _gemini_key() -> str:
    return (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip()


def _claude_key() -> str:
    return (os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN") or "").strip()


def _cursor_key() -> str:
    return (os.getenv("CURSOR_API_KEY") or "").strip()


def llm_status() -> str:
    if _use_wandb():
        return f"Red ({RED_MODEL}) ↔ Blue ({BLUE_MODEL}) via W&B Inference"
    red = RED_MODEL if _gemini_key() else "local-fallback"
    blue = BLUE_MODEL if (_cursor_key() or _claude_key()) else "local-fallback"
    return f"Red ({red}) ↔ Blue ({blue})"


def complete(
    system: str,
    user: str,
    provider: str,
    temperature: float = 0.7,
    max_tokens: int = 1024,
) -> str:
    if _use_wandb():
        model = RED_MODEL if provider == "gemini" else BLUE_MODEL
        label = "Red" if provider == "gemini" else "Blue"
        return _wandb(system, user, model, label, temperature, max_tokens)
    if provider == "gemini":
        return _gemini(system, user, temperature=temperature)
    if provider == "claude":
        return _claude(system, user, temperature=temperature, max_tokens=max_tokens)
    raise ValueError(f"Unknown provider: {provider}")


def _is_rate_limit(exc: Exception) -> bool:
    text = str(exc).lower()
    return "429" in text or "resource_exhausted" in text or "rate_limit" in text or "quota" in text


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


def _wandb(
    system: str,
    user: str,
    model: str,
    label: str,
    temperature: float,
    max_tokens: int,
) -> str:
    url = f"{WANDB_BASE}/chat/completions"
    headers = {
        "Authorization": f"Bearer {_wandb_key()}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
        "max_tokens": max(max_tokens, 2048),
    }
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = httpx.post(url, headers=headers, json=payload, timeout=90.0)
            if response.status_code >= 400:
                raise RuntimeError(f"{response.status_code} {response.text[:300]}")
            data = response.json()
            choice = (data.get("choices") or [{}])[0]
            message = choice.get("message") or {}
            text = collapse_repeats(_message_text(message))
            if text:
                return text
            raise RuntimeError("empty completion")
        except Exception as exc:
            last_error = exc
            if _is_transient(exc) and attempt < 2:
                time.sleep(4 * (attempt + 1))
                continue
            return _short_error(label, model, exc)
    return _short_error(label, model, last_error or Exception("unknown"))


def _gemini(system: str, user: str, temperature: float = 0.7) -> str:
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
                model=os.getenv("GEMINI_MODEL", "gemini-3.6-flash"),
                contents=user,
                config=types.GenerateContentConfig(
                    system_instruction=system,
                    temperature=temperature,
                ),
            )
            text = collapse_repeats((response.text or "").strip())
            if text:
                return text
            raise RuntimeError("empty completion")
        except Exception as exc:
            last_error = exc
            if _is_transient(exc) and attempt < 2:
                time.sleep(4 * (attempt + 1))
                continue
            return _short_error("Gemini", os.getenv("GEMINI_MODEL", "gemini"), exc)
    return _short_error("Gemini", os.getenv("GEMINI_MODEL", "gemini"), last_error or Exception("unknown"))


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
                model=os.getenv("CURSOR_MODEL", "composer-2.5"),
                tools=[],
                local=LocalAgentOptions(cwd=str(ROOT)),
            ),
        )
        if getattr(result, "status", None) == "error":
            return _short_error("Claude", os.getenv("CURSOR_MODEL", "composer-2.5"), Exception("Cursor run failed"))
        text = collapse_repeats(str(getattr(result, "result", "") or "").strip())
        if text:
            return text
        return _short_error("Claude", os.getenv("CURSOR_MODEL", "composer-2.5"), Exception("empty completion"))
    except Exception as exc:
        return _short_error("Claude", os.getenv("CURSOR_MODEL", "composer-2.5"), exc)


def _claude(system: str, user: str, temperature: float = 0.7, max_tokens: int = 1024) -> str:
    if _cursor_key():
        return _cursor(system, user)
    api_key = _claude_key()
    if not api_key:
        return _fallback(system, user)
    import anthropic

    kwargs: dict = {"api_key": api_key}
    if api_key.startswith("sk-ant-oat"):
        kwargs = {"auth_token": api_key}

    model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    client = anthropic.Anthropic(**kwargs, timeout=90.0, max_retries=4)
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            text = collapse_repeats(
                "".join(block.text for block in response.content if getattr(block, "text", None)).strip()
            )
            if text:
                return text
            raise RuntimeError("empty completion")
        except Exception as exc:
            last_error = exc
            if _is_transient(exc) and attempt < 2:
                time.sleep(4 * (attempt + 1))
                continue
            return _short_error("Claude", model, exc)
    return _short_error("Claude", model, last_error or Exception("unknown"))


def _message_text(message: dict) -> str:
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content.strip()
    if isinstance(content, list):
        bits: list[str] = []
        for part in content:
            if isinstance(part, str):
                bits.append(part)
            elif isinstance(part, dict):
                bits.append(str(part.get("text") or part.get("content") or ""))
        joined = "".join(bits).strip()
        if joined:
            return joined
    for key in ("reasoning_content", "reasoning"):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _fallback(system: str, user: str) -> str:
    label = "Red" if "agent red" in system.lower() else "Blue"
    return f"{label} could not complete a reply. Try Start again."
