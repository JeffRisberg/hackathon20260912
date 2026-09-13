"""W&B Inference + Weave helpers for the red/blue agents.

Reads configuration from the repo-root ``.env`` (and optional local overrides):

- ``WANDB_API_KEY`` — auth for Inference and Weave
- ``WEAVE_PROJECT`` — entity/project for traces + Inference usage attribution
- ``WANDB_INFERENCE_BASE_URL`` — defaults to https://api.inference.wandb.ai/v1
- ``INFERENCE_MODEL`` — default model id
- ``INFERENCE_MODEL1`` — preferred model for agent_red
- ``INFERENCE_MODEL2`` — preferred model for agent_blue
- ``USE_LLM`` — set 0/false to force the offline TestModel
- ``WEAVE_OFFLINE`` — set 1 to skip Weave network init
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal, Optional

from dotenv import load_dotenv

DEFAULT_INFERENCE_BASE = "https://api.inference.wandb.ai/v1"
DEFAULT_MODEL = "meta-llama/Llama-3.1-8B-Instruct"

_REPO_ROOT = Path(__file__).resolve().parents[1]
_weave_initialized = False
_weave_error: Optional[str] = None


def load_env(*, agent_dir: Path | None = None) -> None:
    """Load repo-root ``.env`` first, then optional agent-local overrides."""
    load_dotenv(_REPO_ROOT / ".env")
    if agent_dir is not None:
        load_dotenv(agent_dir / ".env", override=True)


def weave_project() -> str:
    project = (os.environ.get("WEAVE_PROJECT") or "secweave").strip()
    entity = os.environ.get("WANDB_ENTITY", "").strip()
    if entity and "/" not in project:
        return f"{entity}/{project}"
    return project


def llm_enabled() -> bool:
    flag = os.environ.get("USE_LLM", "1").strip().lower()
    if flag in {"0", "false", "no", "off"}:
        return False
    return bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("WANDB_API_KEY"))


def inference_model(which: Literal["default", "red", "blue"] = "default") -> str:
    if which == "red":
        return (
            os.environ.get("INFERENCE_MODEL1")
            or os.environ.get("INFERENCE_MODEL")
            or os.environ.get("PYDANTIC_AI_MODEL")
            or DEFAULT_MODEL
        ).strip()
    if which == "blue":
        return (
            os.environ.get("INFERENCE_MODEL2")
            or os.environ.get("INFERENCE_MODEL")
            or os.environ.get("PYDANTIC_AI_MODEL")
            or DEFAULT_MODEL
        ).strip()
    return (
        os.environ.get("INFERENCE_MODEL")
        or os.environ.get("PYDANTIC_AI_MODEL")
        or DEFAULT_MODEL
    ).strip()


def init_weave() -> dict[str, Any]:
    """Initialize Weave tracing for ``WEAVE_PROJECT``. Safe to call repeatedly."""
    global _weave_initialized, _weave_error

    name = weave_project()
    if _weave_initialized:
        return {"ok": True, "project": name, "error": _weave_error}

    if os.environ.get("WEAVE_OFFLINE", "0").strip().lower() in {"1", "true", "yes"}:
        _weave_error = "WEAVE_OFFLINE=1"
        return {"ok": False, "project": name, "error": _weave_error}

    if not os.environ.get("WANDB_API_KEY"):
        _weave_error = "WANDB_API_KEY not set"
        return {"ok": False, "project": name, "error": _weave_error}

    os.environ.setdefault("WANDB_SILENT", "true")
    os.environ.setdefault("WANDB_ERROR_REPORTING", "false")

    try:
        import weave

        weave.init(name)
        _weave_initialized = True
        _weave_error = None
        return {"ok": True, "project": name, "error": None}
    except Exception as exc:  # noqa: BLE001
        _weave_error = repr(exc)
        _weave_initialized = False
        return {"ok": False, "project": name, "error": _weave_error}


def weave_status(*, which: Literal["default", "red", "blue"] = "default") -> dict[str, Any]:
    return {
        "project": weave_project(),
        "initialized": _weave_initialized,
        "error": _weave_error,
        "llm_enabled": llm_enabled(),
        "model": inference_model(which),
        "inference_base": os.environ.get(
            "WANDB_INFERENCE_BASE_URL", DEFAULT_INFERENCE_BASE
        ),
        "wandb_key": bool(os.environ.get("WANDB_API_KEY")),
    }


def maybe_weave_op(fn):
    """Decorate with ``@weave.op`` only when Weave init succeeded."""
    if not _weave_initialized:
        return fn
    try:
        import weave

        return weave.op()(fn)
    except Exception:  # noqa: BLE001
        return fn


def build_model(which: Literal["default", "red", "blue"] = "default"):
    """Build a pydantic-ai model: W&B Inference when configured, else TestModel."""
    if not llm_enabled():
        from pydantic_ai.models.test import TestModel

        return TestModel(), "test"

    # Prefer explicit OpenAI only when W&B Inference is not configured.
    if os.environ.get("OPENAI_API_KEY") and not os.environ.get(
        "WANDB_INFERENCE_BASE_URL"
    ):
        from pydantic_ai.models.openai import OpenAIChatModel

        model_name = inference_model(which)
        # Allow ``openai:gpt-4o-mini`` style ids from older samples.
        if model_name.startswith("openai:"):
            model_name = model_name.split(":", 1)[1]
        return OpenAIChatModel(model_name), "openai"

    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("WANDB_API_KEY")
    if not api_key:
        from pydantic_ai.models.test import TestModel

        return TestModel(), "test"

    from openai import AsyncOpenAI
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    base_url = os.environ.get("WANDB_INFERENCE_BASE_URL", DEFAULT_INFERENCE_BASE)
    project = weave_project()
    model_name = inference_model(which)
    if ":" in model_name and not model_name.startswith(
        ("meta-llama/", "openai/", "google/", "microsoft/", "deepseek-ai/", "Qwen/")
    ):
        # Strip provider prefixes like ``openai:`` from older env samples.
        _, _, rest = model_name.partition(":")
        if rest:
            model_name = rest

    client = AsyncOpenAI(
        api_key=api_key,
        base_url=base_url,
        project=project,
        timeout=120.0,
        max_retries=3,
    )
    model = OpenAIChatModel(
        model_name,
        provider=OpenAIProvider(openai_client=client),
    )
    return model, "wandb-inference"
