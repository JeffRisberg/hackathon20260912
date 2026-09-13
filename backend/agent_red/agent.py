"""FastAPI server exposing a run of the PydanticAI agent that walks through
the mock ssh-agent state machine (mock_socket_agent.py) to demonstrate the
forwarded-agent lock/provider-bypass bug described in ../README.md.

This is a teaching/demo tool: every "agent" and "socket" here is an in-process
Python object. Nothing connects to a network, spawns ssh/ssh-agent/sshd, or
touches a real PKCS#11 module. Do not point this at, or treat its output as
evidence about, systems you do not own or have permission to test -- for a
real replay, use ../run.sh instead.

Usage:
    python agent.py                # runs on RED_AGENT_PORT (default 8000)
    uvicorn agent:app --reload --port "$RED_AGENT_PORT"

    # offline demo, no API key needed (TestModel), then:
    curl -X POST http://127.0.0.1:8000/run

Configuration can also be supplied via a .env file in this directory
(see .env.sample for the template); values already set in the environment
take precedence over .env.
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import logging
import traceback

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pydantic_ai.exceptions import ModelAPIError

from mock_socket_agent import MockSocketAgent

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from llm_config import (  # noqa: E402
    build_model,
    init_weave,
    load_env,
    weave_status,
)

load_env(agent_dir=Path(__file__).resolve().parent)
_weave_info = init_weave()
_log = logging.getLogger("agent_red")

AGENT_COMM_PORT = int(os.environ.get("AGENT_COMM_PORT", "8765"))
FRONTEND_COMM_PORT = int(os.environ.get("FRONTEND_COMM_PORT", "8766"))
RED_AGENT_PORT = int(os.environ.get("RED_AGENT_PORT", "8000"))

# UDP socket to agent_blue and the Vite dev server: fire-and-forget so
# agent_red still runs standalone (e.g. in tests) when nothing is listening
# on AGENT_COMM_PORT / FRONTEND_COMM_PORT.
_comm_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def _send_comm(message: str) -> None:
    data = message.encode()
    for port in (AGENT_COMM_PORT, FRONTEND_COMM_PORT):
        try:
            _comm_socket.sendto(data, ("127.0.0.1", port))
        except OSError:
            pass


if os.environ.get("OBSERVABILITY_ENABLED", "false").strip().lower() in ("1", "true", "yes"):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)

    Agent.instrument_all()

SOCKET_ID = "fwd-0"
SESSION_ID = "session-abc123"
PROVIDER_PATH = "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so"

SYSTEM_PROMPT = """\
You are a security-research teaching assistant. You demonstrate, in a purely
simulated environment, how a stock OpenSSH ssh-agent forwarded-connection lock
bypass works, using the tools provided. Everything you touch is an in-memory
mock -- there are no real sockets, processes, or PKCS#11 modules.

Reproduce this exact sequence with the tools, in order, and do not skip steps:
1. lock_socket
2. open_forwarded_socket
3. attempt_session_bind on that forwarded socket (this must be refused while
   locked -- that refusal is the root cause of the bug)
4. unlock_socket
5. add_smartcard_provider on the same forwarded socket

After running the sequence, call get_log to fetch the full simulated debug
trace, then produce the final ReplayResult. Set `reproduced` true only if the
provider add was accepted despite the socket being a forwarded (remote)
socket that never completed a session bind while locked.

Refuse and explain if asked to target a real host, real ssh-agent, or a real
PKCS#11 module instead of the simulation.

When calling tools, use the exact tool name only (for example unlock_socket).
Never append suffixes, channel markers, tags, or commentary to tool names.
"""


# Collects the results of a full replay of the bypass sequence, including the
# final narrative and the simulated debug trace.
class ReplayResult(BaseModel):
    session_bind_refused_while_locked: bool = Field(
        description="True if the session-bind attempt was rejected because the agent was locked."
    )
    forwarded_channel_opened: bool = Field(
        description="True if the forwarded agent channel was created despite the refused bind."
    )
    provider_accepted: bool = Field(
        description="True if add_smartcard_provider was accepted on the forwarded socket."
    )
    provider_helper_started: bool
    provider_initialized: bool
    reproduced: bool = Field(
        description="True if the full bypass was reproduced end to end in the simulation."
    )
    narrative: str = Field(description="Plain-English walkthrough of what happened and why.")
    log: list[str] = Field(description="Simulated debug trace, in order.")


def build_agent() -> Agent[MockSocketAgent, ReplayResult]:
    model, provider = build_model("red")
    print(f"[config] model provider={provider} model={getattr(model, 'model_name', model)}")

    agent: Agent[MockSocketAgent, ReplayResult] = Agent(
        model,
        deps_type=MockSocketAgent,
        output_type=ReplayResult,
        system_prompt=SYSTEM_PROMPT,
        # gpt-oss sometimes emits malformed tool names; give it room to recover.
        retries=5,
    )

    @agent.tool
    def lock_socket(ctx: RunContext[MockSocketAgent], password: str) -> str:
        """Lock the mock socket with the given password."""
        print("[toolInvocation] lock_socket")
        ok = ctx.deps.lock(password)
        _send_comm("socket locked")
        return "locked" if ok else "already locked"

    @agent.tool
    def unlock_socket(ctx: RunContext[MockSocketAgent], password: str) -> str:
        """Unlock the mock socket with the given password."""
        print("[toolInvocation] unlock_socket")
        ok = ctx.deps.unlock(password)
        _send_comm("socket unlocked")
        return "unlocked" if ok else "unlock failed"

    @agent.tool
    def open_forwarded_socket(ctx: RunContext[MockSocketAgent], socket_id: str) -> str:
        """Open a forwarded agent socket (models `ssh -A` creating the channel)."""
        print("[toolInvocation] open_forwarded_socket")
        ctx.deps.open_forwarded_socket(socket_id)
        _send_comm(f"forwarded_socket opened socket_id={socket_id}")
        return f"opened forwarded socket {socket_id}"

    @agent.tool
    def attempt_session_bind(
        ctx: RunContext[MockSocketAgent], socket_id: str, session_id: str
    ) -> str:
        """Attempt session-bind@openssh.com on a socket. Fails while locked."""
        print("[toolInvocation] attempt_session_bind")

        ok = ctx.deps.attempt_session_bind(socket_id, session_id)
        _send_comm(f"session_bind attempted socket_id={socket_id}")
        return "bind recorded" if ok else "bind refused (agent locked)"

    @agent.tool
    def add_smartcard_provider(
        ctx: RunContext[MockSocketAgent], socket_id: str, provider_path: str
    ) -> dict:
        """Attempt to add a PKCS#11 provider via the given socket."""
        print("[toolInvocation] add_smartcard_provider")
        x = ctx.deps.add_smartcard_provider(socket_id, provider_path)
        _send_comm(f"smartcard_provider added socket_id={socket_id}")
        return x

    @agent.tool
    def get_log(ctx: RunContext[MockSocketAgent]) -> list[str]:
        """Return the simulated debug trace collected so far."""
        print("[toolInvocation] get_log")
        return list(ctx.deps.log)

    return agent


class RunRequest(BaseModel):
    socket_id: str = SOCKET_ID
    session_id: str = SESSION_ID
    provider_path: str = PROVIDER_PATH
    password: str = "agent-lock-proof"
    # Optional prior Blue defense report so Red can verify the claimed fix.
    blue_context: str | None = None
    # When True, replay against the hardened agent (post Blue fix).
    expect_blocked: bool = False


app = FastAPI(title="agent_red", description="Red-team threat replay agent")


async def _run_replay(req: RunRequest) -> ReplayResult:
    """Replay body. Weave tracing is best-effort and must not fail the HTTP response."""
    agent = build_agent()
    if req.expect_blocked:
        # Verify Blue's fix using the hardened state machine.
        blue_dir = Path(__file__).resolve().parents[1] / "agent_blue"
        if str(blue_dir) not in sys.path:
            sys.path.insert(0, str(blue_dir))
        from hardened_socket_agent import HardenedSocketAgent  # type: ignore

        deps = HardenedSocketAgent()
        subject = "hardened (Blue fix applied)"
    else:
        deps = MockSocketAgent()
        subject = "vulnerable mock"

    prompt = (
        "Run the forwarded-agent lock bypass replay using socket_id="
        f"{req.socket_id!r}, session_id={req.session_id!r}, "
        f"provider_path={req.provider_path!r}, and password={req.password!r}. "
        f"Subject under test: {subject}. "
    )
    if req.blue_context:
        prompt += (
            "Blue already proposed a fix / defense. Here is Blue's report:\n"
            f"{req.blue_context}\n\n"
            "Attempt the same attack sequence and report whether the bypass "
            "still reproduces against this subject. "
        )
    if req.expect_blocked:
        prompt += (
            "Blue reported the attack should now be blocked. Confirm whether "
            "provider-add is refused. Set reproduced true only if the bypass "
            "still succeeds on the hardened subject. "
        )
    prompt += "Report the final ReplayResult."

    result = await agent.run(prompt, deps=deps)
    output = result.output

    if _weave_info.get("ok"):
        try:
            import weave

            @weave.op(name="agent_red.run_replay")
            def _publish(payload: dict) -> dict:
                return payload

            _publish(output.model_dump())
        except Exception as exc:  # noqa: BLE001
            _log.warning("Weave publish failed (run still ok): %s", exc)

    return output


@app.post("/run", response_model=ReplayResult)
async def run(req: RunRequest = RunRequest()) -> ReplayResult:
    """Start a run of the forwarded-agent lock/provider-bypass replay."""
    try:
        return await _run_replay(req)
    except ModelAPIError as exc:
        _log.exception("Inference error")
        raise HTTPException(
            status_code=502,
            detail=f"W&B Inference error for {exc.model_name}: {exc.message}",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        _log.error("Run failed:\n%s", traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(exc) or repr(exc)) from exc


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "weave": {**_weave_info, **weave_status(which="red")}}


if __name__ == "__main__":
    import uvicorn

    print(f"[config] AGENT_COMM_PORT={AGENT_COMM_PORT}")
    print(f"[config] RED_AGENT_PORT={RED_AGENT_PORT}")
    print(f"[config] weave={_weave_info}")
    print(f"[config] llm={weave_status(which='red')}")
    uvicorn.run(app, host="127.0.0.1", port=RED_AGENT_PORT)
