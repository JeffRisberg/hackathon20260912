"""PydanticAI agent that walks through the mock ssh-agent state machine
(mock_socket_agent.py) to demonstrate the forwarded-agent lock/provider-bypass bug
described in ../README.md.

This is a teaching/demo tool: every "agent" and "socket" here is an in-process
Python object. Nothing connects to a network, spawns ssh/ssh-agent/sshd, or
touches a real PKCS#11 module. Do not point this at, or treat its output as
evidence about, systems you do not own or have permission to test -- for a
real replay, use ../run.sh instead.

Usage:
    python agent.py                # offline demo, no API key needed (TestModel)
    PYDANTIC_AI_MODEL=openai:gpt-4o-mini OPENAI_API_KEY=... python agent.py

Configuration can also be supplied via a .env file in this directory
(see .env.sample for the template); values already set in the environment
take precedence over .env.
"""

from __future__ import annotations

import os
import socket

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from mock_socket_agent import MockSocketAgent

load_dotenv()

AGENT_COMM_PORT = int(os.environ.get("AGENT_COMM_PORT", "8765"))

# UDP socket to agent_blue: fire-and-forget so agent_red still runs standalone
# (e.g. in tests) when nothing is listening on AGENT_COMM_PORT.
_comm_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def _send_comm(message: str) -> None:
    try:
        _comm_socket.sendto(message.encode(), ("127.0.0.1", AGENT_COMM_PORT))
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
    model = os.environ.get("PYDANTIC_AI_MODEL")
    if not model:
        from pydantic_ai.models.test import TestModel

        model = TestModel()

    agent: Agent[MockSocketAgent, ReplayResult] = Agent(
        model,
        deps_type=MockSocketAgent,
        output_type=ReplayResult,
        system_prompt=SYSTEM_PROMPT,
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


def main() -> None:
    print(f"[config] AGENT_COMM_PORT={AGENT_COMM_PORT}")

    agent = build_agent()
    deps = MockSocketAgent()

    prompt = (
        "Run the forwarded-agent lock bypass replay using socket_id="
        f"{SOCKET_ID!r}, session_id={SESSION_ID!r}, provider_path={PROVIDER_PATH!r}, "
        "and password='agent-lock-proof'. Report the final ReplayResult."
    )
    result = agent.run_sync(prompt, deps=deps)

    print(result.output.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
