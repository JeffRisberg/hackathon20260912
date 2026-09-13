"""PydanticAI agent that defends against the forwarded-agent lock/provider
bypass described in ../README.md.

It combines two independent defenses and reports on both:

1. Runtime fix -- replays the same attack sequence used in ../agent_sim
   against HardenedSshAgent (hardened_socket_agent.py) and confirms the
   provider-add is now refused.
2. Log-based detection -- runs detect_bypass_signature() over a raw debug
   log (e.g. the shape of ../evidence/stock-openssh-10.4p1.txt) to flag the
   attack ordering even against an agent you can't patch yet.

Everything here is in-process simulation / static log analysis: no real
sockets, processes, or PKCS#11 modules, and no connection to a real target.

Usage:
    pip install -r requirements.txt
    python agent.py                # real model, narrated
"""

from __future__ import annotations

import os
import socket
import threading
from datetime import datetime, timezone
from enum import Enum

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

from hardened_socket_agent import HardenedSocketAgent, detect_bypass_signature

load_dotenv()

AGENT_COMM_PORT = int(os.environ.get("AGENT_COMM_PORT", "8765"))
BLUE_AGENT_PORT = int(os.environ.get("BLUE_AGENT_PORT", "8001"))

SOCKET_ID = "fwd-0"
SESSION_ID = "session-abc123"
PROVIDER_PATH = "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so"

# A log trace shaped like ../evidence/stock-openssh-10.4p1.txt, i.e. what an
# *unpatched* real agent would emit during a successful attack. The detector
# is run against this to show it flags the pattern independent of the
# runtime fix.
SAMPLE_UNPATCHED_LOG = [
    "socket locked",
    "process_message: socket 1 (fd=4) type 27",
    "socket unlocked",
    "process_message: socket 1 (fd=4) type 20",
    "process_add_smartcard_key: add /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so",
]

SYSTEM_PROMPT = """\
You are a defensive security agent countering a specific OpenSSH ssh-agent
bug: a forwarded agent socket can bypass the remote-provider restriction
because a session-bind attempted while the agent is locked is silently
dropped, so the socket is later misclassified as local once the agent is
unlocked.

You have two independent defenses to exercise and report on, using only the
tools provided (everything is a simulation or static log analysis -- no real
network, process, or module access):

1. Runtime fix: replay the attack sequence against the hardened agent tools
   (lock_agent, open_forwarded_socket, attempt_session_bind,
   unlock_agent, add_smartcard_provider) in that order, using
   socket_id, session_id, provider_path, and password given in the prompt.
   Confirm the provider-add is refused.
2. Detection: call detect_bypass_signature on the sample unpatched log to
   confirm the attack ordering is still flagged even without the runtime
   fix in place.

Call get_log after the replay to capture the full simulated trace. Then
produce the final DefenseReport. Set `attack_blocked` true only if the
hardened runtime actually refused the provider-add, and
`log_pattern_detected` true only if detect_bypass_signature reported a match.

Refuse and explain if asked to run this against a real host, real ssh-agent,
or real log files instead of the provided simulation and sample log.
"""


# Collects the results of a full replay of the bypass sequence, including the
# final narrative and the simulated debug trace.
class DefenseReport(BaseModel):
    attack_blocked: bool = Field(
        description="True if the hardened runtime refused the provider-add on the forwarded socket."
    )
    blocking_reason: str = Field(description="Why the request was accepted or refused.")
    log_pattern_detected: bool = Field(
        description="True if detect_bypass_signature flagged the attack ordering in the sample log."
    )
    recommendation: str = Field(
        description="Concrete mitigation advice, referencing the README's Repair Direction."
    )
    narrative: str = Field(description="Plain-English walkthrough of both defenses and the result.")
    log: list[str] = Field(description="Simulated hardened-agent debug trace, in order.")


class BlueAgentStatus(str, Enum):
    WAITING = "waiting"
    DEFENDING = "defending"


# One entry per status transition, recording when a defense run started
# (DEFENDING) or finished (WAITING).
class ExecutionRecord(BaseModel):
    timestamp: datetime
    status: BlueAgentStatus


class BlueAgent:
    """Bundles the pydantic_ai agent with its HardenedSocketAgent deps and
    the UDP listener that watches for agent_red's comm messages."""

    def __init__(self, deps: HardenedSocketAgent) -> None:
        self.deps = deps
        self.status = BlueAgentStatus.WAITING
        self.lastMessage: str | None = None
        self.executions: list[ExecutionRecord] = []

    def _record_execution(self, status: BlueAgentStatus) -> None:
        self.status = status
        self.executions.append(
            ExecutionRecord(timestamp=datetime.now(timezone.utc), status=status)
        )

    def listen_for_comm(self, port: int) -> None:
        """Listen for messages from agent_red on `port`, print each one, and
        switch to DEFENDING when a "socket locked" message is received.
        Blocks forever."""
        print("Listening on port {}".format(port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port))
        while True:
            data, _ = sock.recvfrom(4096)
            message = data.decode()
            print(f"[agent_comm] {message}")
            self.lastMessage = message
            if message == "socket locked":
                self._record_execution(BlueAgentStatus.DEFENDING)
                print("Threat Detected")
            elif "smartcard_provider added" in message:
                self._record_execution(BlueAgentStatus.WAITING)
                print("Threat Resolved\n")


def build_agent() -> BlueAgent:
    model = os.environ.get("PYDANTIC_AI_MODEL")

    agent: Agent[HardenedSocketAgent, DefenseReport] = Agent(
        model,
        deps_type=HardenedSocketAgent,
        output_type=DefenseReport,
        system_prompt=SYSTEM_PROMPT,
    )

    deps = HardenedSocketAgent()
    return BlueAgent(deps)


blue_agent: BlueAgent | None = None

app = FastAPI()


@app.get("/status")
def get_status() -> dict:
    return {"status": blue_agent.status, "last_message": blue_agent.lastMessage}


@app.get("/executions")
def get_executions() -> list[ExecutionRecord]:
    return blue_agent.executions


def main() -> None:
    global blue_agent

    print(f"[config] AGENT_COMM_PORT={AGENT_COMM_PORT}")
    print(f"[config] BLUE_AGENT_PORT={BLUE_AGENT_PORT}")

    # agent_red/agent.py for information about the attack. The UDP listener
    # runs in the background so the FastAPI server can serve status in the
    # foreground.
    blue_agent = build_agent()
    threading.Thread(
        target=blue_agent.listen_for_comm, args=(AGENT_COMM_PORT,), daemon=True
    ).start()

    uvicorn.run(app, host="127.0.0.1", port=BLUE_AGENT_PORT)


if __name__ == "__main__":
    main()
