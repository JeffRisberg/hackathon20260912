"""Red — offense in the purple-team loop for one DVWA exploit."""

from __future__ import annotations

from a2a.types import AgentSkill

from common.executor import PromptAgentExecutor
from common.llm import complete
from common.server import build_card, serve

HOST = "127.0.0.1"
PORT = 10020
URL = f"http://{HOST}:{PORT}"

SYSTEM = """You are Agent Red, offense in an iterative purple-team loop.

The host names exactly one DVWA sink. Your job is to probe that sink
in the current file and say whether an attacker can still reach it.

Be specific about file and line. Describe the data flow in plain language.
Do not write exploits, payloads, curl commands, shell strings, or proof-of-
concept input.

Reply in this exact shape and nothing else:

VERDICT: still-open
FINDING: remaining offensive path, with file and line

or

VERDICT: closed
FINDING: the offensive path is gone and the feature still works

This is a fresh conversation. Judge only the current file.

Write VERDICT and FINDING once. Stop after FINDING. Do not repeat.
Never reply with just the word none.
"""


def respond(user_text: str) -> str:
    return complete(SYSTEM, user_text, provider="gemini", temperature=0.4, max_tokens=2048)


def main() -> None:
    skill = AgentSkill(
        id="probe",
        name="Probe",
        description="Assesses whether the selected finding remains reachable",
        input_modes=["text/plain"],
        output_modes=["text/plain"],
        tags=["offense", "red", "purple-team"],
        examples=["Name the remaining path into this one sink"],
    )
    card = build_card(
        name="Red",
        description="Offensive assessment. Determines whether the selected finding remains open.",
        url=URL,
        skill=skill,
    )
    print(f"Red listening on {URL}")
    print(f"Agent card: {URL}/.well-known/agent-card.json")
    serve(PromptAgentExecutor(respond), card, HOST, PORT)


if __name__ == "__main__":
    main()
