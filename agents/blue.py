"""Blue — defense in the purple-team loop for one DVWA exploit."""

from __future__ import annotations

from a2a.types import AgentSkill

from common.executor import PromptAgentExecutor
from common.llm import complete
from common.server import build_card, serve

HOST = "127.0.0.1"
PORT = 10021
URL = f"http://{HOST}:{PORT}"

SYSTEM = """You are Agent Blue, defense in an iterative purple-team loop.

The host names exactly one DVWA sink. Red just reported an offensive
path. Patch only that path. Keep the feature working. Do not touch
other vulnerability modules or any other bug.

This is a fresh conversation. Ignore any earlier DVWA hardening you remember.
Change one small thing this turn. One SEARCH/REPLACE hunk only.
Do not rewrite the file into a complete hardened version.

Write the file change. Do not write a proof of concept.

Reply in this exact shape and nothing else:

STATUS: defend
SUMMARY: what you changed and why it blocks Red's path
FILE: the file the host named
<<<<<<< SEARCH
exact lines from the current file
=======
replacement lines
>>>>>>> REPLACE

Use STATUS: revise when Red still found a path after your last write.
Copy SEARCH from the unnumbered source. One hunk only.
Write each field once. Stop after REPLACE. Do not repeat the hunk.
"""


def respond(user_text: str) -> str:
    return complete(SYSTEM, user_text, provider="claude", temperature=0.55, max_tokens=2048)


def main() -> None:
    skill = AgentSkill(
        id="defend",
        name="Defend",
        description="Applies a focused remediation to the path Red Team identified",
        input_modes=["text/plain"],
        output_modes=["text/plain"],
        tags=["defense", "blue", "purple-team", "patch"],
        examples=["Patch the one DVWA sink Red just called out"],
    )
    card = build_card(
        name="Blue",
        description="Defensive remediation. Hardens the path identified by Red Team.",
        url=URL,
        skill=skill,
    )
    print(f"Blue listening on {URL}")
    print(f"Agent card: {URL}/.well-known/agent-card.json")
    serve(PromptAgentExecutor(respond), card, HOST, PORT)


if __name__ == "__main__":
    main()
