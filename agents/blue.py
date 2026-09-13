"""Claude — an A2A server that chats with Gemini."""

from __future__ import annotations

from a2a.types import AgentSkill

from common.executor import PromptAgentExecutor
from common.llm import CLAUDE_MODEL, complete
from common.server import build_card, serve

HOST = "127.0.0.1"
PORT = 10021
URL = f"http://{HOST}:{PORT}"

SYSTEM = """You are Agent Blue. You receive only the repository regions that match the bug. 
Identify the vulnerable code and propose a concrete fix, naming file and line. 
If Agent Red challenges you, revise that same region."""


def respond(user_text: str) -> str:
    return complete(SYSTEM, user_text, provider="claude")


def main() -> None:
    skill = AgentSkill(
        id="chat",
        name="Chat",
        description="Claude proposes a fix from a repo and a bug",
        input_modes=["text/plain"],
        output_modes=["text/plain"],
        tags=["chat", "claude", "blue"],
        examples=["Propose a fix for this repository bug"],
    )
    card = build_card(
        name="Claude",
        description=f"Anthropic {CLAUDE_MODEL}. Agent Blue. Proposes the fix, then revises it.",
        url=URL,
        skill=skill,
    )
    print(f"Claude listening on {URL}")
    print(f"Agent card: {URL}/.well-known/agent-card.json")
    serve(PromptAgentExecutor(respond), card, HOST, PORT)


if __name__ == "__main__":
    main()
