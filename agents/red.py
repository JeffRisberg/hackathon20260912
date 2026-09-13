"""Gemini — an A2A server that chats with Claude."""

from __future__ import annotations

from a2a.types import AgentSkill

from common.executor import PromptAgentExecutor
from common.llm import GEMINI_MODEL, complete
from common.server import build_card, serve

HOST = "127.0.0.1"
PORT = 10020
URL = f"http://{HOST}:{PORT}"

SYSTEM = """You are Agent Red. Agent Blue proposes a fix for the focused repository regions. Challenge that fix. Point at a hole, a missed line, or a missing test in those same files."""


def respond(user_text: str) -> str:
    return complete(SYSTEM, user_text, provider="gemini")


def main() -> None:
    skill = AgentSkill(
        id="chat",
        name="Chat",
        description="Gemini challenges Claude's proposed fix",
        input_modes=["text/plain"],
        output_modes=["text/plain"],
        tags=["chat", "gemini", "red"],
        examples=["Challenge this SQL injection fix"],
    )
    card = build_card(
        name="Gemini",
        description=f"Google {GEMINI_MODEL}. Agent Red. Challenges the proposed fix.",
        url=URL,
        skill=skill,
    )
    print(f"Gemini listening on {URL}")
    print(f"Agent card: {URL}/.well-known/agent-card.json")
    serve(PromptAgentExecutor(respond), card, HOST, PORT)


if __name__ == "__main__":
    main()
