# Two A2A agents talking

A local version of the [Google Cloud A2A guide](https://medium.com/google-cloud/a-practical-guide-to-building-multi-agents-ai-systems-with-a2a-2c0e3d77af24): two specialist agents publish **agent cards**, a host discovers those cards, and they pass work over the Agent2Agent protocol.

The original notebook needs Vertex AI, Google Search, and an older ADK pin. This repo uses the current `a2a-sdk` and runs on your laptop.

```
you
  └─ host (orchestrator)
       ├─ discovers  GET http://127.0.0.1:10020/.well-known/agent-card.json
       ├─ discovers  GET http://127.0.0.1:10021/.well-known/agent-card.json
       ├─ Gemini        :10020   research
       └─ Claude        :10021   briefing, then a follow-up turn
```

## Run

Needs Python 3.13 (already selected via `uv`).

```bash
cd /Users/suryaanand/Downloads/HackathonRedBlue
uv sync
uv run python run_demo.py
```

Then open [http://127.0.0.1:8080](http://127.0.0.1:8080) and give them a topic.

CLI only:

```bash
# terminals 1 and 2
uv run python -m agents.hunter
uv run python -m agents.analyzer

# terminal 3
uv run python -m host.converse "electric bikes in NYC"
```

## Keys (Gemini ↔ Claude)

Copy `.env.example` to `.env` and add both keys there. Do not paste keys into chat.

```
GEMINI_API_KEY=...
ANTHROPIC_API_KEY=...
```

Gemini runs the hunter on `:10020`. Claude (Anthropic) runs the analyzer on `:10021`. Without keys they still talk over A2A using a local fallback.
