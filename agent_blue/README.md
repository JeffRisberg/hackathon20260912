# Agent Blue

## PydanticAI defense agent

A PydanticAI agent that defends against the forwarded-agent lock/provider
bypass described in [`../README.md`](../README.md) (see also the attack
simulation in [`../agent_sim`](../agent_sim)). Two independent, complementary
defenses, both simulated / static -- no real sockets, processes, PKCS#11
modules, or connection to a real target:

| Layer | File                                                      | What it does |
| --- |-----------------------------------------------------------| --- |
| Runtime fix | `hardened_socket_agent.py` -> `HardenedSocketAgent`       | Fixes the root cause: `attempt_session_bind` records its marker whether or not the agent is locked (instead of being silently dropped at the locked gate), and socket classification is fail-safe -- a forwarded socket is remote by default and only becomes "local" on an explicit successful bind. Replaying the exact attack sequence from `agent_sim` now gets refused. |
| Detection | `hardened_socket_agent.py` -> `detect_bypass_signature()` | A log-pattern rule over raw debug lines (same shape as `../evidence/stock-openssh-10.4p1.txt`) that flags the required attack ordering -- lock, bind-rejected-while-locked, unlock, provider-add -- even against a real, unpatched agent's logs you can't modify. |
| Agent | `agent.py`                                                | PydanticAI `Agent` with tools over both layers; replays the attack against the hardened runtime, runs the detector against a bundled sample unpatched log, and reports a structured `DefenseReport`. |

## Setup

Create and activate a virtual environment, then install dependencies:

```sh
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in this directory (never commit it) with your model and key:

```sh
# .env
PYDANTIC_AI_MODEL=openai:gpt-4o-mini
OPENAI_API_KEY=sk-...
```

# Run it

```sh
python agent.py
```

## Scope

This hardens and detects the *pattern* described in the README, modeled in
Python. It does not patch real OpenSSH source, and `detect_bypass_signature`
is a simple ordered-regex rule meant as a starting point for a real log
monitor, not a production-grade parser. For real remediation, apply the
README's Repair Direction to the actual OpenSSH source (process
`session-bind@openssh.com` while locked) and/or point a real log pipeline's
equivalent rule at production `ssh-agent`/`sshd` debug output.
