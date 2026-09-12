# AgentRed

## PydanticAI simulation agent

A PydanticAI agent that walks through the forwarded-agent lock/provider-bypass
described in [`../README.md`](../README.md) against an **in-process mock**
of the vulnerable `ssh-agent` state machine -- not a real agent, socket, or
PKCS#11 module. It is for explaining and demoing the bug (talks, onboarding,
regression-test design discussions), not for reproducing it against a real
target. For an actual replay against real OpenSSH binaries, use `../run.sh`.

## Files

| Path | Purpose |
| --- | --- |
| `mock_agent.py` | Pure-Python state machine reproducing only the control-flow ordering from the README's Root Cause section: the locked gate runs before extension dispatch, so a bind attempted while locked never sets `session_bind_attempted`, so `socket_is_remote()` misclassifies the forwarded socket after unlock. |
| `agent.py` | PydanticAI `Agent` with tools (`lock_agent`, `unlock_agent`, `open_forwarded_socket`, `attempt_session_bind`, `add_smartcard_provider`, `get_log`) bound to one `MockSshAgent` instance, and a structured `ReplayResult` output. |

## Usage

Create and activate a virtual environment, then install dependencies:

```sh
python3 -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Set up .env file, based on .env.sample:


```
PYDANTIC_AI_MODEL=openai:gpt-4o-mini   # or anthropic:claude-..., etc.
OPENAI_API_KEY=...                     # matching provider key
```

# run it

```
python agent.py
```

## What it proves and doesn't prove

`mock_agent.py` encodes the same *ordering bug* as the real code (locked gate
before extension dispatch; `socket_is_remote()` keyed off a bind marker that a
locked bind can't set) but has no real network I/O, no real OpenSSH source,
and no real PKCS#11 loading. Treat its `reproduced: true` output as a model
of the bug for teaching and test-case design, not as evidence about any real
system's patch status -- use `../run.sh` against real binaries for that.
