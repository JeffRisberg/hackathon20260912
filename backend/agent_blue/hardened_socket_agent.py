"""In-process model of a *fixed* ssh-agent, plus a standalone log-pattern
detector for the bypass described in ../README.md.

Two independent layers of defense, matching how this would actually be
mitigated in production before/without a same-day OpenSSH upgrade:

1. HardenedSshAgent -- fixes the root cause: a forwarded socket is classified
   remote by default (fail-safe), and a session-bind attempt is recorded
   whether or not the agent happens to be locked at the time. This directly
   addresses the README's "Repair Direction": process session-bind@openssh.com
   while locked so the per-socket security state is recorded before any later
   unlock.
2. detect_bypass_signature -- a detection rule over raw debug-log lines (the
   same shape as evidence/stock-openssh-10.4p1.txt) that flags the attack
   ordering even when running against an unpatched/real agent you cannot
   modify, so it can be pointed at real ssh-agent/sshd debug output for
   monitoring or alerting.

No real sockets, processes, or PKCS#11 modules are involved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SocketState:
    socket_id: str
    forwarded: bool
    session_bind_attempted: bool = False
    session_bind_succeeded: bool = False

    def is_remote(self) -> bool:
        """Fail-safe default: any forwarded socket is remote unless a bind
        explicitly succeeded. Unlike the vulnerable socket_is_remote(), an
        *unattempted or failed* bind never falls back to "local"."""
        if not self.forwarded:
            return False
        return not self.session_bind_succeeded


class HardenedSocketAgent:
    """Fixes the ordering bug: session-bind is processed regardless of lock
    state, so the per-socket marker is always recorded before any later
    unlock can be used to smuggle a provider-add through."""

    def __init__(self) -> None:
        self.locked = False
        self._password: str | None = None
        self.sockets: dict[str, SocketState] = {}
        self.log: list[str] = []

    def _emit(self, line: str) -> None:
        self.log.append(line)

    def lock(self, password: str) -> bool:
        if self.locked:
            self._emit("lock: already locked")
            return False
        self._password = password
        self.locked = True
        self._emit("agent locked")
        return True

    def unlock(self, password: str) -> bool:
        if not self.locked:
            self._emit("unlock: already unlocked")
            return False
        if password != self._password:
            self._emit("unlock: incorrect passphrase")
            return False
        self.locked = False
        self._password = None
        self._emit("agent unlocked")
        return True

    def open_forwarded_socket(self, socket_id: str) -> SocketState:
        state = SocketState(socket_id=socket_id, forwarded=True)
        self.sockets[socket_id] = state
        self._emit(f"channel: new agent-connection [{socket_id}]")
        return state

    def attempt_session_bind(self, socket_id: str, session_id: str) -> bool:
        """Fix: process the extension (and record the marker) even while
        locked, instead of discarding it at the locked gate."""
        state = self.sockets[socket_id]
        state.session_bind_attempted = True
        if self.locked:
            self._emit(
                f"process_ext_session_bind: socket {socket_id} recorded while locked "
                f"(session {session_id}); bind not yet verified"
            )
            state.session_bind_succeeded = False
            return False

        state.session_bind_succeeded = True
        self._emit(f"process_ext_session_bind: socket {socket_id} bound session {session_id}")
        return True

    def add_smartcard_provider(self, socket_id: str, provider_path: str) -> dict:
        state = self.sockets[socket_id]
        if state.is_remote():
            self._emit(
                f"process_add_smartcard_key: socket {socket_id} classified remote, request refused"
            )
            return {"accepted": False, "reason": "remote-provider-restriction"}

        self._emit(f"process_add_smartcard_key: add {provider_path}")
        self._emit("pkcs11_start_helper: starting ssh-pkcs11-helper (simulated)")
        self._emit(f"provider {provider_path}: initialized (simulated)")
        return {"accepted": True, "reason": "socket verified local"}


# --------------------------------------------------------------------------
# Log-based detection rule (works against a real, unpatched agent's logs)
# --------------------------------------------------------------------------

_LOCK_RE = re.compile(r"\bagent locked\b")
_BIND_REJECTED_RE = re.compile(r"process_message:.*type[= ]27|session-bind.*rejected")
_UNLOCK_RE = re.compile(r"\bagent unlocked\b")
_PROVIDER_ADD_RE = re.compile(r"process_add_smartcard_key: add|process_add_identity:")


def detect_bypass_signature(log_lines: list[str]) -> dict:
    """Flags the exploit's required ordering: a bind rejection while locked,
    followed later by unlock, followed later by a provider-add -- on the same
    log stream, in that order. This does not require the agent to be patched;
    it is a monitoring rule over its debug output.
    """
    lock_idx = bind_rejected_idx = unlock_idx = provider_idx = -1
    for i, line in enumerate(log_lines):
        if lock_idx == -1 and _LOCK_RE.search(line):
            lock_idx = i
        elif lock_idx != -1 and bind_rejected_idx == -1 and _BIND_REJECTED_RE.search(line):
            bind_rejected_idx = i
        elif bind_rejected_idx != -1 and unlock_idx == -1 and _UNLOCK_RE.search(line):
            unlock_idx = i
        elif unlock_idx != -1 and provider_idx == -1 and _PROVIDER_ADD_RE.search(line):
            provider_idx = i

    matched = lock_idx < bind_rejected_idx < unlock_idx < provider_idx
    return {
        "matched": matched,
        "lock_line": lock_idx,
        "bind_rejected_line": bind_rejected_idx,
        "unlock_line": unlock_idx,
        "provider_add_line": provider_idx,
    }
