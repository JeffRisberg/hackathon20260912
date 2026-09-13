"""In-process simulation of the vulnerable ssh-agent state machine.

No real sockets, processes, or PKCS#11 modules are involved. This models only the
control-flow described in the PoC README's Root Cause section, so the bypass can be
demonstrated and taught without touching a real OpenSSH installation.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SocketState:
    socket_id: str
    forwarded: bool
    session_bind_attempted: bool = False
    session_id_count: int = 0

    def is_remote(self) -> bool:
        """Mirrors socket_is_remote(): remote iff a bind was recorded."""
        return self.session_bind_attempted or self.session_id_count > 0


class ProtocolError(Exception):
    pass


class MockSocketAgent:
    """Reproduces the locked-gate-before-extension-dispatch ordering bug."""

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
        self._emit("socket locked")
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
        self._emit("socket unlocked")
        return True

    def open_forwarded_socket(self, socket_id: str) -> SocketState:
        """Models client_request_agent(): the channel opens even if bind fails."""
        state = SocketState(socket_id=socket_id, forwarded=True)
        self.sockets[socket_id] = state
        self._emit(f"channel: new agent-connection [{socket_id}]")
        return state

    def attempt_session_bind(self, socket_id: str, session_id: str) -> bool:
        """Models process_message() applying the locked gate before process_extension().

        While locked, every extension request -- including session-bind@openssh.com --
        is discarded before process_ext_session_bind() can run, so the bind marker is
        never set on the socket.
        """
        state = self.sockets[socket_id]
        if self.locked:
            self._emit(
                f"process_message: socket {socket_id} type=session-bind rejected (locked gate)"
            )
            return False
        state.session_bind_attempted = True
        state.session_id_count += 1
        self._emit(f"process_ext_session_bind: socket {socket_id} bound session {session_id}")
        return True

    def add_smartcard_provider(self, socket_id: str, provider_path: str) -> dict:
        """Models process_add_smartcard_key() consulting socket_is_remote()."""
        state = self.sockets[socket_id]
        if state.is_remote():
            self._emit(
                f"process_add_smartcard_key: socket {socket_id} classified remote, request refused"
            )
            return {"accepted": False, "reason": "remote-provider-restriction"}

        self._emit(f"process_add_smartcard_key: add {provider_path}")
        self._emit("pkcs11_start_helper: starting ssh-pkcs11-helper (simulated)")
        self._emit(f"provider {provider_path}: initialized (simulated)")
        return {"accepted": True, "reason": "socket misclassified as local"}
