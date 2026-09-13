"""Host-owned purple-team loop with pick, start, and emergency stop."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from typing import Any

from common.mission import (
    DEFAULT_DIFFICULTY,
    Mission,
    build_mission,
    mission_payload,
    normalize_difficulty,
)
from host.converse import talk

EOF = {"type": "eof"}


class LoopSession:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.subscribers: list[asyncio.Queue] = []
        self.task: asyncio.Task | None = None
        self.done = False
        self.mission: dict[str, Any] | None = None
        self.mission_obj: Mission | None = None
        self.difficulty = DEFAULT_DIFFICULTY
        self.run_id = uuid.uuid4().hex[:8]
        self.cancel = asyncio.Event()

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()

    def pick(self, exploit_id: str = "") -> dict[str, Any]:
        if self.running:
            raise RuntimeError("Stop the current run before picking another exploit.")
        self.run_id = uuid.uuid4().hex[:8]
        mission = build_mission(difficulty=self.difficulty, exploit_id=exploit_id)
        self.mission_obj = mission
        self.mission = mission_payload(mission)
        self.events = [self._stamp(self.mission)]
        self.done = False
        self.cancel = asyncio.Event()
        return self.mission

    def set_difficulty(self, difficulty: str, keep_exploit: bool = False) -> dict[str, Any]:
        if self.running:
            raise RuntimeError("Stop the current run before changing difficulty.")
        self.difficulty = normalize_difficulty(difficulty)
        if keep_exploit and self.mission_obj is not None:
            return self.pick(exploit_id=self.mission_obj.exploit_id)
        return {"difficulty": self.difficulty}

    def start(self) -> dict[str, Any]:
        if self.running:
            raise RuntimeError("The agents are already running.")
        if self.mission_obj is None:
            self.pick()
        self.run_id = uuid.uuid4().hex[:8]
        self.events = [self._stamp(self.mission)] if self.mission else []
        self.done = False
        self.cancel = asyncio.Event()
        self.task = asyncio.create_task(self._run())
        return self.mission or {}

    def abort(self) -> dict[str, Any]:
        self.cancel.set()
        if self.task and not self.task.done():
            self.task.cancel()
        return {"aborted": True, "running": False}

    def _stamp(self, event: dict[str, Any]) -> dict[str, Any]:
        return {**event, "id": len(self.events) + 1}

    async def _run(self) -> None:
        try:
            async for event in talk(mission=self.mission_obj, cancel=self.cancel, run_id=self.run_id):
                if event.get("type") == "mission":
                    self.mission = event
                stamped = self._stamp(event)
                self.events.append(stamped)
                await self._fanout(stamped)
        except asyncio.CancelledError:
            event = self._stamp(
                {
                    "type": "done",
                    "closed": False,
                    "aborted": True,
                    "text": "Emergency stop. The agents were aborted.",
                }
            )
            self.events.append(event)
            await self._fanout(event)
        except Exception as exc:
            event = self._stamp({"type": "error", "text": str(exc)})
            self.events.append(event)
            await self._fanout(event)
        finally:
            self.done = True
            await self._fanout(EOF)

    async def _fanout(self, event: dict[str, Any]) -> None:
        for queue in list(self.subscribers):
            await queue.put(event)

    async def watch(self) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue = asyncio.Queue()
        self.subscribers.append(queue)
        try:
            for event in self.events:
                yield event
            if self.done and not self.running:
                return
            while True:
                event = await queue.get()
                if event.get("type") == "eof":
                    return
                yield event
        finally:
            if queue in self.subscribers:
                self.subscribers.remove(queue)


SESSION = LoopSession()
