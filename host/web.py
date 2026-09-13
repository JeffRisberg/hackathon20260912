"""UI plus pick / start / emergency-stop controls."""

from __future__ import annotations

import json
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, StreamingResponse
from starlette.routing import Route

from common.client import card_to_dict, discover
from common.mission import DEFAULT_DIFFICULTY, DEFAULT_REPO, DIFFICULTIES, MAX_ROUNDS, normalize_difficulty
from common.patch import check_payloads, live_file
from common.restore import restore_dvwa
from host.converse import ANALYZER_URL, HUNTER_URL
from host.session import SESSION

STATIC = Path(__file__).resolve().parent.parent / "static"


def _state() -> dict:
    mission = SESSION.mission or {}
    return {
        "repo": mission.get("repo") or str(DEFAULT_REPO),
        "bug": mission.get("bug") or "",
        "file": mission.get("file") or "",
        "title": mission.get("title") or "",
        "exploit_id": mission.get("exploit_id") or "",
        "difficulty": mission.get("difficulty") or SESSION.difficulty or DEFAULT_DIFFICULTY,
        "difficulties": list(DIFFICULTIES),
        "running": SESSION.running,
        "done": SESSION.done,
        "picked": bool(SESSION.mission_obj),
        "checks": mission.get("checks") or [],
        "max_rounds": mission.get("max_rounds") or MAX_ROUNDS,
        "run_id": SESSION.run_id,
    }


async def index(_request: Request) -> FileResponse:
    return FileResponse(
        STATIC / "index.html",
        headers={"Cache-Control": "no-store"},
    )


async def defaults(_request: Request) -> JSONResponse:
    state = _state()
    if state.get("file"):
        state["content"] = live_file(DEFAULT_REPO, state["file"])
    return JSONResponse(state)


async def cards(_request: Request) -> JSONResponse:
    hunter = await discover(HUNTER_URL)
    analyzer = await discover(ANALYZER_URL)
    return JSONResponse(
        {
            "hunter": card_to_dict(hunter),
            "analyzer": card_to_dict(analyzer),
        }
    )


async def _read_json(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


async def pick(request: Request) -> JSONResponse:
    body = await _read_json(request)
    if body.get("difficulty"):
        SESSION.difficulty = normalize_difficulty(str(body["difficulty"]))
    try:
        mission = SESSION.pick()
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc), **_state()}, status_code=409)
    source = live_file(DEFAULT_REPO, mission.get("file") or "")
    return JSONResponse({**_state(), **mission, "content": source})


async def difficulty(request: Request) -> JSONResponse:
    body = await _read_json(request)
    try:
        result = SESSION.set_difficulty(str(body.get("difficulty") or ""), keep_exploit=True)
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc), **_state()}, status_code=409)
    path = result.get("file") if isinstance(result, dict) else ""
    source = live_file(DEFAULT_REPO, path or "")
    payload = {**_state(), **(result if isinstance(result, dict) else {})}
    if source:
        payload["content"] = source
    return JSONResponse(payload)


async def start(_request: Request) -> JSONResponse:
    try:
        SESSION.start()
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc), **_state()}, status_code=409)
    return JSONResponse(_state())


async def stop(_request: Request) -> JSONResponse:
    SESSION.abort()
    return JSONResponse(_state())


async def revert(_request: Request) -> JSONResponse:
    if SESSION.running:
        SESSION.abort()
    try:
        restored = restore_dvwa()
    except OSError as exc:
        return JSONResponse({"error": str(exc), **_state()}, status_code=500)
    path = SESSION.mission.get("file") if SESSION.mission else f"vulnerabilities/exec/source/{SESSION.difficulty}.php"
    source = live_file(DEFAULT_REPO, path)
    exploit_id = SESSION.mission.get("exploit_id") if SESSION.mission else ""
    return JSONResponse(
        {
            **_state(),
            "restored": restored,
            "file": path,
            "content": source,
            "checks": check_payloads(exploit_id, source) if exploit_id and source else [],
            "text": "DVWA restored to the stock snapshot.",
        }
    )


async def conversation(_request: Request) -> StreamingResponse:
    async def events():
        try:
            async for event in SESSION.watch():
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'error', 'text': str(exc)})}\n\n"

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


app = Starlette(
    routes=[
        Route("/", index),
        Route("/api/defaults", defaults),
        Route("/api/cards", cards),
        Route("/api/pick", pick, methods=["POST"]),
        Route("/api/difficulty", difficulty, methods=["POST"]),
        Route("/api/start", start, methods=["POST"]),
        Route("/api/stop", stop, methods=["POST"]),
        Route("/api/revert", revert, methods=["POST"]),
        Route("/api/talk", conversation),
    ]
)
