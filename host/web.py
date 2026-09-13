"""Small UI so you can watch the two A2A agents talk."""

from __future__ import annotations

import json
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, StreamingResponse
from starlette.routing import Route

from common.client import card_to_dict, discover
from host.converse import ANALYZER_URL, HUNTER_URL, talk

STATIC = Path(__file__).resolve().parent.parent / "static"


async def index(_request: Request) -> FileResponse:
    return FileResponse(
        STATIC / "index.html",
        headers={"Cache-Control": "no-store"},
    )


async def cards(_request: Request) -> JSONResponse:
    hunter = await discover(HUNTER_URL)
    analyzer = await discover(ANALYZER_URL)
    return JSONResponse(
        {
            "hunter": card_to_dict(hunter),
            "analyzer": card_to_dict(analyzer),
        }
    )


def _files(raw: object) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    files: list[dict[str, str]] = []
    for item in raw[:150]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("path") or "").strip()[:400]
        content = str(item.get("content") or "")[:200_000]
        if name and content.strip():
            files.append({"name": name, "content": content})
    return files


async def conversation(request: Request) -> StreamingResponse:
    body = await request.json()
    repo = str(body.get("repo") or "").strip()
    bug = str(body.get("bug") or "").strip()
    files = _files(body.get("files"))
    if not repo and not files:
        return JSONResponse({"error": "repository is required"}, status_code=400)
    if not bug:
        return JSONResponse({"error": "bug fix is required"}, status_code=400)

    async def events():
        try:
            async for event in talk(repo, bug, files):
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
        Route("/api/cards", cards),
        Route("/api/talk", conversation, methods=["POST"]),
    ]
)
