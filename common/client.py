"""Discover an agent card and send it a message over A2A."""

from __future__ import annotations

from google.protobuf.json_format import MessageToDict

from a2a.client import A2ACardResolver, ClientConfig, create_client
from a2a.helpers import get_message_text, new_text_message
from a2a.types import AgentCard, Role, SendMessageRequest
import httpx


def card_to_dict(card: AgentCard) -> dict:
    return MessageToDict(card, preserving_proto_field_name=True)


def extract_text(chunk) -> str:
    pieces: list[str] = []
    if chunk.HasField("task"):
        for artifact in chunk.task.artifacts:
            for part in artifact.parts:
                if part.text:
                    pieces.append(part.text)
        if chunk.task.HasField("status") and chunk.task.status.HasField("message"):
            status_text = get_message_text(chunk.task.status.message)
            if status_text and status_text not in {"Working...", "Done."}:
                pieces.append(status_text)
    if chunk.HasField("message"):
        pieces.append(get_message_text(chunk.message))
    if chunk.HasField("artifact_update"):
        for part in chunk.artifact_update.artifact.parts:
            if part.text:
                pieces.append(part.text)
    return "\n".join(piece for piece in pieces if piece).strip()


async def discover(base_url: str) -> AgentCard:
    async with httpx.AsyncClient(timeout=10.0) as httpx_client:
        resolver = A2ACardResolver(httpx_client=httpx_client, base_url=base_url)
        return await resolver.get_agent_card()


async def send_text(base_url: str, text: str) -> str:
    card = await discover(base_url)
    timeout = httpx.Timeout(180.0, connect=10.0)
    httpx_client = httpx.AsyncClient(timeout=timeout)
    config = ClientConfig(streaming=False, httpx_client=httpx_client)
    client = await create_client(agent=card, client_config=config)
    try:
        request = SendMessageRequest(
            message=new_text_message(text, role=Role.ROLE_USER)
        )
        replies: list[str] = []
        async for chunk in client.send_message(request):
            extracted = extract_text(chunk)
            if extracted:
                replies.append(extracted)
        return replies[-1] if replies else "No response received."
    finally:
        await client.close()
        await httpx_client.aclose()
