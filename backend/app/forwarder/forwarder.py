import httpx
from fastapi import Response

BACKEND_URL = "http://127.0.0.1:8001"


async def forward_request(body: bytes, headers):
    async with httpx.AsyncClient() as client:
        backend_response = await client.post(
            f"{BACKEND_URL}/login",
            content=body,
            headers=dict(headers),
        )

    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=dict(backend_response.headers),
    )
