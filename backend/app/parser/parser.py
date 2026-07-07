from datetime import datetime

from fastapi import Request

from app.parser.request_model import RequestData


async def parse_request(request: Request) -> RequestData:
    body_bytes = await request.body()
    body = body_bytes.decode("utf-8", errors="ignore")

    return RequestData(
        ip=request.client.host if request.client else "Unknown",
        method=request.method,
        url=str(request.url.path),
        headers=dict(request.headers),
        body=body,
        timestamp=datetime.utcnow().isoformat(),
        user_agent=request.headers.get("user-agent", "Unknown"),
        content_length=len(body_bytes),
        )

