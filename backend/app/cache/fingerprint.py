import hashlib

from app.parser.request_model import RequestData


def generate_fingerprint(request: RequestData) -> str:
    data = (
        request.method
        + request.url
        + request.body
        + request.ip
    )

    return hashlib.sha256(data.encode()).hexdigest()
