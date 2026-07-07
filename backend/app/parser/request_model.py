from dataclasses import dataclass
from typing import Dict


@dataclass
class RequestData:
    ip: str
    method: str
    url: str
    headers: Dict[str, str]
    body: str
    timestamp: str
    user_agent: str
    content_length: int
