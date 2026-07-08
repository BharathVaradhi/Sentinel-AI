from dataclasses import dataclass


@dataclass
class LogEntry:
    timestamp: str
    ip: str
    method: str
    url: str
    attack: str
    decision: str
    severity: str
