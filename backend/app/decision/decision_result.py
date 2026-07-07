from dataclasses import dataclass

@dataclass
class DecisionResult:
    allow: bool
    status_code: int
    message: str
