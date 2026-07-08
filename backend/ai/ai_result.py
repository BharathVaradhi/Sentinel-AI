from dataclasses import dataclass


@dataclass
class AIResult:
    prediction: str
    confidence: float
    risk_score: float
