from dataclasses import dataclass


@dataclass
class RuleResult:
    matched: bool
    attack_type: str
    severity: str
    rule_id: str
    message: str
