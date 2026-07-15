import re

from app.parser.request_model import RequestData
from .rule_result import RuleResult


COMMAND_PATTERNS = [
    r";\s*\w+",
    r"\|\s*\w+",
    r"&&\s*\w+",
    r"`.*?`",
    r"\$\(.+?\)",
]


def check_command_injection(request: RequestData) -> RuleResult:

    body = request.body.lower()

    for pattern in COMMAND_PATTERNS:
        if re.search(pattern, body):

            return RuleResult(
                matched=True,
                attack_type="Command Injection",
                severity="CRITICAL",
                rule_id="CMD-001",
                message=f"Matched pattern: {pattern}"
            )

    return RuleResult(
        matched=False,
        attack_type=None,
        severity=None,
        rule_id=None,
        message="No Command Injection detected")

