import re

from app.parser.request_model import RequestData
from security.normalizer import normalize
from .rule_result import RuleResult


XXE_PATTERNS = [
    r"<!doctype",
    r"<!entity",
    r"system",
    r"public",
    r"file://",
]


def check_xxe(request: RequestData) -> RuleResult:

    body = normalize(request.body)

    for pattern in XXE_PATTERNS:
        if re.search(pattern, body):
            return RuleResult(
                matched=True,
                attack_type="XML External Entity",
                severity="CRITICAL",
                rule_id="XXE-001",
                message=f"Matched pattern: {pattern}"
            )

    return RuleResult(
        matched=False,
        attack_type=None,
        severity=None,
        rule_id=None,
        message="No XXE detected"
    )
