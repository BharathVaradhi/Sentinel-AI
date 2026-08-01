import re

from app.parser.request_model import RequestData
from security.normalizer import normalize
from .rule_result import RuleResult


SSRF_PATTERNS = [
    r"127\.0\.0\.1",
    r"localhost",
    r"0\.0\.0\.0",
    r"169\.254\.169\.254",
    r"file://",
    r"ftp://",
    r"gopher://",
]


def check_ssrf(request: RequestData) -> RuleResult:

    body = normalize(request.body)

    for pattern in SSRF_PATTERNS:
        if re.search(pattern, body):
            return RuleResult(
                matched=True,
                attack_type="Server Side Request Forgery",
                severity="HIGH",
                rule_id="SSRF-001",
                message=f"Matched pattern: {pattern}"
            )

    return RuleResult(
        matched=False,
        attack_type=None,
        severity=None,
        rule_id=None,
        message="No SSRF detected"
    )
