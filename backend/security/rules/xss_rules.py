import re
from security.normalizer import normalize
from app.parser.request_model import RequestData
from .rule_result import RuleResult


XSS_PATTERNS = [
    r"<script.*?>",
    r"</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<img.*?>",
    r"<svg.*?>",
]


def check_xss(request: RequestData) -> RuleResult:

    body = normalize(request.body)
    print(f"Normalized Body: {body}")

    for pattern in XSS_PATTERNS:
        if re.search(pattern, body):

            return RuleResult(
                matched=True,
                attack_type="Cross Site Scripting",
                severity="HIGH",
                rule_id="XSS-001",
                message=f"Matched pattern: {pattern}"
            )

    return RuleResult(
        matched=False,
        attack_type=None,
        severity=None,
        rule_id=None,
        message="No XSS detected"
    )
