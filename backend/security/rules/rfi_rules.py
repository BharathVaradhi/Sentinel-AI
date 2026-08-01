import re

from app.parser.request_model import RequestData
from security.normalizer import normalize
from .rule_result import RuleResult

RFI_PATTERNS = [
    r"evil\.com",
    r"malicious\.com",
    r"shell\.php",
    r"backdoor\.php",
    r"cmd\.php",
    r"webshell",
    r"c99\.php",
    r"r57\.php",
]

def check_rfi(request: RequestData) -> RuleResult:

    body = normalize(request.body)

    for pattern in RFI_PATTERNS:
        if re.search(pattern, body):
            return RuleResult(
                matched=True,
                attack_type="Remote File Inclusion",
                severity="HIGH",
                rule_id="RFI-001",
                message=f"Matched pattern: {pattern}"
            )

    return RuleResult(
        matched=False,
        attack_type=None,
        severity=None,
        rule_id=None,
        message="No RFI detected"
    )
