import re

from app.parser.request_model import RequestData
from security.normalizer import normalize
from .rule_result import RuleResult


LFI_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"/proc/self",
    r"boot\.ini",
    r"windows/system32",
]


def check_lfi(request: RequestData) -> RuleResult:

    body = normalize(request.body)

    for pattern in LFI_PATTERNS:
        if re.search(pattern, body):
            return RuleResult(
                matched=True,
                attack_type="Local File Inclusion",
                severity="HIGH",
                rule_id="LFI-001",
                message=f"Matched pattern: {pattern}"
            )

    return RuleResult(
        matched=False,
        attack_type=None,
        severity=None,
        rule_id=None,
        message="No LFI detected"
    )
