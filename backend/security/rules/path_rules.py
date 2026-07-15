import re

from app.parser.request_model import RequestData
from .rule_result import RuleResult


PATH_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"windows/system32",
    r"boot.ini",
]


def check_path_traversal(request: RequestData) -> RuleResult:

    body = request.body.lower()

    for pattern in PATH_PATTERNS:
        if re.search(pattern, body):

            return RuleResult(
                matched=True,
                attack_type="Path Traversal",
                severity="HIGH",
                rule_id="PATH-001",
                message=f"Matched pattern: {pattern}"
            )

    return RuleResult(
        matched=False,
        attack_type=None,
        severity=None,
        rule_id=None,
        message="No Path Traversal detected"
    )
