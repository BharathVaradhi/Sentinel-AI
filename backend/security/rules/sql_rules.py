from app.parser.request_model import RequestData

from .rule_result import RuleResult


SQL_PATTERNS = [
    "' OR '1'='1",
    " OR 1=1",
    "UNION SELECT",
    "DROP TABLE",
    "--",
    ";--",
]


def check_sql_injection(request: RequestData) -> RuleResult:

    body = request.body.upper()

    for pattern in SQL_PATTERNS:
        if pattern.upper() in body:
            return RuleResult(
                matched=True,
                attack_type="SQL Injection",
                severity="HIGH",
                rule_id="SQL-001",
                message=f"Matched pattern: {pattern}",
            )

    return RuleResult(
        matched=False,
        attack_type="None",
        severity="None",
        rule_id="None",
        message="No SQL Injection detected",
        )
