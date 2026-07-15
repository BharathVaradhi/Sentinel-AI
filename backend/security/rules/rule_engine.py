
from app.parser.request_model import RequestData

from .xss_rules import check_xss
from .sql_rules import check_sql_injection
from .path_rules import check_path_traversal
from .rule_result import RuleResult
from .command_rules import check_command_injection

def inspect(request: RequestData) -> RuleResult:

    result = check_sql_injection(request)
    if result.matched:
        return result

    result = check_xss(request)
    if result.matched:
        return result

    result = check_path_traversal(request)
    if result.matched:
        return result

    result = check_command_injection(request)
    if result.matched:
        return result

    return RuleResult(
        matched=False,
        attack_type=None,
        severity=None,
        rule_id=None,
        message="No attack detected"
    )
