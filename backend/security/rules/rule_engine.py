from app.parser.request_model import RequestData

from .sql_rules import check_sql_injection
from .rule_result import RuleResult


def inspect(request: RequestData) -> RuleResult:

    result = check_sql_injection(request)

    return result
