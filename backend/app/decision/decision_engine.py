from security.rules.rule_result import RuleResult
from .decision_result import DecisionResult


def evaluate(rule_result: RuleResult) -> DecisionResult:

    if rule_result.matched:
        return DecisionResult(
            allow=False,
            status_code=403,
            message="Blocked by Rule Engine"
        )

    return DecisionResult(
        allow=True,
        status_code=200,
        message="Request Allowed"
    )
