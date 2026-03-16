"""SNS topic policy compliance rules."""

from typing import List
import json

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


def check_world_access_for_action(policies: dict, target_action: str) -> tuple:
    """
    Check if policy allows world access for a specific action.

    Returns:
        Tuple of (allows_world_access: bool, violating_statements: list)
    """
    allows_world_access = False
    violating_statements = []

    statements = policies.get("Statement", [])

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        # Check if action matches
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        action_matches = False
        for action in actions:
            if action == "*" or action == "sns:*" or action == target_action:
                action_matches = True
                break

        if not action_matches:
            continue

        # Check principal
        principal = statement.get("Principal", {})
        is_world_principal = False

        if principal == "*":
            is_world_principal = True
        elif isinstance(principal, dict):
            aws_principal = principal.get("AWS", [])
            if isinstance(aws_principal, str):
                aws_principal = [aws_principal]
            if "*" in aws_principal:
                is_world_principal = True

        # Check for conditions that might restrict access
        has_condition = "Condition" in statement and len(statement["Condition"]) > 0

        if is_world_principal and not has_condition:
            allows_world_access = True
            violating_statements.append({
                "sid": statement.get("Sid", ""),
                "effect": statement.get("Effect"),
                "principal": principal,
                "action": actions,
            })

    return allows_world_access, violating_statements


class SNSTopicPolicyRule(ComplianceRule):
    """
    Base class for SNS topic policy rules.
    Subclasses define specific actions to check for world-accessible permissions.
    """

    # To be overridden by subclasses
    target_action: str = ""
    action_name: str = ""
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched SNS topics for world-accessible policy permissions."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            topic_arn = attrs.get("topic_arn", resource.resource_id)
            topic_name = attrs.get("topic_name", resource.resource_name)

            # Get policy from pre-fetched data
            policy = attrs.get("policy", {})
            if isinstance(policy, str):
                try:
                    policy = json.loads(policy)
                except json.JSONDecodeError:
                    policy = {}

            allows_world_access, violating_statements = check_world_access_for_action(
                policy, self.target_action
            )

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "allows_world_access": allows_world_access,
                "action_checked": self.target_action,
                "violating_statements": violating_statements,
                "message": f"Topic policy allows {self.action_name} from anyone" if allows_world_access else f"Topic policy does not allow world {self.action_name}"
            })

            results.append(RuleResult(
                resource_id=topic_arn,
                resource_name=topic_name,
                status="FAIL" if allows_world_access else "PASS",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return f"Remove or restrict the {cls.target_action} permission in the SNS topic policy to specific AWS accounts or principals"


class SNSWorldAddPermissionRule(SNSTopicPolicyRule):
    """Ensures SNS topics do not allow AddPermission from anyone."""

    rule_id = "SNS_WORLD_ADD_PERMISSION"
    name = "SNS Topic World AddPermission"
    description = "Ensures SNS topic policies do not allow sns:AddPermission from anyone (Principal: *)"
    resource_type = "AWS::SNS::Topic"
    severity = Severity.HIGH
    has_remediation = False

    target_action = "sns:AddPermission"
    action_name = "AddPermission"


class SNSWorldRemovePermissionRule(SNSTopicPolicyRule):
    """Ensures SNS topics do not allow RemovePermission from anyone."""

    rule_id = "SNS_WORLD_REMOVE_PERMISSION"
    name = "SNS Topic World RemovePermission"
    description = "Ensures SNS topic policies do not allow sns:RemovePermission from anyone (Principal: *)"
    resource_type = "AWS::SNS::Topic"
    severity = Severity.HIGH
    has_remediation = False

    target_action = "sns:RemovePermission"
    action_name = "RemovePermission"


class SNSWorldSetTopicAttributesRule(SNSTopicPolicyRule):
    """Ensures SNS topics do not allow SetTopicAttributes from anyone."""

    rule_id = "SNS_WORLD_SET_TOPIC_ATTRIBUTES"
    name = "SNS Topic World SetTopicAttributes"
    description = "Ensures SNS topic policies do not allow sns:SetTopicAttributes from anyone (Principal: *)"
    resource_type = "AWS::SNS::Topic"
    severity = Severity.HIGH
    has_remediation = False

    target_action = "sns:SetTopicAttributes"
    action_name = "SetTopicAttributes"


class SNSWorldSubscribeRule(SNSTopicPolicyRule):
    """Ensures SNS topics do not allow Subscribe from anyone."""

    rule_id = "SNS_WORLD_SUBSCRIBE"
    name = "SNS Topic World Subscribe"
    description = "Ensures SNS topic policies do not allow sns:Subscribe from anyone (Principal: *)"
    resource_type = "AWS::SNS::Topic"
    severity = Severity.HIGH
    has_remediation = False

    target_action = "sns:Subscribe"
    action_name = "Subscribe"


class SNSWorldDeleteTopicRule(SNSTopicPolicyRule):
    """Ensures SNS topics do not allow DeleteTopic from anyone."""

    rule_id = "SNS_WORLD_DELETE_TOPIC"
    name = "SNS Topic World DeleteTopic"
    description = "Ensures SNS topic policies do not allow sns:DeleteTopic from anyone (Principal: *)"
    resource_type = "AWS::SNS::Topic"
    severity = Severity.CRITICAL
    has_remediation = False

    target_action = "sns:DeleteTopic"
    action_name = "DeleteTopic"


class SNSWorldPublishRule(SNSTopicPolicyRule):
    """Ensures SNS topics do not allow Publish from anyone."""

    rule_id = "SNS_WORLD_PUBLISH"
    name = "SNS Topic World Publish"
    description = "Ensures SNS topic policies do not allow sns:Publish from anyone (Principal: *)"
    resource_type = "AWS::SNS::Topic"
    severity = Severity.HIGH
    has_remediation = False

    target_action = "sns:Publish"
    action_name = "Publish"


class SNSWorldGetTopicAttributesRule(SNSTopicPolicyRule):
    """Ensures SNS topics do not allow GetTopicAttributes from anyone."""

    rule_id = "SNS_WORLD_GET_TOPIC_ATTRIBUTES"
    name = "SNS Topic World GetTopicAttributes"
    description = "Ensures SNS topic policies do not allow sns:GetTopicAttributes from anyone (Principal: *)"
    resource_type = "AWS::SNS::Topic"
    severity = Severity.MEDIUM
    has_remediation = False

    target_action = "sns:GetTopicAttributes"
    action_name = "GetTopicAttributes"


class SNSWorldListSubscriptionsByTopicRule(SNSTopicPolicyRule):
    """Ensures SNS topics do not allow ListSubscriptionsByTopic from anyone."""

    rule_id = "SNS_WORLD_LIST_SUBSCRIPTIONS_BY_TOPIC"
    name = "SNS Topic World ListSubscriptionsByTopic"
    description = "Ensures SNS topic policies do not allow sns:ListSubscriptionsByTopic from anyone (Principal: *)"
    resource_type = "AWS::SNS::Topic"
    severity = Severity.MEDIUM
    has_remediation = False

    target_action = "sns:ListSubscriptionsByTopic"
    action_name = "ListSubscriptionsByTopic"
