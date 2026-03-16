"""SQS queue compliance rules."""
import json
from typing import List

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


def check_world_access_policy(policy: dict, action_patterns: List[str]) -> bool:
    """
    Check if an SQS policy allows world (public) access for specific actions.

    Args:
        policy: Parsed queue policy dict
        action_patterns: List of action patterns to check (e.g., ["sqs:*"], ["sqs:SendMessage"])

    Returns:
        True if world access is allowed for any of the action patterns
    """
    for statement in policy.get("Statement", []):
        effect = statement.get("Effect", "")
        if effect != "Allow":
            continue

        # Check for world principal
        principal = statement.get("Principal", {})
        is_world_principal = (
            principal == "*" or
            principal == {"AWS": "*"} or
            (isinstance(principal, dict) and principal.get("AWS") == "*")
        )

        if not is_world_principal:
            continue

        # Check for matching actions
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            action_lower = action.lower()
            for pattern in action_patterns:
                pattern_lower = pattern.lower()
                # Check exact match or wildcard match
                if action_lower == pattern_lower:
                    return True
                # sqs:* matches everything
                if action_lower == "sqs:*" or action_lower == "*":
                    return True
                # Check prefix match for wildcards like sqs:Send*
                if pattern_lower.endswith("*"):
                    prefix = pattern_lower[:-1]
                    if action_lower.startswith(prefix):
                        return True
                # Check if action matches a broader pattern
                if action_lower.endswith("*"):
                    action_prefix = action_lower[:-1]
                    if pattern_lower.startswith(action_prefix):
                        return True

    return False


class SQSQueuePolicyBaseRule(ComplianceRule):
    """Base class for SQS queue policy world access checks."""

    resource_type = "AWS::SQS::Queue"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    # Subclasses should override these
    action_patterns: List[str] = []
    action_description: str = ""

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched SQS queues for world access policies."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            queue_name = attrs.get("queue_name", resource.resource_name)
            queue_arn = attrs.get("queue_arn", resource.resource_id)
            queue_url = attrs.get("queue_url", "")

            # Get policy from pre-fetched data
            policy = attrs.get("policy", {})
            if isinstance(policy, str):
                try:
                    policy = json.loads(policy)
                except json.JSONDecodeError:
                    policy = {}

            allows_world_access = False
            policy_exists = bool(policy)

            if policy_exists:
                allows_world_access = check_world_access_policy(
                    policy, self.action_patterns
                )

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "allows_world_access": allows_world_access,
                "policy_exists": policy_exists,
                "action_checked": self.action_description,
            })

            results.append(RuleResult(
                resource_id=queue_arn,
                resource_name=queue_name,
                status="FAIL" if allows_world_access else "PASS",
                details=details
            ))

        return results


class SQSWorldGetQueueUrlPolicyRule(SQSQueuePolicyBaseRule):
    """Ensures SQS queues do not have world access for GetQueueUrl action."""

    rule_id = "SQS_WORLD_GET_QUEUE_URL_POLICY"
    name = "SQS Queue World Get Queue URL Policy"
    description = "Ensures SQS queues do not allow public access for GetQueueUrl action"
    action_patterns = ["sqs:GetQueueUrl"]
    action_description = "GetQueueUrl action"
    severity = Severity.MEDIUM


class SQSWorldGetQueueAttributesPolicyRule(SQSQueuePolicyBaseRule):
    """Ensures SQS queues do not have world access for GetQueueAttributes action."""

    rule_id = "SQS_WORLD_GET_QUEUE_ATTRIBUTES_POLICY"
    name = "SQS Queue World Get Queue Attributes Policy"
    description = "Ensures SQS queues do not allow public access for GetQueueAttributes action"
    action_patterns = ["sqs:GetQueueAttributes"]
    action_description = "GetQueueAttributes action"
    severity = Severity.MEDIUM


class SQSWorldChangeMessageVisibilityPolicyRule(SQSQueuePolicyBaseRule):
    """Ensures SQS queues do not have world access for ChangeMessageVisibility action."""

    rule_id = "SQS_WORLD_CHANGE_MESSAGE_VISIBILITY_POLICY"
    name = "SQS Queue World Change Message Visibility Policy"
    description = "Ensures SQS queues do not allow public access for ChangeMessageVisibility action"
    action_patterns = ["sqs:ChangeMessageVisibility", "sqs:ChangeMessageVisibility*"]
    action_description = "ChangeMessageVisibility action"
    severity = Severity.HIGH


class SQSWorldDeleteMessagePolicyRule(SQSQueuePolicyBaseRule):
    """Ensures SQS queues do not have world access for DeleteMessage action."""

    rule_id = "SQS_WORLD_DELETE_MESSAGE_POLICY"
    name = "SQS Queue World Delete Message Policy"
    description = "Ensures SQS queues do not allow public access for DeleteMessage action"
    action_patterns = ["sqs:DeleteMessage", "sqs:DeleteMessage*"]
    action_description = "DeleteMessage action"
    severity = Severity.CRITICAL


class SQSWorldPurgeQueuePolicyRule(SQSQueuePolicyBaseRule):
    """Ensures SQS queues do not have world access for PurgeQueue action."""

    rule_id = "SQS_WORLD_PURGE_QUEUE_POLICY"
    name = "SQS Queue World Purge Queue Policy"
    description = "Ensures SQS queues do not allow public access for PurgeQueue action"
    action_patterns = ["sqs:PurgeQueue"]
    action_description = "PurgeQueue action"
    severity = Severity.CRITICAL


class SQSWorldReceiveMessagePolicyRule(SQSQueuePolicyBaseRule):
    """Ensures SQS queues do not have world access for ReceiveMessage action."""

    rule_id = "SQS_WORLD_RECEIVE_MESSAGE_POLICY"
    name = "SQS Queue World Receive Message Policy"
    description = "Ensures SQS queues do not allow public access for ReceiveMessage action"
    action_patterns = ["sqs:ReceiveMessage"]
    action_description = "ReceiveMessage action"
    severity = Severity.CRITICAL


class SQSWorldSendMessagePolicyRule(SQSQueuePolicyBaseRule):
    """Ensures SQS queues do not have world access for SendMessage action."""

    rule_id = "SQS_WORLD_SEND_MESSAGE_POLICY"
    name = "SQS Queue World Send Message Policy"
    description = "Ensures SQS queues do not allow public access for SendMessage action"
    action_patterns = ["sqs:SendMessage", "sqs:SendMessage*"]
    action_description = "SendMessage action"
    severity = Severity.CRITICAL


class SQSQueueEncryptionDisabledRule(ComplianceRule):
    """Ensures SQS queues have server-side encryption enabled."""

    rule_id = "SQS_QUEUE_ENCRYPTION_DISABLED"
    name = "SQS Queue with Encryption Disabled"
    description = "Ensures SQS queues have server-side encryption enabled using KMS or SQS-managed keys"
    resource_type = "AWS::SQS::Queue"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched SQS queues for encryption settings."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            queue_name = attrs.get("queue_name", resource.resource_name)
            queue_arn = attrs.get("queue_arn", resource.resource_id)
            queue_url = attrs.get("queue_url", "")

            # Check for encryption from pre-fetched data
            kms_key_id = attrs.get("kms_master_key_id")
            sqs_managed_sse = attrs.get("sqs_managed_sse_enabled", False)

            is_encrypted = bool(kms_key_id) or sqs_managed_sse

            encryption_type = None
            if kms_key_id:
                encryption_type = "KMS"
            elif sqs_managed_sse:
                encryption_type = "SQS-managed SSE"

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "encryption_enabled": is_encrypted,
                "encryption_type": encryption_type,
                "message": f"Queue is encrypted using {encryption_type}" if is_encrypted else "Queue does not have encryption enabled"
            })

            results.append(RuleResult(
                resource_id=queue_arn,
                resource_name=queue_name,
                status="PASS" if is_encrypted else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable server-side encryption on the SQS queue using either a KMS key or SQS-managed encryption"
