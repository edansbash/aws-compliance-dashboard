"""SES identity compliance rules."""

from typing import List
import json

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


class SESIdentityWorldSendEmailRule(ComplianceRule):
    """Ensures SES identities do not allow SendEmail from anyone."""

    rule_id = "SES_IDENTITY_WORLD_SEND_EMAIL"
    name = "SES Identity World SendEmail"
    description = "Ensures SES identity policies do not allow ses:SendEmail from anyone (Principal: *)"
    resource_type = "AWS::SES::Identity"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched SES identities for world-accessible SendEmail permissions."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            identity = attrs.get("identity", resource.resource_name)
            identity_type = attrs.get("identity_type", "unknown")

            # Get policies from pre-fetched data
            policies = attrs.get("policies", {})

            allows_world_send = False
            violating_statements = []

            for policy_name, policy_doc in policies.items():
                # Parse policy if it's a string
                if isinstance(policy_doc, str):
                    try:
                        policy_doc = json.loads(policy_doc)
                    except json.JSONDecodeError:
                        continue

                statements = policy_doc.get("Statement", [])

                for statement in statements:
                    if statement.get("Effect") != "Allow":
                        continue

                    # Check if action matches SendEmail or SendRawEmail
                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    action_matches = False
                    matched_actions = []
                    for action in actions:
                        if action in ("*", "ses:*", "ses:SendEmail", "ses:SendRawEmail"):
                            action_matches = True
                            matched_actions.append(action)

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
                        allows_world_send = True
                        violating_statements.append({
                            "policy_name": policy_name,
                            "sid": statement.get("Sid", ""),
                            "effect": statement.get("Effect"),
                            "principal": principal,
                            "action": matched_actions,
                        })

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "allows_world_send_email": allows_world_send,
                "policy_count": len(policies),
                "violating_statements": violating_statements,
                "message": "Identity policy allows SendEmail from anyone" if allows_world_send else "Identity policy does not allow world SendEmail"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=identity,
                status="FAIL" if allows_world_send else "PASS",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove or restrict the ses:SendEmail permission in the SES identity policy to specific AWS accounts or principals"


class SESDKIMNotEnabledRule(ComplianceRule):
    """Ensures SES identities have DKIM signing enabled."""

    rule_id = "SES_DKIM_NOT_ENABLED"
    name = "SES DKIM Not Enabled"
    description = "Ensures SES identities have DKIM (DomainKeys Identified Mail) signing enabled for email authentication"
    resource_type = "AWS::SES::Identity"
    severity = Severity.MEDIUM
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched SES identities for DKIM enablement."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            identity = attrs.get("identity", resource.resource_name)
            identity_type = attrs.get("identity_type", "unknown")

            dkim_enabled = attrs.get("dkim_enabled", False)
            dkim_verification_status = attrs.get("dkim_verification_status")
            dkim_tokens = attrs.get("dkim_tokens", [])

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "dkim_enabled": dkim_enabled,
                "dkim_tokens_count": len(dkim_tokens),
                "message": "DKIM signing is enabled" if dkim_enabled else "DKIM signing is not enabled"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=identity,
                status="PASS" if dkim_enabled else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable DKIM signing for the SES identity by generating DKIM tokens and adding the CNAME records to DNS"


class SESDKIMNotVerifiedRule(ComplianceRule):
    """Ensures SES identities have DKIM verification completed successfully."""

    rule_id = "SES_DKIM_NOT_VERIFIED"
    name = "SES DKIM Not Verified"
    description = "Ensures SES identities have DKIM verification completed successfully for proper email authentication"
    resource_type = "AWS::SES::Identity"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched SES identities for DKIM verification status."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            identity = attrs.get("identity", resource.resource_name)
            identity_type = attrs.get("identity_type", "unknown")

            dkim_enabled = attrs.get("dkim_enabled", False)
            dkim_verification_status = attrs.get("dkim_verification_status", "NotStarted")
            dkim_tokens = attrs.get("dkim_tokens", [])

            # DKIM is verified if status is "Success"
            is_verified = dkim_verification_status == "Success"

            # Only report on identities where DKIM is enabled but not verified
            # or where verification has been attempted
            if dkim_enabled or dkim_verification_status != "NotStarted":
                # Preserve all resource attributes (including tags) and add compliance-specific fields
                details = dict(attrs)
                details.update({
                    "dkim_enabled": dkim_enabled,
                    "dkim_verification_status": dkim_verification_status,
                    "dkim_tokens_count": len(dkim_tokens),
                    "message": "DKIM verification successful" if is_verified else f"DKIM verification status: {dkim_verification_status}"
                })

                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=identity,
                    status="PASS" if is_verified else "FAIL",
                    details=details
                ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Complete DKIM verification by adding the required CNAME records to your DNS configuration"
