"""IAM role trust policy compliance rules."""
from typing import List
from botocore.exceptions import ClientError
import json

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.rules.iam_policy_analyzer import TrustPolicyAnalyzer


class IAMAssumeRolePolicyAllowsAllRule(ComplianceRule):
    """Ensures IAM role trust policies do not allow all principals."""

    rule_id = "IAM_ASSUME_ROLE_ALLOWS_ALL"
    name = "IAM Assume Role Policy Allows All"
    description = "Ensures IAM role trust policies do not allow all principals (Principal: *)"
    resource_type = "AWS::IAM::Role"
    severity = Severity.CRITICAL
    has_remediation = False

    # Service-linked roles and AWS-managed roles to skip
    SKIP_ROLE_PREFIXES = [
        "AWSServiceRole",
        "aws-service-role",
        "AWS-QuickSetup",
    ]

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM roles for overly permissive trust policies."""
        results = []

        # IAM is global, only run in us-east-1 to avoid duplicates
        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]

                    # Skip AWS service-linked roles
                    if any(role_name.startswith(prefix) for prefix in self.SKIP_ROLE_PREFIXES):
                        continue

                    # Skip if path indicates it's AWS managed
                    role_path = role.get("Path", "/")
                    if "/aws-service-role/" in role_path:
                        continue

                    # Get trust policy
                    trust_policy = role.get("AssumeRolePolicyDocument", {})
                    if isinstance(trust_policy, str):
                        trust_policy = json.loads(trust_policy)

                    allows_all, violating_stmts = TrustPolicyAnalyzer.allows_all_principals(trust_policy)

                    results.append(RuleResult(
                        resource_id=role_arn,
                        resource_name=role_name,
                        status="FAIL" if allows_all else "PASS",
                        details={
                            "role_name": role_name,
                            "role_arn": role_arn,
                            "allows_all_principals": allows_all,
                            "violating_statements": violating_stmts,
                            "trust_policy": trust_policy,
                            "message": "Role trust policy allows all principals (Principal: *)" if allows_all else "Role trust policy has restricted principals"
                        }
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Restrict the trust policy to specific AWS accounts, users, or roles"


class IAMAssumeRoleLacksExternalIdMFARule(ComplianceRule):
    """Ensures IAM role trust policies require external ID or MFA for cross-account access."""

    rule_id = "IAM_ASSUME_ROLE_LACKS_EXTERNAL_ID_MFA"
    name = "IAM Assume Role Lacks External ID and MFA"
    description = "Ensures IAM role trust policies require external ID or MFA for cross-account assume role"
    resource_type = "AWS::IAM::Role"
    severity = Severity.HIGH
    has_remediation = False

    # Service-linked roles and AWS-managed roles to skip
    SKIP_ROLE_PREFIXES = [
        "AWSServiceRole",
        "aws-service-role",
        "AWS-QuickSetup",
        "OrganizationAccountAccessRole",
    ]

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM roles for missing external ID or MFA in trust policies."""
        results = []

        # IAM is global, only run in us-east-1 to avoid duplicates
        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)
            current_account = session.client("sts").get_caller_identity()["Account"]

            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]

                    # Skip AWS service-linked roles
                    if any(role_name.startswith(prefix) for prefix in self.SKIP_ROLE_PREFIXES):
                        continue

                    # Skip if path indicates it's AWS managed
                    role_path = role.get("Path", "/")
                    if "/aws-service-role/" in role_path:
                        continue

                    # Get trust policy
                    trust_policy = role.get("AssumeRolePolicyDocument", {})
                    if isinstance(trust_policy, str):
                        trust_policy = json.loads(trust_policy)

                    # Extract role's account ID from ARN for same-account detection
                    role_account_id = TrustPolicyAnalyzer.extract_account_id(role_arn)

                    is_violation, violating_stmts, details = TrustPolicyAnalyzer.lacks_external_id_or_mfa(
                        trust_policy, role_account_id=role_account_id
                    )

                    # Only report if there are cross-account statements
                    if not details["cross_account_statements"]:
                        continue

                    results.append(RuleResult(
                        resource_id=role_arn,
                        resource_name=role_name,
                        status="FAIL" if is_violation else "PASS",
                        details={
                            "role_name": role_name,
                            "role_arn": role_arn,
                            "has_cross_account_trust": len(details["cross_account_statements"]) > 0,
                            "missing_external_id_count": len(details["missing_external_id"]),
                            "missing_mfa_count": len(details["missing_mfa"]),
                            "violating_statements": violating_stmts,
                            "trust_policy": trust_policy,
                            "message": "Role allows cross-account assume role without external ID or MFA" if is_violation else "Role has external ID or MFA requirement for cross-account access"
                        }
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Add sts:ExternalId condition or aws:MultiFactorAuthPresent condition to the trust policy"
