"""IAM managed policy compliance rules."""
from typing import List
from botocore.exceptions import ClientError

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.rules.iam_policy_analyzer import PolicyAnalyzer


class IAMManagedPolicyFullPrivilegesRule(ComplianceRule):
    """Ensures managed policies do not provide full admin privileges."""

    rule_id = "IAM_MANAGED_POLICY_FULL_PRIVILEGES"
    name = "IAM Managed Policy Provides Full Privileges"
    description = "Ensures IAM managed policies do not grant full administrative privileges (*:*)"
    resource_type = "AWS::IAM::ManagedPolicy"
    severity = Severity.CRITICAL
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate managed policies for full privileges."""
        results = []

        # IAM is global, only run in us-east-1 to avoid duplicates
        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)
            account_id = session.client("sts").get_caller_identity()["Account"]

            # List customer managed policies (not AWS managed)
            paginator = iam.get_paginator("list_policies")

            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_arn = policy["Arn"]
                    policy_name = policy["PolicyName"]
                    default_version = policy["DefaultVersionId"]

                    # Get the policy document
                    version_response = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version
                    )
                    policy_doc = version_response["PolicyVersion"]["Document"]

                    # Analyze policy
                    has_full_privs, violating_stmts = PolicyAnalyzer.has_full_privileges(policy_doc)

                    results.append(RuleResult(
                        resource_id=policy_arn,
                        resource_name=policy_name,
                        status="FAIL" if has_full_privs else "PASS",
                        details={
                            "policy_name": policy_name,
                            "policy_arn": policy_arn,
                            "has_full_privileges": has_full_privs,
                            "violating_statements": violating_stmts,
                            "message": "Policy grants full administrative privileges (*:*)" if has_full_privs else "Policy does not grant full admin privileges"
                        }
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Modify the policy to use least privilege permissions instead of *:*"


class IAMManagedPolicyAllowsAssumeRoleRule(ComplianceRule):
    """Ensures managed policies do not allow sts:AssumeRole on all resources."""

    rule_id = "IAM_MANAGED_POLICY_ALLOWS_ASSUME_ROLE"
    name = "IAM Managed Policy Allows STS Assume Role on All Resources"
    description = "Ensures IAM managed policies do not allow sts:AssumeRole with Resource: *"
    resource_type = "AWS::IAM::ManagedPolicy"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate managed policies for sts:AssumeRole."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_policies")

            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_arn = policy["Arn"]
                    policy_name = policy["PolicyName"]
                    default_version = policy["DefaultVersionId"]

                    version_response = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version
                    )
                    policy_doc = version_response["PolicyVersion"]["Document"]

                    has_assume_role, violating_stmts = PolicyAnalyzer.allows_sts_assume_role(policy_doc)

                    results.append(RuleResult(
                        resource_id=policy_arn,
                        resource_name=policy_name,
                        status="FAIL" if has_assume_role else "PASS",
                        details={
                            "policy_name": policy_name,
                            "policy_arn": policy_arn,
                            "allows_assume_role": has_assume_role,
                            "violating_statements": violating_stmts,
                            "message": "Policy allows sts:AssumeRole on all resources (Resource: *)" if has_assume_role else "Policy does not allow sts:AssumeRole on all resources"
                        }
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove sts:AssumeRole permission or scope it to specific roles"


class IAMManagedPolicyAllowsPassRoleRule(ComplianceRule):
    """Ensures managed policies do not allow iam:PassRole on all resources."""

    rule_id = "IAM_MANAGED_POLICY_ALLOWS_PASS_ROLE"
    name = "IAM Managed Policy Allows IAM Pass Role on All Resources"
    description = "Ensures IAM managed policies do not allow iam:PassRole with Resource: *"
    resource_type = "AWS::IAM::ManagedPolicy"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate managed policies for iam:PassRole."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_policies")

            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_arn = policy["Arn"]
                    policy_name = policy["PolicyName"]
                    default_version = policy["DefaultVersionId"]

                    version_response = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version
                    )
                    policy_doc = version_response["PolicyVersion"]["Document"]

                    has_pass_role, violating_stmts = PolicyAnalyzer.allows_iam_pass_role(policy_doc)

                    results.append(RuleResult(
                        resource_id=policy_arn,
                        resource_name=policy_name,
                        status="FAIL" if has_pass_role else "PASS",
                        details={
                            "policy_name": policy_name,
                            "policy_arn": policy_arn,
                            "allows_pass_role": has_pass_role,
                            "violating_statements": violating_stmts,
                            "message": "Policy allows iam:PassRole on all resources (Resource: *)" if has_pass_role else "Policy does not allow iam:PassRole on all resources"
                        }
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove iam:PassRole permission or scope it to specific roles"


class IAMManagedPolicyNotActionRule(ComplianceRule):
    """Ensures managed policies do not use NotAction with Allow."""

    rule_id = "IAM_MANAGED_POLICY_NOTACTION"
    name = "IAM Managed Policy Uses NotAction with Allow"
    description = "Ensures IAM managed policies do not use NotAction with Allow effect (overly permissive pattern)"
    resource_type = "AWS::IAM::ManagedPolicy"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate managed policies for NotAction with Allow."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_policies")

            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_arn = policy["Arn"]
                    policy_name = policy["PolicyName"]
                    default_version = policy["DefaultVersionId"]

                    version_response = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version
                    )
                    policy_doc = version_response["PolicyVersion"]["Document"]

                    has_notaction, violating_stmts = PolicyAnalyzer.has_notaction_with_allow(policy_doc)

                    results.append(RuleResult(
                        resource_id=policy_arn,
                        resource_name=policy_name,
                        status="FAIL" if has_notaction else "PASS",
                        details={
                            "policy_name": policy_name,
                            "policy_arn": policy_arn,
                            "has_notaction_with_allow": has_notaction,
                            "violating_statements": violating_stmts,
                            "message": "Policy uses NotAction with Allow effect (overly permissive)" if has_notaction else "Policy does not use NotAction with Allow"
                        }
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Replace NotAction with explicit Action list using least privilege principle"
