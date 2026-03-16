"""IAM inline policy compliance rules for Users, Roles, and Groups."""
from typing import List, Callable, Any
from botocore.exceptions import ClientError

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.rules.iam_policy_analyzer import PolicyAnalyzer


# ============================================================================
# Base class for inline policy checks
# ============================================================================

class InlinePolicyCheckMixin:
    """Mixin providing shared inline policy checking logic."""

    SKIP_ROLE_PREFIXES = [
        "AWSServiceRole",
        "aws-service-role",
        "AWS-QuickSetup",
    ]

    @staticmethod
    def should_skip_role(role_name: str, role_path: str) -> bool:
        """Check if role should be skipped (AWS managed)."""
        if any(role_name.startswith(prefix) for prefix in InlinePolicyCheckMixin.SKIP_ROLE_PREFIXES):
            return True
        if "/aws-service-role/" in role_path:
            return True
        return False


# ============================================================================
# IAM User Inline Policy Rules
# ============================================================================

class IAMUserInlinePolicyExistsRule(ComplianceRule):
    """Ensures IAM users do not have inline policies attached."""

    rule_id = "IAM_USER_INLINE_POLICIES"
    name = "IAM User Inline Policies"
    description = "Ensures IAM users do not have inline policies attached (use managed policies instead)"
    resource_type = "AWS::IAM::User"
    severity = Severity.MEDIUM
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM users for inline policies."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]

                    policies_response = iam.list_user_policies(UserName=user_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    is_compliant = len(inline_policies) == 0

                    attached_response = iam.list_attached_user_policies(UserName=user_name)
                    attached_policies = [p["PolicyName"] for p in attached_response.get("AttachedPolicies", [])]

                    results.append(RuleResult(
                        resource_id=user_arn,
                        resource_name=user_name,
                        status="PASS" if is_compliant else "FAIL",
                        details={
                            "user_name": user_name,
                            "inline_policy_count": len(inline_policies),
                            "inline_policies": inline_policies,
                            "attached_managed_policies": attached_policies,
                            "message": f"User has {len(inline_policies)} inline policy(ies) attached" if not is_compliant else "No inline policies attached"
                        }
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Convert inline policies to managed policies and attach them to the user or a group"


class IAMUserInlinePolicyAssumeRoleRule(ComplianceRule):
    """Ensures IAM user inline policies do not allow sts:AssumeRole on all resources."""

    rule_id = "IAM_USER_INLINE_ALLOWS_ASSUME_ROLE"
    name = "IAM User Inline Policy Allows STS Assume Role on All Resources"
    description = "Ensures IAM user inline policies do not allow sts:AssumeRole with Resource: *"
    resource_type = "AWS::IAM::User"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM user inline policies for sts:AssumeRole."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]

                    policies_response = iam.list_user_policies(UserName=user_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    violating_policies = []
                    for policy_name in inline_policies:
                        policy_response = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                        policy_doc = policy_response["PolicyDocument"]

                        has_assume_role, stmts = PolicyAnalyzer.allows_sts_assume_role(policy_doc)
                        if has_assume_role:
                            violating_policies.append({
                                "policy_name": policy_name,
                                "violating_statements": stmts
                            })

                    if inline_policies:
                        is_compliant = len(violating_policies) == 0

                        results.append(RuleResult(
                            resource_id=user_arn,
                            resource_name=user_name,
                            status="PASS" if is_compliant else "FAIL",
                            details={
                                "user_name": user_name,
                                "inline_policy_count": len(inline_policies),
                                "violating_policies": violating_policies,
                                "message": f"User has {len(violating_policies)} inline policy(ies) allowing sts:AssumeRole on all resources" if not is_compliant else "No inline policies allow sts:AssumeRole on all resources"
                            }
                        ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove sts:AssumeRole permission from inline policies or scope to specific roles"


class IAMUserInlinePolicyPassRoleRule(ComplianceRule):
    """Ensures IAM user inline policies do not allow iam:PassRole on all resources."""

    rule_id = "IAM_USER_INLINE_ALLOWS_PASS_ROLE"
    name = "IAM User Inline Policy Allows IAM Pass Role on All Resources"
    description = "Ensures IAM user inline policies do not allow iam:PassRole with Resource: *"
    resource_type = "AWS::IAM::User"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM user inline policies for iam:PassRole."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]

                    policies_response = iam.list_user_policies(UserName=user_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    violating_policies = []
                    for policy_name in inline_policies:
                        policy_response = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                        policy_doc = policy_response["PolicyDocument"]

                        has_pass_role, stmts = PolicyAnalyzer.allows_iam_pass_role(policy_doc)
                        if has_pass_role:
                            violating_policies.append({
                                "policy_name": policy_name,
                                "violating_statements": stmts
                            })

                    if inline_policies:
                        is_compliant = len(violating_policies) == 0

                        results.append(RuleResult(
                            resource_id=user_arn,
                            resource_name=user_name,
                            status="PASS" if is_compliant else "FAIL",
                            details={
                                "user_name": user_name,
                                "inline_policy_count": len(inline_policies),
                                "violating_policies": violating_policies,
                                "message": f"User has {len(violating_policies)} inline policy(ies) allowing iam:PassRole on all resources" if not is_compliant else "No inline policies allow iam:PassRole on all resources"
                            }
                        ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove iam:PassRole permission from inline policies or scope to specific roles"


class IAMUserInlinePolicyNotActionRule(ComplianceRule):
    """Ensures IAM user inline policies do not use NotAction with Allow."""

    rule_id = "IAM_USER_INLINE_NOTACTION"
    name = "IAM User Inline Policy Uses NotAction with Allow"
    description = "Ensures IAM user inline policies do not use NotAction with Allow effect"
    resource_type = "AWS::IAM::User"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM user inline policies for NotAction with Allow."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]

                    policies_response = iam.list_user_policies(UserName=user_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    violating_policies = []
                    for policy_name in inline_policies:
                        policy_response = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                        policy_doc = policy_response["PolicyDocument"]

                        has_notaction, stmts = PolicyAnalyzer.has_notaction_with_allow(policy_doc)
                        if has_notaction:
                            violating_policies.append({
                                "policy_name": policy_name,
                                "violating_statements": stmts
                            })

                    if inline_policies:
                        is_compliant = len(violating_policies) == 0

                        results.append(RuleResult(
                            resource_id=user_arn,
                            resource_name=user_name,
                            status="PASS" if is_compliant else "FAIL",
                            details={
                                "user_name": user_name,
                                "inline_policy_count": len(inline_policies),
                                "violating_policies": violating_policies,
                                "message": f"User has {len(violating_policies)} inline policy(ies) using NotAction with Allow" if not is_compliant else "No inline policies use NotAction with Allow"
                            }
                        ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Replace NotAction with explicit Action list using least privilege principle"


# ============================================================================
# IAM Role Inline Policy Rules
# ============================================================================

class IAMRoleInlinePolicyExistsRule(ComplianceRule, InlinePolicyCheckMixin):
    """Ensures IAM roles do not have inline policies attached."""

    rule_id = "IAM_ROLE_INLINE_POLICIES"
    name = "IAM Role Inline Policies"
    description = "Ensures IAM roles do not have inline policies attached (use managed policies instead)"
    resource_type = "AWS::IAM::Role"
    severity = Severity.LOW
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM roles for inline policies."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    role_path = role.get("Path", "/")

                    if self.should_skip_role(role_name, role_path):
                        continue

                    policies_response = iam.list_role_policies(RoleName=role_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    is_compliant = len(inline_policies) == 0

                    attached_response = iam.list_attached_role_policies(RoleName=role_name)
                    attached_policies = [p["PolicyName"] for p in attached_response.get("AttachedPolicies", [])]

                    # Fetch role tags
                    tags = {}
                    try:
                        tags_response = iam.list_role_tags(RoleName=role_name)
                        for tag in tags_response.get("Tags", []):
                            tags[tag["Key"]] = tag["Value"]
                    except ClientError:
                        pass

                    results.append(RuleResult(
                        resource_id=role_arn,
                        resource_name=role_name,
                        status="PASS" if is_compliant else "FAIL",
                        details={
                            "role_name": role_name,
                            "role_path": role_path,
                            "inline_policy_count": len(inline_policies),
                            "inline_policies": inline_policies,
                            "attached_managed_policies": attached_policies,
                            "tags": tags,
                            "message": f"Role has {len(inline_policies)} inline policy(ies) attached" if not is_compliant else "No inline policies attached"
                        }
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Convert inline policies to managed policies and attach them to the role"


class IAMRoleInlinePolicyAssumeRoleRule(ComplianceRule, InlinePolicyCheckMixin):
    """Ensures IAM role inline policies do not allow sts:AssumeRole on all resources."""

    rule_id = "IAM_ROLE_INLINE_ALLOWS_ASSUME_ROLE"
    name = "IAM Role Inline Policy Allows STS Assume Role on All Resources"
    description = "Ensures IAM role inline policies do not allow sts:AssumeRole with Resource: *"
    resource_type = "AWS::IAM::Role"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM role inline policies for sts:AssumeRole."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    role_path = role.get("Path", "/")

                    if self.should_skip_role(role_name, role_path):
                        continue

                    policies_response = iam.list_role_policies(RoleName=role_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    violating_policies = []
                    for policy_name in inline_policies:
                        policy_response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                        policy_doc = policy_response["PolicyDocument"]

                        has_assume_role, stmts = PolicyAnalyzer.allows_sts_assume_role(policy_doc)
                        if has_assume_role:
                            violating_policies.append({
                                "policy_name": policy_name,
                                "violating_statements": stmts
                            })

                    if inline_policies:
                        is_compliant = len(violating_policies) == 0

                        # Fetch role tags
                        tags = {}
                        try:
                            tags_response = iam.list_role_tags(RoleName=role_name)
                            for tag in tags_response.get("Tags", []):
                                tags[tag["Key"]] = tag["Value"]
                        except ClientError:
                            pass

                        results.append(RuleResult(
                            resource_id=role_arn,
                            resource_name=role_name,
                            status="PASS" if is_compliant else "FAIL",
                            details={
                                "role_name": role_name,
                                "inline_policy_count": len(inline_policies),
                                "violating_policies": violating_policies,
                                "tags": tags,
                                "message": f"Role has {len(violating_policies)} inline policy(ies) allowing sts:AssumeRole on all resources" if not is_compliant else "No inline policies allow sts:AssumeRole on all resources"
                            }
                        ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove sts:AssumeRole permission from inline policies or scope to specific roles"


class IAMRoleInlinePolicyPassRoleRule(ComplianceRule, InlinePolicyCheckMixin):
    """Ensures IAM role inline policies do not allow iam:PassRole on all resources."""

    rule_id = "IAM_ROLE_INLINE_ALLOWS_PASS_ROLE"
    name = "IAM Role Inline Policy Allows IAM Pass Role on All Resources"
    description = "Ensures IAM role inline policies do not allow iam:PassRole with Resource: *"
    resource_type = "AWS::IAM::Role"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM role inline policies for iam:PassRole."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    role_path = role.get("Path", "/")

                    if self.should_skip_role(role_name, role_path):
                        continue

                    policies_response = iam.list_role_policies(RoleName=role_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    violating_policies = []
                    for policy_name in inline_policies:
                        policy_response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                        policy_doc = policy_response["PolicyDocument"]

                        has_pass_role, stmts = PolicyAnalyzer.allows_iam_pass_role(policy_doc)
                        if has_pass_role:
                            violating_policies.append({
                                "policy_name": policy_name,
                                "violating_statements": stmts
                            })

                    if inline_policies:
                        is_compliant = len(violating_policies) == 0

                        # Fetch role tags
                        tags = {}
                        try:
                            tags_response = iam.list_role_tags(RoleName=role_name)
                            for tag in tags_response.get("Tags", []):
                                tags[tag["Key"]] = tag["Value"]
                        except ClientError:
                            pass

                        results.append(RuleResult(
                            resource_id=role_arn,
                            resource_name=role_name,
                            status="PASS" if is_compliant else "FAIL",
                            details={
                                "role_name": role_name,
                                "inline_policy_count": len(inline_policies),
                                "violating_policies": violating_policies,
                                "tags": tags,
                                "message": f"Role has {len(violating_policies)} inline policy(ies) allowing iam:PassRole on all resources" if not is_compliant else "No inline policies allow iam:PassRole on all resources"
                            }
                        ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove iam:PassRole permission from inline policies or scope to specific roles"


class IAMRoleInlinePolicyNotActionRule(ComplianceRule, InlinePolicyCheckMixin):
    """Ensures IAM role inline policies do not use NotAction with Allow."""

    rule_id = "IAM_ROLE_INLINE_NOTACTION"
    name = "IAM Role Inline Policy Uses NotAction with Allow"
    description = "Ensures IAM role inline policies do not use NotAction with Allow effect"
    resource_type = "AWS::IAM::Role"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM role inline policies for NotAction with Allow."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    role_path = role.get("Path", "/")

                    if self.should_skip_role(role_name, role_path):
                        continue

                    policies_response = iam.list_role_policies(RoleName=role_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    violating_policies = []
                    for policy_name in inline_policies:
                        policy_response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                        policy_doc = policy_response["PolicyDocument"]

                        has_notaction, stmts = PolicyAnalyzer.has_notaction_with_allow(policy_doc)
                        if has_notaction:
                            violating_policies.append({
                                "policy_name": policy_name,
                                "violating_statements": stmts
                            })

                    if inline_policies:
                        is_compliant = len(violating_policies) == 0

                        # Fetch role tags
                        tags = {}
                        try:
                            tags_response = iam.list_role_tags(RoleName=role_name)
                            for tag in tags_response.get("Tags", []):
                                tags[tag["Key"]] = tag["Value"]
                        except ClientError:
                            pass

                        results.append(RuleResult(
                            resource_id=role_arn,
                            resource_name=role_name,
                            status="PASS" if is_compliant else "FAIL",
                            details={
                                "role_name": role_name,
                                "inline_policy_count": len(inline_policies),
                                "violating_policies": violating_policies,
                                "tags": tags,
                                "message": f"Role has {len(violating_policies)} inline policy(ies) using NotAction with Allow" if not is_compliant else "No inline policies use NotAction with Allow"
                            }
                        ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Replace NotAction with explicit Action list using least privilege principle"


# ============================================================================
# IAM Group Inline Policy Rules
# ============================================================================

class IAMGroupInlinePolicyExistsRule(ComplianceRule):
    """Ensures IAM groups do not have inline policies embedded."""

    rule_id = "IAM_GROUP_INLINE_POLICIES"
    name = "IAM Policy Embedded in Group"
    description = "Ensures IAM groups do not have inline policies embedded (use managed policies instead)"
    resource_type = "AWS::IAM::Group"
    severity = Severity.MEDIUM
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM groups for inline policies."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_groups")

            for page in paginator.paginate():
                for group in page.get("Groups", []):
                    group_name = group["GroupName"]
                    group_arn = group["Arn"]

                    policies_response = iam.list_group_policies(GroupName=group_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    is_compliant = len(inline_policies) == 0

                    attached_response = iam.list_attached_group_policies(GroupName=group_name)
                    attached_policies = [p["PolicyName"] for p in attached_response.get("AttachedPolicies", [])]

                    results.append(RuleResult(
                        resource_id=group_arn,
                        resource_name=group_name,
                        status="PASS" if is_compliant else "FAIL",
                        details={
                            "group_name": group_name,
                            "inline_policy_count": len(inline_policies),
                            "inline_policies": inline_policies,
                            "attached_managed_policies": attached_policies,
                            "message": f"Group has {len(inline_policies)} inline policy(ies) embedded" if not is_compliant else "No inline policies embedded"
                        }
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Convert inline policies to managed policies and attach them to the group"


class IAMGroupInlinePolicyAssumeRoleRule(ComplianceRule):
    """Ensures IAM group inline policies do not allow sts:AssumeRole on all resources."""

    rule_id = "IAM_GROUP_INLINE_ALLOWS_ASSUME_ROLE"
    name = "IAM Group Inline Policy Allows STS Assume Role on All Resources"
    description = "Ensures IAM group inline policies do not allow sts:AssumeRole with Resource: *"
    resource_type = "AWS::IAM::Group"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM group inline policies for sts:AssumeRole."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_groups")

            for page in paginator.paginate():
                for group in page.get("Groups", []):
                    group_name = group["GroupName"]
                    group_arn = group["Arn"]

                    policies_response = iam.list_group_policies(GroupName=group_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    violating_policies = []
                    for policy_name in inline_policies:
                        policy_response = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                        policy_doc = policy_response["PolicyDocument"]

                        has_assume_role, stmts = PolicyAnalyzer.allows_sts_assume_role(policy_doc)
                        if has_assume_role:
                            violating_policies.append({
                                "policy_name": policy_name,
                                "violating_statements": stmts
                            })

                    if inline_policies:
                        is_compliant = len(violating_policies) == 0

                        results.append(RuleResult(
                            resource_id=group_arn,
                            resource_name=group_name,
                            status="PASS" if is_compliant else "FAIL",
                            details={
                                "group_name": group_name,
                                "inline_policy_count": len(inline_policies),
                                "violating_policies": violating_policies,
                                "message": f"Group has {len(violating_policies)} inline policy(ies) allowing sts:AssumeRole on all resources" if not is_compliant else "No inline policies allow sts:AssumeRole on all resources"
                            }
                        ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove sts:AssumeRole permission from inline policies or scope to specific roles"


class IAMGroupInlinePolicyPassRoleRule(ComplianceRule):
    """Ensures IAM group inline policies do not allow iam:PassRole on all resources."""

    rule_id = "IAM_GROUP_INLINE_ALLOWS_PASS_ROLE"
    name = "IAM Group Inline Policy Allows IAM Pass Role on All Resources"
    description = "Ensures IAM group inline policies do not allow iam:PassRole with Resource: *"
    resource_type = "AWS::IAM::Group"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM group inline policies for iam:PassRole."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_groups")

            for page in paginator.paginate():
                for group in page.get("Groups", []):
                    group_name = group["GroupName"]
                    group_arn = group["Arn"]

                    policies_response = iam.list_group_policies(GroupName=group_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    violating_policies = []
                    for policy_name in inline_policies:
                        policy_response = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                        policy_doc = policy_response["PolicyDocument"]

                        has_pass_role, stmts = PolicyAnalyzer.allows_iam_pass_role(policy_doc)
                        if has_pass_role:
                            violating_policies.append({
                                "policy_name": policy_name,
                                "violating_statements": stmts
                            })

                    if inline_policies:
                        is_compliant = len(violating_policies) == 0

                        results.append(RuleResult(
                            resource_id=group_arn,
                            resource_name=group_name,
                            status="PASS" if is_compliant else "FAIL",
                            details={
                                "group_name": group_name,
                                "inline_policy_count": len(inline_policies),
                                "violating_policies": violating_policies,
                                "message": f"Group has {len(violating_policies)} inline policy(ies) allowing iam:PassRole on all resources" if not is_compliant else "No inline policies allow iam:PassRole on all resources"
                            }
                        ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove iam:PassRole permission from inline policies or scope to specific roles"


class IAMGroupInlinePolicyNotActionRule(ComplianceRule):
    """Ensures IAM group inline policies do not use NotAction with Allow."""

    rule_id = "IAM_GROUP_INLINE_NOTACTION"
    name = "IAM Group Inline Policy Uses NotAction with Allow"
    description = "Ensures IAM group inline policies do not use NotAction with Allow effect"
    resource_type = "AWS::IAM::Group"
    severity = Severity.HIGH
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate IAM group inline policies for NotAction with Allow."""
        results = []

        if region != "us-east-1":
            return results

        try:
            iam = session.client("iam", region_name=region)

            paginator = iam.get_paginator("list_groups")

            for page in paginator.paginate():
                for group in page.get("Groups", []):
                    group_name = group["GroupName"]
                    group_arn = group["Arn"]

                    policies_response = iam.list_group_policies(GroupName=group_name)
                    inline_policies = policies_response.get("PolicyNames", [])

                    violating_policies = []
                    for policy_name in inline_policies:
                        policy_response = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                        policy_doc = policy_response["PolicyDocument"]

                        has_notaction, stmts = PolicyAnalyzer.has_notaction_with_allow(policy_doc)
                        if has_notaction:
                            violating_policies.append({
                                "policy_name": policy_name,
                                "violating_statements": stmts
                            })

                    if inline_policies:
                        is_compliant = len(violating_policies) == 0

                        results.append(RuleResult(
                            resource_id=group_arn,
                            resource_name=group_name,
                            status="PASS" if is_compliant else "FAIL",
                            details={
                                "group_name": group_name,
                                "inline_policy_count": len(inline_policies),
                                "violating_policies": violating_policies,
                                "message": f"Group has {len(violating_policies)} inline policy(ies) using NotAction with Allow" if not is_compliant else "No inline policies use NotAction with Allow"
                            }
                        ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Replace NotAction with explicit Action list using least privilege principle"
