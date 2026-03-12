"""Shared policy analysis utilities for IAM compliance rules."""
from typing import Dict, Any, List, Tuple
import json


class PolicyAnalyzer:
    """Analyzes IAM policy documents for compliance issues."""

    @staticmethod
    def normalize_policy(policy: Any) -> Dict:
        """Normalize policy to dict format."""
        if isinstance(policy, str):
            return json.loads(policy)
        return policy

    @staticmethod
    def get_statements(policy_doc: Dict) -> List[Dict]:
        """Get list of statements from policy document."""
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            return [statements]
        return statements

    @classmethod
    def has_full_privileges(cls, policy_doc: Dict) -> Tuple[bool, List[Dict]]:
        """
        Check if policy grants full admin privileges (*:*).
        Returns (is_violation, violating_statements).
        """
        policy_doc = cls.normalize_policy(policy_doc)
        violating = []

        for stmt in cls.get_statements(policy_doc):
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Check for *:* or full admin
            has_star_action = "*" in actions or any(a == "*:*" for a in actions)
            has_star_resource = "*" in resources

            if has_star_action and has_star_resource:
                violating.append(stmt)

        return len(violating) > 0, violating

    @classmethod
    def allows_sts_assume_role(cls, policy_doc: Dict) -> Tuple[bool, List[Dict]]:
        """
        Check if policy allows sts:AssumeRole on all resources (Resource: *).
        Only flags when resource is overly permissive (wildcard).
        Returns (is_violation, violating_statements).
        """
        policy_doc = cls.normalize_policy(policy_doc)
        violating = []

        for stmt in cls.get_statements(policy_doc):
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Check if resource is overly permissive (wildcard)
            has_star_resource = "*" in resources

            if not has_star_resource:
                continue

            # Check for sts:AssumeRole or wildcards that would include it
            for action in actions:
                action_lower = action.lower()
                if (action_lower == "sts:assumerole" or
                    action_lower == "sts:*" or
                    action_lower == "*" or
                    (action_lower.startswith("sts:") and "*" in action_lower)):
                    violating.append(stmt)
                    break

        return len(violating) > 0, violating

    @classmethod
    def allows_iam_pass_role(cls, policy_doc: Dict) -> Tuple[bool, List[Dict]]:
        """
        Check if policy allows iam:PassRole on all resources (Resource: *).
        Only flags when resource is overly permissive (wildcard).
        Returns (is_violation, violating_statements).
        """
        policy_doc = cls.normalize_policy(policy_doc)
        violating = []

        for stmt in cls.get_statements(policy_doc):
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Check if resource is overly permissive (wildcard)
            has_star_resource = "*" in resources

            if not has_star_resource:
                continue

            # Check for iam:PassRole or wildcards that would include it
            for action in actions:
                action_lower = action.lower()
                if (action_lower == "iam:passrole" or
                    action_lower == "iam:*" or
                    action_lower == "*" or
                    (action_lower.startswith("iam:") and "*" in action_lower)):
                    violating.append(stmt)
                    break

        return len(violating) > 0, violating

    @classmethod
    def has_notaction_with_allow(cls, policy_doc: Dict) -> Tuple[bool, List[Dict]]:
        """
        Check if policy uses NotAction with Allow effect (overly permissive).
        Returns (is_violation, violating_statements).
        """
        policy_doc = cls.normalize_policy(policy_doc)
        violating = []

        for stmt in cls.get_statements(policy_doc):
            if stmt.get("Effect") == "Allow" and "NotAction" in stmt:
                violating.append(stmt)

        return len(violating) > 0, violating

    @classmethod
    def analyze_policy(cls, policy_doc: Dict) -> Dict[str, Any]:
        """
        Run all policy checks and return results.
        """
        has_full_privs, full_privs_stmts = cls.has_full_privileges(policy_doc)
        has_assume_role, assume_role_stmts = cls.allows_sts_assume_role(policy_doc)
        has_pass_role, pass_role_stmts = cls.allows_iam_pass_role(policy_doc)
        has_notaction, notaction_stmts = cls.has_notaction_with_allow(policy_doc)

        return {
            "has_full_privileges": has_full_privs,
            "full_privileges_statements": full_privs_stmts,
            "allows_sts_assume_role": has_assume_role,
            "assume_role_statements": assume_role_stmts,
            "allows_iam_pass_role": has_pass_role,
            "pass_role_statements": pass_role_stmts,
            "has_notaction_with_allow": has_notaction,
            "notaction_statements": notaction_stmts,
        }


class TrustPolicyAnalyzer:
    """Analyzes IAM role trust policies for compliance issues."""

    @staticmethod
    def normalize_policy(policy: Any) -> Dict:
        """Normalize policy to dict format."""
        if isinstance(policy, str):
            return json.loads(policy)
        return policy

    @staticmethod
    def get_statements(policy_doc: Dict) -> List[Dict]:
        """Get list of statements from policy document."""
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            return [statements]
        return statements

    @classmethod
    def allows_all_principals(cls, trust_policy: Dict) -> Tuple[bool, List[Dict]]:
        """
        Check if trust policy allows all principals (Principal: "*").
        Returns (is_violation, violating_statements).
        """
        trust_policy = cls.normalize_policy(trust_policy)
        violating = []

        for stmt in cls.get_statements(trust_policy):
            if stmt.get("Effect") != "Allow":
                continue

            principal = stmt.get("Principal", {})

            # Check for "*" principal
            if principal == "*":
                violating.append(stmt)
                continue

            if isinstance(principal, dict):
                # Check AWS principal
                aws_principal = principal.get("AWS", [])
                if isinstance(aws_principal, str):
                    aws_principal = [aws_principal]
                if "*" in aws_principal:
                    violating.append(stmt)
                    continue

                # Check Federated principal
                federated = principal.get("Federated", [])
                if isinstance(federated, str):
                    federated = [federated]
                if "*" in federated:
                    violating.append(stmt)
                    continue

        return len(violating) > 0, violating

    @staticmethod
    def extract_account_id(arn: str) -> str:
        """Extract AWS account ID from an ARN."""
        if not arn or arn == "*":
            return ""
        # ARN format: arn:aws:iam::ACCOUNT_ID:...
        parts = str(arn).split(":")
        if len(parts) >= 5:
            return parts[4]
        return ""

    @classmethod
    def lacks_external_id_or_mfa(cls, trust_policy: Dict, role_account_id: str = "") -> Tuple[bool, List[Dict], Dict[str, Any]]:
        """
        Check if trust policy allows cross-account assume role without external ID or MFA.
        Returns (is_violation, violating_statements, details).

        Args:
            trust_policy: The trust policy document
            role_account_id: The AWS account ID where the role exists (for same-account detection)
        """
        trust_policy = cls.normalize_policy(trust_policy)
        violating = []
        details = {
            "cross_account_statements": [],
            "missing_external_id": [],
            "missing_mfa": [],
        }

        for stmt in cls.get_statements(trust_policy):
            if stmt.get("Effect") != "Allow":
                continue

            principal = stmt.get("Principal", {})
            condition = stmt.get("Condition", {})

            # Get AWS principals
            aws_principals = []
            if principal == "*":
                aws_principals = ["*"]
            elif isinstance(principal, dict):
                aws_principal = principal.get("AWS", [])
                if isinstance(aws_principal, str):
                    aws_principals = [aws_principal]
                else:
                    aws_principals = aws_principal

            # Check if this is a cross-account trust (has external account ARNs)
            is_cross_account = False
            for p in aws_principals:
                if p == "*":
                    # Wildcard principal is definitely cross-account risk
                    is_cross_account = True
                    break
                elif ":root" in str(p) or ":user/" in str(p) or ":role/" in str(p):
                    # Extract account ID from principal and compare with role's account
                    principal_account_id = cls.extract_account_id(str(p))
                    if principal_account_id and role_account_id:
                        # If principal is in a different account, it's cross-account
                        if principal_account_id != role_account_id:
                            is_cross_account = True
                            break
                    else:
                        # Can't determine, assume cross-account for safety
                        is_cross_account = True
                        break

            if not is_cross_account:
                continue

            details["cross_account_statements"].append(stmt)

            # Check for external ID in condition
            has_external_id = False
            for condition_key in condition.values():
                if isinstance(condition_key, dict) and "sts:ExternalId" in condition_key:
                    has_external_id = True
                    break

            # Check for MFA in condition
            has_mfa = False
            bool_condition = condition.get("Bool", {})
            if bool_condition.get("aws:MultiFactorAuthPresent") == "true":
                has_mfa = True

            if not has_external_id:
                details["missing_external_id"].append(stmt)
            if not has_mfa:
                details["missing_mfa"].append(stmt)

            # Violation if missing both external ID and MFA for cross-account
            if not has_external_id and not has_mfa:
                violating.append(stmt)

        return len(violating) > 0, violating, details
