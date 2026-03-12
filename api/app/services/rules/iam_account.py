"""IAM account-level compliance rules."""
from typing import List

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


class IAMRootAccessKeysRule(ComplianceRule):
    """Ensures the root account does not have access keys."""

    rule_id = "IAM_ROOT_ACCESS_KEYS"
    name = "IAM Root Account Access Keys"
    description = "Ensures the root account does not have access keys configured"
    resource_type = "AWS::IAM::AccountSummary"
    severity = Severity.CRITICAL
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched account summary for root access keys."""
        results = []

        for resource in resources:
            # Skip non-AccountSummary resources (safety check)
            if resource.resource_type != "AWS::IAM::AccountSummary":
                continue

            attrs = resource.attributes
            # Use resource.account_id directly
            account_id = resource.account_id

            # Skip if credential report wasn't available (can't reliably check access keys)
            if not attrs.get("credential_report_available", False):
                continue

            # Check if root has access keys (fetcher provides boolean and list)
            root_has_access_keys = attrs.get("root_has_access_keys", False)
            root_access_keys = attrs.get("root_access_keys", [])

            is_compliant = not root_has_access_keys

            results.append(RuleResult(
                resource_id=f"arn:aws:iam::{account_id}:root",
                resource_name="Root Account",
                status="PASS" if is_compliant else "FAIL",
                details={
                    "account_id": account_id,
                    "has_access_keys": root_has_access_keys,
                    "access_key_count": len(root_access_keys),
                    "message": "Root account has access keys configured - this is a critical security risk" if not is_compliant else "Root account has no access keys"
                }
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Delete root account access keys immediately. Use IAM users or roles for programmatic access."


class IAMRootActiveCertificatesRule(ComplianceRule):
    """Ensures the root account does not have active signing certificates."""

    rule_id = "IAM_ROOT_ACTIVE_CERTIFICATES"
    name = "IAM Root Account Active Certificates"
    description = "Ensures the root account does not have active signing certificates"
    resource_type = "AWS::IAM::AccountSummary"
    severity = Severity.CRITICAL
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched account summary for root signing certificates."""
        results = []

        for resource in resources:
            # Skip non-AccountSummary resources (safety check)
            if resource.resource_type != "AWS::IAM::AccountSummary":
                continue

            attrs = resource.attributes
            # Use resource.account_id directly
            account_id = resource.account_id

            # Skip if credential report wasn't available (can't reliably check certificates)
            if not attrs.get("credential_report_available", False):
                continue

            # Check if root has signing certificates (fetcher provides boolean)
            root_has_active_certs = attrs.get("root_has_active_certs", False)

            is_compliant = not root_has_active_certs

            results.append(RuleResult(
                resource_id=f"arn:aws:iam::{account_id}:root",
                resource_name="Root Account",
                status="PASS" if is_compliant else "FAIL",
                details={
                    "account_id": account_id,
                    "has_active_certificates": root_has_active_certs,
                    "message": "Root account has active signing certificates - this is a critical security risk" if not is_compliant else "Root account has no active signing certificates"
                }
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Delete root account signing certificates. Use IAM users or roles with properly scoped permissions."


class IAMRootMFARule(ComplianceRule):
    """Ensures the root account has MFA enabled."""

    rule_id = "IAM_ROOT_MFA"
    name = "IAM Root Account MFA Enabled"
    description = "Ensures the root account has multi-factor authentication (MFA) enabled"
    resource_type = "AWS::IAM::AccountSummary"
    severity = Severity.CRITICAL
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched account summary for root MFA configuration."""
        results = []

        for resource in resources:
            # Skip non-AccountSummary resources (safety check)
            if resource.resource_type != "AWS::IAM::AccountSummary":
                continue

            attrs = resource.attributes
            # Use resource.account_id directly
            account_id = resource.account_id

            # Check if root has MFA enabled
            root_mfa_enabled = attrs.get("root_mfa_enabled", False)
            # Check if root credentials are disabled (AWS Organizations centralized management)
            root_credentials_disabled = attrs.get("root_credentials_disabled", False)

            # Compliant if MFA is enabled OR if root credentials are disabled (centralized management)
            is_compliant = root_mfa_enabled or root_credentials_disabled

            # Determine the appropriate message
            if root_credentials_disabled:
                message = "Root credentials are disabled (AWS Organizations centralized root management)"
            elif root_mfa_enabled:
                message = "Root account has MFA enabled"
            else:
                message = "Root account does not have MFA enabled - this is a critical security risk"

            results.append(RuleResult(
                resource_id=f"arn:aws:iam::{account_id}:root",
                resource_name="Root Account",
                status="PASS" if is_compliant else "FAIL",
                details={
                    "account_id": account_id,
                    "mfa_enabled": root_mfa_enabled,
                    "root_credentials_disabled": root_credentials_disabled,
                    "message": message
                }
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable MFA on the root account using a hardware or virtual MFA device"
