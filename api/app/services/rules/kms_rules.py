"""KMS compliance rules."""

from typing import List, Dict, Any

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


class KMSKeyRotationDisabledRule(ComplianceRule):
    """Ensures KMS customer-managed keys have automatic rotation enabled."""

    rule_id = "KMS_KEY_ROTATION_DISABLED"
    name = "KMS Key Rotation Disabled"
    description = "Ensures KMS customer-managed keys have automatic key rotation enabled for security best practices"
    resource_type = "AWS::KMS::Key"
    severity = Severity.MEDIUM
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched KMS keys for rotation status."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            key_id = attrs.get("key_id", resource.resource_id)
            key_arn = attrs.get("key_arn", resource.resource_id)
            key_name = resource.resource_name

            key_manager = attrs.get("key_manager")
            key_state = attrs.get("key_state")
            key_spec = attrs.get("key_spec", "")
            aliases = attrs.get("aliases", [])

            # Only check customer-managed symmetric keys that are enabled
            # (rotation is not applicable to AWS-managed keys, asymmetric keys, or disabled keys)
            is_symmetric = attrs.get("is_symmetric", key_spec == "SYMMETRIC_DEFAULT")
            if not is_symmetric:
                continue

            rotation_enabled = attrs.get("key_rotation_enabled", False)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "rotation_enabled": rotation_enabled,
                "message": "Key rotation is enabled" if rotation_enabled else "Key rotation is not enabled"
            })

            results.append(RuleResult(
                resource_id=key_arn,
                resource_name=key_name,
                status="PASS" if rotation_enabled else "FAIL",
                details=details
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Enable key rotation for the KMS key."""
        # Extract key ID from ARN
        key_id = resource_id.split("/")[-1]

        kms = session.client("kms", region_name=region)
        kms.enable_key_rotation(KeyId=key_id)

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable automatic key rotation for the KMS customer-managed key"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "key_rotation_enabled": True,
        }
