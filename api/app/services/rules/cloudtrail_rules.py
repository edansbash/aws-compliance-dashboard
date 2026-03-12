"""CloudTrail compliance rules."""

from typing import List, Dict, Any, TYPE_CHECKING

from app.services.rules.base import ComplianceRule, RuleResult, Severity

if TYPE_CHECKING:
    from app.services.fetchers.base import FetchedResource


class CloudTrailNotMultiRegionRule(ComplianceRule):
    """Ensures CloudTrail is configured for all regions."""

    rule_id = "CLOUDTRAIL_NOT_MULTI_REGION"
    name = "CloudTrail Not Enabled in All Regions"
    description = "Ensures CloudTrail trails are configured as multi-region to capture events across all AWS regions"
    resource_type = "AWS::CloudTrail::Trail"
    severity = Severity.HIGH
    has_remediation = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate CloudTrail trails for multi-region configuration."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            is_multi_region = attrs.get("is_multi_region_trail", False)
            is_logging = attrs.get("is_logging", False)

            # Trail should be multi-region AND actively logging
            is_compliant = is_multi_region and is_logging

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "is_multi_region_trail": is_multi_region,
                "is_logging": is_logging,
                "message": "Trail is multi-region and logging" if is_compliant else
                          "Trail is not configured for all regions" if not is_multi_region else
                          "Trail is not actively logging"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="PASS" if is_compliant else "FAIL",
                details=details
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Enable multi-region trail configuration."""
        trail_name = resource_id.split("/")[-1]

        cloudtrail = session.client("cloudtrail", region_name=region)
        cloudtrail.update_trail(
            Name=trail_name,
            IsMultiRegionTrail=True
        )
        # Also ensure logging is started
        cloudtrail.start_logging(Name=trail_name)

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable multi-region trail configuration and start logging"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "is_multi_region_trail": True,
            "is_logging": True,
        }


class CloudTrailNoCloudWatchLogsRule(ComplianceRule):
    """Ensures CloudTrail is integrated with CloudWatch Logs."""

    rule_id = "CLOUDTRAIL_NO_CLOUDWATCH_LOGS"
    name = "CloudTrail Not Integrated with CloudWatch Logs"
    description = "Ensures CloudTrail trails are configured to send logs to CloudWatch Logs for real-time monitoring and alerting"
    resource_type = "AWS::CloudTrail::Trail"
    severity = Severity.MEDIUM
    has_remediation = False  # Requires CloudWatch log group setup
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate CloudTrail trails for CloudWatch Logs integration."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            log_group_arn = attrs.get("cloud_watch_logs_log_group_arn")
            role_arn = attrs.get("cloud_watch_logs_role_arn")

            # Both log group and role must be configured
            is_compliant = bool(log_group_arn) and bool(role_arn)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "cloud_watch_logs_log_group_arn": log_group_arn,
                "cloud_watch_logs_role_arn": role_arn,
                "message": "Trail is integrated with CloudWatch Logs" if is_compliant else
                          "Trail is not sending logs to CloudWatch Logs"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="PASS" if is_compliant else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Configure CloudWatch Logs log group and IAM role for CloudTrail integration"


class CloudTrailNotEncryptedRule(ComplianceRule):
    """Ensures CloudTrail logs are encrypted with KMS."""

    rule_id = "CLOUDTRAIL_NOT_ENCRYPTED"
    name = "CloudTrail Logs Not Encrypted"
    description = "Ensures CloudTrail trails are configured to encrypt log files using AWS KMS customer managed keys"
    resource_type = "AWS::CloudTrail::Trail"
    severity = Severity.HIGH
    has_remediation = False  # Requires KMS key setup
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate CloudTrail trails for KMS encryption."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            kms_key_id = attrs.get("kms_key_id")
            is_compliant = bool(kms_key_id)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "kms_key_id": kms_key_id,
                "message": f"Trail logs are encrypted with KMS key: {kms_key_id}" if is_compliant else
                          "Trail logs are not encrypted with KMS"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="PASS" if is_compliant else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Configure KMS customer managed key for CloudTrail log encryption"


class CloudTrailLogFileValidationDisabledRule(ComplianceRule):
    """Ensures CloudTrail log file validation is enabled."""

    rule_id = "CLOUDTRAIL_LOG_FILE_VALIDATION_DISABLED"
    name = "CloudTrail Log File Validation Disabled"
    description = "Ensures CloudTrail trails have log file integrity validation enabled to detect tampering"
    resource_type = "AWS::CloudTrail::Trail"
    severity = Severity.MEDIUM
    has_remediation = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate CloudTrail trails for log file validation."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            log_file_validation_enabled = attrs.get("log_file_validation_enabled", False)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "log_file_validation_enabled": log_file_validation_enabled,
                "message": "Log file validation is enabled" if log_file_validation_enabled else
                          "Log file validation is not enabled"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="PASS" if log_file_validation_enabled else "FAIL",
                details=details
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Enable log file validation for the trail."""
        trail_name = resource_id.split("/")[-1]

        cloudtrail = session.client("cloudtrail", region_name=region)
        cloudtrail.update_trail(
            Name=trail_name,
            EnableLogFileValidation=True
        )

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable log file integrity validation for CloudTrail"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "log_file_validation_enabled": True,
        }
