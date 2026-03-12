"""Redshift compliance rules."""

from typing import List

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


class RedshiftClusterEncryptionRule(ComplianceRule):
    """Ensures Redshift clusters have encryption enabled."""

    rule_id = "REDSHIFT_CLUSTER_ENCRYPTION"
    name = "Redshift Cluster Encryption"
    description = "Ensures Redshift clusters have encryption at rest enabled"
    resource_type = "AWS::Redshift::Cluster"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched Redshift clusters for encryption configuration."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            cluster_id = attrs.get("cluster_identifier", resource.resource_name)

            encrypted = attrs.get("encrypted", False)
            kms_key_id = attrs.get("kms_key_id")

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "encrypted": encrypted,
                "kms_key_id": kms_key_id,
                "message": "Cluster encryption is enabled" if encrypted else "Cluster encryption is not enabled"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=cluster_id,
                status="PASS" if encrypted else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable encryption for the Redshift cluster. Note: This requires creating a new encrypted cluster and migrating data."


class RedshiftClusterPubliclyAccessibleRule(ComplianceRule):
    """Ensures Redshift clusters are not publicly accessible."""

    rule_id = "REDSHIFT_CLUSTER_PUBLICLY_ACCESSIBLE"
    name = "Redshift Cluster Publicly Accessible"
    description = "Ensures Redshift clusters are not publicly accessible from the internet"
    resource_type = "AWS::Redshift::Cluster"
    severity = Severity.CRITICAL
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched Redshift clusters for public accessibility."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            cluster_id = attrs.get("cluster_identifier", resource.resource_name)

            publicly_accessible = attrs.get("publicly_accessible", False)
            endpoint = attrs.get("endpoint", {})

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "publicly_accessible": publicly_accessible,
                "endpoint_address": endpoint.get("address"),
                "endpoint_port": endpoint.get("port"),
                "message": "Cluster is publicly accessible" if publicly_accessible else "Cluster is not publicly accessible"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=cluster_id,
                status="FAIL" if publicly_accessible else "PASS",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Modify the Redshift cluster to disable public accessibility"


class RedshiftParameterGroupLoggingRule(ComplianceRule):
    """Ensures Redshift clusters have audit logging enabled via parameter groups."""

    rule_id = "REDSHIFT_PARAMETER_GROUP_LOGGING"
    name = "Redshift Parameter Group Logging"
    description = "Ensures Redshift clusters have user activity logging enabled in parameter groups"
    resource_type = "AWS::Redshift::Cluster"
    severity = Severity.MEDIUM
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched Redshift clusters for logging configuration."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            cluster_id = attrs.get("cluster_identifier", resource.resource_name)

            logging_enabled = attrs.get("user_activity_logging_enabled", False)
            param_group_names = attrs.get("parameter_groups", [])

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "user_activity_logging_enabled": logging_enabled,
                "message": "User activity logging is enabled" if logging_enabled else "User activity logging is not enabled in parameter group"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=cluster_id,
                status="PASS" if logging_enabled else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable user activity logging by setting enable_user_activity_logging to true in the cluster parameter group"


class RedshiftParameterGroupSSLRule(ComplianceRule):
    """Ensures Redshift clusters require SSL connections via parameter groups."""

    rule_id = "REDSHIFT_PARAMETER_GROUP_SSL"
    name = "Redshift Parameter Group SSL"
    description = "Ensures Redshift clusters require SSL for all connections via parameter groups"
    resource_type = "AWS::Redshift::Cluster"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched Redshift clusters for SSL requirement."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            cluster_id = attrs.get("cluster_identifier", resource.resource_name)

            ssl_required = attrs.get("require_ssl", False)
            param_group_names = attrs.get("parameter_groups", [])

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "require_ssl": ssl_required,
                "message": "SSL is required for connections" if ssl_required else "SSL is not required for connections"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=cluster_id,
                status="PASS" if ssl_required else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable SSL requirement by setting require_ssl to true in the cluster parameter group"


class RedshiftSecurityGroupAllowsInternetRule(ComplianceRule):
    """Ensures Redshift cluster security groups do not allow access from 0.0.0.0/0."""

    rule_id = "REDSHIFT_SECURITY_GROUP_ALLOWS_INTERNET"
    name = "Redshift Security Group Allows Internet Access"
    description = "Ensures Redshift cluster security groups do not allow inbound access from 0.0.0.0/0"
    resource_type = "AWS::Redshift::Cluster"
    severity = Severity.CRITICAL
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched Redshift cluster security groups for open access."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            cluster_id = attrs.get("cluster_identifier", resource.resource_name)

            allows_internet = attrs.get("security_group_allows_internet", False)
            violating_rules = attrs.get("security_group_violating_rules", [])
            sg_ids = attrs.get("vpc_security_group_ids", [])

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "allows_internet_access": allows_internet,
                "violating_rules": violating_rules,
                "message": f"Security group allows access from internet ({len(violating_rules)} rule(s))" if allows_internet else "Security groups do not allow internet access"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=cluster_id,
                status="FAIL" if allows_internet else "PASS",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove inbound rules allowing access from 0.0.0.0/0 or ::/0 from the Redshift cluster security groups"


class RedshiftVersionUpgradeDisabledRule(ComplianceRule):
    """Ensures Redshift clusters have automatic version upgrades enabled."""

    rule_id = "REDSHIFT_VERSION_UPGRADE_DISABLED"
    name = "Redshift Version Upgrade Disabled"
    description = "Ensures Redshift clusters have automatic major version upgrades enabled"
    resource_type = "AWS::Redshift::Cluster"
    severity = Severity.MEDIUM
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched Redshift clusters for version upgrade settings."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            cluster_id = attrs.get("cluster_identifier", resource.resource_name)

            allow_version_upgrade = attrs.get("allow_version_upgrade", True)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "allow_version_upgrade": allow_version_upgrade,
                "message": "Automatic version upgrades are enabled" if allow_version_upgrade else "Automatic version upgrades are disabled"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=cluster_id,
                status="PASS" if allow_version_upgrade else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable automatic version upgrades for the Redshift cluster"
