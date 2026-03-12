"""RDS compliance rules for database security, encryption, availability, and backups."""
from typing import List, Dict, Any

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


class RDSSecurityGroupAllowsAllRule(ComplianceRule):
    """Ensures RDS instances do not have security groups allowing all traffic."""

    rule_id = "RDS_SG_ALLOWS_ALL_TRAFFIC"
    name = "RDS Security Group Allows All Traffic"
    description = "Ensures RDS database instances do not have security groups that allow unrestricted inbound traffic (0.0.0.0/0)"
    resource_type = "AWS::RDS::DBInstance"
    severity = Severity.CRITICAL
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched RDS instances for overly permissive security groups."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            db_instance_id = attrs.get("db_instance_id", resource.resource_name)

            # Get security groups with open access from pre-fetched data
            violating_sgs = attrs.get("security_groups_open_access", [])
            has_violation = len(violating_sgs) > 0

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "violating_rules": violating_sgs,
                "message": f"RDS instance has {len(violating_sgs)} security group rule(s) allowing all traffic" if has_violation else "RDS instance security groups do not allow unrestricted traffic"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=db_instance_id,
                status="FAIL" if has_violation else "PASS",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Modify the RDS instance security groups to restrict inbound traffic to specific IP ranges and ports"


class RDSStorageEncryptionRule(ComplianceRule):
    """Ensures RDS instances have storage encryption enabled."""

    rule_id = "RDS_STORAGE_ENCRYPTION"
    name = "RDS Storage Encryption"
    description = "Ensures RDS database instances have encryption at rest enabled for data protection"
    resource_type = "AWS::RDS::DBInstance"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched RDS instances for storage encryption."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            db_instance_id = attrs.get("db_instance_id", resource.resource_name)
            storage_encrypted = attrs.get("storage_encrypted", False)
            kms_key_id = attrs.get("kms_key_id", "")

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "storage_encrypted": storage_encrypted,
                "kms_key_id": kms_key_id if storage_encrypted else None,
                "message": "RDS instance has storage encryption enabled" if storage_encrypted else "RDS instance does not have storage encryption enabled"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=db_instance_id,
                status="PASS" if storage_encrypted else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable storage encryption for the RDS instance. Note: Encryption can only be enabled during instance creation; for existing instances, create an encrypted snapshot and restore from it"


class RDSInstanceSingleAZRule(ComplianceRule):
    """Ensures RDS instances have Multi-AZ deployment enabled."""

    rule_id = "RDS_INSTANCE_SINGLE_AZ"
    name = "RDS Instance Single AZ"
    description = "Ensures RDS database instances are deployed in Multi-AZ configuration for high availability"
    resource_type = "AWS::RDS::DBInstance"
    severity = Severity.MEDIUM
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched RDS instances for Multi-AZ deployment."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            db_instance_id = attrs.get("db_instance_id", resource.resource_name)

            # Skip read replicas
            if attrs.get("is_read_replica", False):
                continue

            multi_az = attrs.get("multi_az", False)
            availability_zone = attrs.get("availability_zone", "")

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "multi_az": multi_az,
                "availability_zone": availability_zone,
                "secondary_availability_zone": attrs.get("secondary_availability_zone") if multi_az else None,
                "message": "RDS instance is deployed in Multi-AZ configuration" if multi_az else "RDS instance is deployed in a single AZ without high availability"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=db_instance_id,
                status="PASS" if multi_az else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Modify the RDS instance to enable Multi-AZ deployment for high availability and automatic failover"


class RDSBackupRetentionPeriodRule(ComplianceRule):
    """Ensures RDS instances have adequate backup retention period."""

    rule_id = "RDS_BACKUP_RETENTION_PERIOD"
    name = "RDS Backup Retention Period"
    description = "Ensures RDS database instances have a backup retention period of at least 30 days"
    resource_type = "AWS::RDS::DBInstance"
    severity = Severity.MEDIUM
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    min_retention_days = 30

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched RDS instances for backup retention period."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            db_instance_id = attrs.get("db_instance_id", resource.resource_name)
            backup_retention = attrs.get("backup_retention_period", 0)

            meets_requirement = backup_retention >= self.min_retention_days

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "backup_retention_period": backup_retention,
                "minimum_required": self.min_retention_days,
                "message": f"RDS instance has {backup_retention} day backup retention (meets {self.min_retention_days} day requirement)" if meets_requirement else f"RDS instance has only {backup_retention} day backup retention (minimum {self.min_retention_days} days required)"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=db_instance_id,
                status="PASS" if meets_requirement else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Modify the RDS instance to increase the backup retention period to at least 30 days"

    async def remediate(self, session, resource_id: str, region: str, finding_details: Dict[str, Any] = None) -> bool:
        """Increase backup retention period to 30 days on the RDS instance or cluster."""
        db_instance_id = resource_id.split(":")[-1]
        rds = session.client("rds", region_name=region)

        # Check if instance is part of an Aurora cluster
        db_cluster_id = None
        if finding_details and finding_details.get("db_cluster_identifier"):
            db_cluster_id = finding_details["db_cluster_identifier"]
        else:
            # Look up the instance to check for cluster membership
            try:
                response = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
                if response.get("DBInstances"):
                    db_cluster_id = response["DBInstances"][0].get("DBClusterIdentifier")
            except Exception:
                pass

        if db_cluster_id:
            # Aurora cluster - modify at cluster level
            rds.modify_db_cluster(
                DBClusterIdentifier=db_cluster_id,
                BackupRetentionPeriod=self.min_retention_days,
                ApplyImmediately=True
            )
        else:
            # Standalone RDS instance
            rds.modify_db_instance(
                DBInstanceIdentifier=db_instance_id,
                BackupRetentionPeriod=self.min_retention_days,
                ApplyImmediately=True
            )

        return True

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "backup_retention_period": cls.min_retention_days,
        }


class RDSInstancePubliclyAccessibleRule(ComplianceRule):
    """Ensures RDS instances are not publicly accessible."""

    rule_id = "RDS_INSTANCE_PUBLICLY_ACCESSIBLE"
    name = "RDS Instance Publicly Accessible"
    description = "Ensures RDS database instances are not publicly accessible from the internet"
    resource_type = "AWS::RDS::DBInstance"
    severity = Severity.CRITICAL
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched RDS instances for public accessibility."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            db_instance_id = attrs.get("db_instance_id", resource.resource_name)
            publicly_accessible = attrs.get("publicly_accessible", False)
            endpoint = attrs.get("endpoint", {})

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "publicly_accessible": publicly_accessible,
                "endpoint_address": endpoint.get("address") if publicly_accessible else None,
                "endpoint_port": endpoint.get("port") if publicly_accessible else None,
                "message": "RDS instance is publicly accessible from the internet" if publicly_accessible else "RDS instance is not publicly accessible"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=db_instance_id,
                status="FAIL" if publicly_accessible else "PASS",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Modify the RDS instance to disable public accessibility and ensure it is only accessible within the VPC"

    async def remediate(self, session, resource_id: str, region: str, finding_details: Dict[str, Any] = None) -> bool:
        """Disable public accessibility on the RDS instance."""
        db_instance_id = resource_id.split(":")[-1]

        rds = session.client("rds", region_name=region)
        rds.modify_db_instance(
            DBInstanceIdentifier=db_instance_id,
            PubliclyAccessible=False,
            ApplyImmediately=True
        )

        return True

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "publicly_accessible": False,
        }


class RDSBackupEnabledRule(ComplianceRule):
    """Ensures RDS instances have automated backups enabled."""

    rule_id = "RDS_BACKUP_ENABLED"
    name = "RDS Backup Enabled"
    description = "Ensures RDS database instances have automated backups enabled (backup retention period > 0)"
    resource_type = "AWS::RDS::DBInstance"
    severity = Severity.HIGH
    has_remediation = True
    remediation_tested = False
    supports_prefetch = True

    default_retention_days = 7

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched RDS instances for backup enablement."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            db_instance_id = attrs.get("db_instance_id", resource.resource_name)
            backup_retention = attrs.get("backup_retention_period", 0)

            backup_enabled = backup_retention > 0

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "backup_enabled": backup_enabled,
                "backup_retention_period": backup_retention,
                "preferred_backup_window": attrs.get("preferred_backup_window") if backup_enabled else None,
                "latest_restorable_time": attrs.get("latest_restorable_time") if backup_enabled else None,
                "message": f"RDS instance has automated backups enabled with {backup_retention} day retention" if backup_enabled else "RDS instance does not have automated backups enabled"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=db_instance_id,
                status="PASS" if backup_enabled else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable automated backups for the RDS instance by setting the backup retention period to 7 days"

    async def remediate(self, session, resource_id: str, region: str, finding_details: Dict[str, Any] = None) -> bool:
        """Enable automated backups on the RDS instance or cluster with 7-day retention."""
        db_instance_id = resource_id.split(":")[-1]
        rds = session.client("rds", region_name=region)

        # Check if instance is part of an Aurora cluster
        db_cluster_id = None
        if finding_details and finding_details.get("db_cluster_identifier"):
            db_cluster_id = finding_details["db_cluster_identifier"]
        else:
            # Look up the instance to check for cluster membership
            try:
                response = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
                if response.get("DBInstances"):
                    db_cluster_id = response["DBInstances"][0].get("DBClusterIdentifier")
            except Exception:
                pass

        if db_cluster_id:
            # Aurora cluster - modify at cluster level
            rds.modify_db_cluster(
                DBClusterIdentifier=db_cluster_id,
                BackupRetentionPeriod=self.default_retention_days,
                ApplyImmediately=True
            )
        else:
            # Standalone RDS instance
            rds.modify_db_instance(
                DBInstanceIdentifier=db_instance_id,
                BackupRetentionPeriod=self.default_retention_days,
                ApplyImmediately=True
            )

        return True

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "backup_enabled": True,
            "backup_retention_period": cls.default_retention_days,
        }


class RDSAutoMinorVersionUpgradeRule(ComplianceRule):
    """Ensures RDS instances have auto minor version upgrade enabled."""

    rule_id = "RDS_AUTO_MINOR_VERSION_UPGRADE"
    name = "RDS Auto Minor Version Upgrade Disabled"
    description = "Ensures RDS database instances have automatic minor version upgrades enabled for security patches"
    resource_type = "AWS::RDS::DBInstance"
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
        """Evaluate pre-fetched RDS instances for auto minor version upgrade setting."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            db_instance_id = attrs.get("db_instance_id", resource.resource_name)
            auto_minor_version_upgrade = attrs.get("auto_minor_version_upgrade", False)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "auto_minor_version_upgrade": auto_minor_version_upgrade,
                "message": "RDS instance has auto minor version upgrade enabled" if auto_minor_version_upgrade else "RDS instance does not have auto minor version upgrade enabled - security patches may not be applied automatically"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=db_instance_id,
                status="PASS" if auto_minor_version_upgrade else "FAIL",
                details=details
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: Dict[str, Any] = None) -> bool:
        """Enable auto minor version upgrade on the RDS instance."""
        db_instance_id = resource_id.split(":")[-1]

        rds = session.client("rds", region_name=region)
        rds.modify_db_instance(
            DBInstanceIdentifier=db_instance_id,
            AutoMinorVersionUpgrade=True,
            ApplyImmediately=False
        )

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable auto minor version upgrade for the RDS instance to automatically receive security patches"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "auto_minor_version_upgrade": True,
        }


class RDSSnapshotPublicRule(ComplianceRule):
    """Ensures RDS snapshots are not publicly accessible."""

    rule_id = "RDS_SNAPSHOT_PUBLIC"
    name = "RDS Snapshot Publicly Accessible"
    description = "Ensures RDS database snapshots are not shared publicly, which could expose sensitive data"
    resource_type = "AWS::RDS::DBSnapshot"
    severity = Severity.CRITICAL
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched RDS snapshots for public accessibility."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            snapshot_id = attrs.get("snapshot_id", resource.resource_name)

            is_public = attrs.get("is_public", False)
            shared_accounts = attrs.get("shared_accounts", [])
            is_cluster_snapshot = attrs.get("is_cluster_snapshot", False)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "is_public": is_public,
                "shared_accounts": shared_accounts,
                "is_cluster_snapshot": is_cluster_snapshot,
                "message": f"RDS {'cluster ' if is_cluster_snapshot else ''}snapshot is publicly accessible" if is_public else f"RDS {'cluster ' if is_cluster_snapshot else ''}snapshot is not publicly accessible"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=snapshot_id,
                status="FAIL" if is_public else "PASS",
                details=details
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: Dict[str, Any] = None) -> bool:
        """Remove public access from the RDS snapshot."""
        rds = session.client("rds", region_name=region)

        if ":cluster-snapshot:" in resource_id:
            snapshot_id = resource_id.split(":")[-1]
            rds.modify_db_cluster_snapshot_attribute(
                DBClusterSnapshotIdentifier=snapshot_id,
                AttributeName="restore",
                ValuesToRemove=["all"]
            )
        else:
            snapshot_id = resource_id.split(":")[-1]
            rds.modify_db_snapshot_attribute(
                DBSnapshotIdentifier=snapshot_id,
                AttributeName="restore",
                ValuesToRemove=["all"]
            )

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove public access from the RDS snapshot by removing the 'all' restore permission"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "is_public": False,
        }
