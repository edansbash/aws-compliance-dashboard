"""EC2, EBS, and AMI compliance rules."""

from typing import List, Dict, Any

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


class EC2PublicIPRule(ComplianceRule):
    """Ensures EC2 instances do not have public IP addresses."""

    rule_id = "EC2_NO_PUBLIC_IP"
    name = "EC2 Instance No Public IP"
    description = "Ensures EC2 instances do not have public IP addresses assigned"
    resource_type = "AWS::EC2::Instance"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched EC2 instances for public IPs."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            instance_id = attrs.get("instance_id", resource.resource_id)

            # Check for public IP
            public_ip = attrs.get("public_ip")
            public_dns = attrs.get("public_dns")

            is_compliant = public_ip is None

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "instance_id": instance_id,
                "public_ip": public_ip,
                "public_dns": public_dns,
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
        return "Remediation not supported - requires manual intervention to remove public IP"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "public_ip": None,
            "public_dns": None
        }


class EBSSnapshotEncryptionRule(ComplianceRule):
    """Ensures EBS snapshots are encrypted."""

    rule_id = "EBS_SNAPSHOT_ENCRYPTED"
    name = "EBS Snapshot Should Be Encrypted"
    description = "Ensures EBS snapshots are encrypted to protect data at rest"
    resource_type = "AWS::EC2::Snapshot"
    severity = Severity.HIGH
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched EBS snapshots for encryption."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            snapshot_id = attrs.get("snapshot_id", resource.resource_id)

            is_encrypted = attrs.get("encrypted", False)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "snapshot_id": snapshot_id,
                "encrypted": is_encrypted,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="PASS" if is_encrypted else "FAIL",
                details=details
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Copy the snapshot with encryption enabled using the default EBS KMS key."""
        snapshot_id = resource_id.split("/")[-1]

        ec2 = session.client("ec2", region_name=region)

        # Get original snapshot details for tags
        original = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
        original_tags = original.get("Tags", [])
        description = original.get("Description", "")

        # Copy snapshot with encryption
        copy_response = ec2.copy_snapshot(
            SourceRegion=region,
            SourceSnapshotId=snapshot_id,
            Description=f"Encrypted copy of {snapshot_id}: {description}",
            Encrypted=True,
            # Uses default AWS managed key (alias/aws/ebs) when KmsKeyId not specified
        )
        new_snapshot_id = copy_response["SnapshotId"]

        # Wait for the copy to complete
        waiter = ec2.get_waiter("snapshot_completed")
        waiter.wait(SnapshotIds=[new_snapshot_id], WaiterConfig={"Delay": 15, "MaxAttempts": 40})

        # Copy tags to new snapshot
        if original_tags:
            ec2.create_tags(Resources=[new_snapshot_id], Tags=original_tags)

        # Delete the original unencrypted snapshot
        ec2.delete_snapshot(SnapshotId=snapshot_id)

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Creates an encrypted copy of the snapshot, copies tags, then deletes the original. WARNING: The snapshot ID will change - update any AMIs or launch templates that reference this snapshot."

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "encrypted": True
        }


class EBSVolumeEncryptionRule(ComplianceRule):
    """Ensures EBS volumes are encrypted."""

    rule_id = "EBS_VOLUME_ENCRYPTED"
    name = "EBS Volume Not Encrypted"
    description = "Ensures EBS volumes are encrypted to protect data at rest"
    resource_type = "AWS::EC2::Volume"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched EBS volumes for encryption."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            volume_id = attrs.get("volume_id", resource.resource_id)

            is_encrypted = attrs.get("encrypted", False)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "volume_id": volume_id,
                "encrypted": is_encrypted,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="PASS" if is_encrypted else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Create a snapshot, copy it with encryption, create new volume from encrypted snapshot, then swap volumes"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "encrypted": True
        }


class EBSSnapshotPublicRule(ComplianceRule):
    """Ensures EBS snapshots are not publicly accessible."""

    rule_id = "EBS_SNAPSHOT_PUBLIC"
    name = "Public EBS Snapshot"
    description = "Ensures EBS snapshots are not shared publicly, which could expose sensitive data"
    resource_type = "AWS::EC2::Snapshot"
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
        """Evaluate pre-fetched EBS snapshots for public accessibility."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            snapshot_id = attrs.get("snapshot_id", resource.resource_id)

            is_public = attrs.get("is_public", False)
            shared_accounts = attrs.get("shared_accounts", [])

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "snapshot_id": snapshot_id,
                "is_public": is_public,
                "shared_accounts": shared_accounts,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if is_public else "PASS",
                details=details
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Remove public access from the EBS snapshot."""
        snapshot_id = resource_id.split("/")[-1]

        ec2 = session.client("ec2", region_name=region)
        ec2.modify_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission",
            OperationType="remove",
            GroupNames=["all"]
        )

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove public access permission from the EBS snapshot"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "is_public": False
        }


class AMIPublicRule(ComplianceRule):
    """Ensures AMIs are not publicly accessible."""

    rule_id = "AMI_PUBLIC"
    name = "Publicly Accessible AMI"
    description = "Ensures AMIs are not shared publicly, which could expose sensitive data or proprietary software"
    resource_type = "AWS::EC2::Image"
    severity = Severity.CRITICAL
    has_remediation = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched AMIs for public accessibility."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            image_id = attrs.get("image_id", resource.resource_id)

            is_public = attrs.get("is_public", False)
            shared_accounts = attrs.get("shared_accounts", [])

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "image_id": image_id,
                "is_public": is_public,
                "shared_accounts": shared_accounts,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if is_public else "PASS",
                details=details
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Remove public access from the AMI."""
        image_id = resource_id.split("/")[-1]

        ec2 = session.client("ec2", region_name=region)
        ec2.modify_image_attribute(
            ImageId=image_id,
            LaunchPermission={
                "Remove": [{"Group": "all"}]
            }
        )

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove public launch permission from the AMI"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "is_public": False
        }
