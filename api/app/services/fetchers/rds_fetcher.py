"""RDS resource fetcher - fetches RDS instances and snapshots."""

from typing import List
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class RDSResourceFetcher(ResourceFetcher):
    """
    Fetches RDS resources including DB instances and snapshots.

    This fetcher collects:
    - RDS DB instances with security groups
    - RDS manual snapshots with sharing permissions
    - RDS cluster snapshots (Aurora)
    """

    resource_types = [
        "AWS::RDS::DBInstance",
        "AWS::RDS::DBSnapshot",
        "AWS::RDS::DBClusterSnapshot",
    ]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch RDS resources based on resource type."""
        if resource_type == "AWS::RDS::DBInstance":
            return await self._fetch_db_instances(session, region, account_id)
        elif resource_type == "AWS::RDS::DBSnapshot":
            return await self._fetch_db_snapshots(session, region, account_id)
        elif resource_type == "AWS::RDS::DBClusterSnapshot":
            return await self._fetch_cluster_snapshots(session, region, account_id)
        return []

    async def _fetch_db_instances(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all RDS DB instances with security group details."""
        resources = []

        try:
            rds = session.client("rds", region_name=region)
            ec2 = session.client("ec2", region_name=region)

            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for instance in page.get("DBInstances", []):
                    db_instance_id = instance["DBInstanceIdentifier"]
                    db_instance_arn = instance["DBInstanceArn"]

                    # Get security group details for checking open rules
                    vpc_security_groups = instance.get("VpcSecurityGroups", [])
                    sg_ids = [sg["VpcSecurityGroupId"] for sg in vpc_security_groups if sg.get("Status") == "active"]

                    security_group_details = []
                    if sg_ids:
                        try:
                            sg_response = ec2.describe_security_groups(GroupIds=sg_ids)
                            security_group_details = sg_response.get("SecurityGroups", [])
                        except ClientError:
                            pass

                    endpoint = instance.get("Endpoint", {})

                    # Get tags
                    tags = {}
                    try:
                        tags_response = rds.list_tags_for_resource(ResourceName=db_instance_arn)
                        for tag in tags_response.get("TagList", []):
                            tags[tag["Key"]] = tag["Value"]
                    except ClientError:
                        pass

                    attributes = {
                        "db_instance_id": db_instance_id,
                        "db_cluster_identifier": instance.get("DBClusterIdentifier"),
                        "engine": instance.get("Engine"),
                        "engine_version": instance.get("EngineVersion"),
                        "db_instance_class": instance.get("DBInstanceClass"),
                        "storage_encrypted": instance.get("StorageEncrypted", False),
                        "kms_key_id": instance.get("KmsKeyId"),
                        "multi_az": instance.get("MultiAZ", False),
                        "availability_zone": instance.get("AvailabilityZone"),
                        "secondary_availability_zone": instance.get("SecondaryAvailabilityZone"),
                        "publicly_accessible": instance.get("PubliclyAccessible", False),
                        "endpoint_address": endpoint.get("Address"),
                        "endpoint_port": endpoint.get("Port"),
                        "backup_retention_period": instance.get("BackupRetentionPeriod", 0),
                        "preferred_backup_window": instance.get("PreferredBackupWindow"),
                        "latest_restorable_time": str(instance.get("LatestRestorableTime")) if instance.get("LatestRestorableTime") else None,
                        "auto_minor_version_upgrade": instance.get("AutoMinorVersionUpgrade", False),
                        "preferred_maintenance_window": instance.get("PreferredMaintenanceWindow"),
                        "vpc_security_groups": vpc_security_groups,
                        "security_group_ids": sg_ids,
                        "security_group_details": security_group_details,
                        "db_subnet_group": instance.get("DBSubnetGroup", {}).get("DBSubnetGroupName"),
                        "is_read_replica": bool(instance.get("ReadReplicaSourceDBInstanceIdentifier")),
                        "read_replica_source": instance.get("ReadReplicaSourceDBInstanceIdentifier"),
                        "db_instance_status": instance.get("DBInstanceStatus"),
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=db_instance_arn,
                        resource_name=db_instance_id,
                        resource_type="AWS::RDS::DBInstance",
                        region=region,
                        account_id=account_id,
                        raw_data=instance,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_db_snapshots(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all manual RDS snapshots with sharing permissions."""
        resources = []

        try:
            rds = session.client("rds", region_name=region)

            snapshot_paginator = rds.get_paginator("describe_db_snapshots")
            for page in snapshot_paginator.paginate(SnapshotType="manual"):
                for snapshot in page.get("DBSnapshots", []):
                    snapshot_id = snapshot["DBSnapshotIdentifier"]
                    snapshot_arn = snapshot["DBSnapshotArn"]

                    # Get snapshot attributes (public/shared)
                    is_public = False
                    shared_accounts = []
                    try:
                        attr_response = rds.describe_db_snapshot_attributes(
                            DBSnapshotIdentifier=snapshot_id
                        )
                        attributes_result = attr_response.get("DBSnapshotAttributesResult", {})
                        for attr in attributes_result.get("DBSnapshotAttributes", []):
                            if attr.get("AttributeName") == "restore":
                                values = attr.get("AttributeValues", [])
                                if "all" in values:
                                    is_public = True
                                shared_accounts = [v for v in values if v != "all"]
                    except ClientError:
                        pass

                    # Get tags
                    tags = {}
                    try:
                        tags_response = rds.list_tags_for_resource(ResourceName=snapshot_arn)
                        for tag in tags_response.get("TagList", []):
                            tags[tag["Key"]] = tag["Value"]
                    except ClientError:
                        pass

                    attributes = {
                        "snapshot_id": snapshot_id,
                        "db_instance_id": snapshot.get("DBInstanceIdentifier"),
                        "engine": snapshot.get("Engine"),
                        "engine_version": snapshot.get("EngineVersion"),
                        "is_public": is_public,
                        "shared_accounts": shared_accounts,
                        "snapshot_type": snapshot.get("SnapshotType"),
                        "status": snapshot.get("Status"),
                        "encrypted": snapshot.get("Encrypted", False),
                        "kms_key_id": snapshot.get("KmsKeyId"),
                        "snapshot_create_time": str(snapshot.get("SnapshotCreateTime")) if snapshot.get("SnapshotCreateTime") else None,
                        "allocated_storage": snapshot.get("AllocatedStorage"),
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=snapshot_arn,
                        resource_name=snapshot_id,
                        resource_type="AWS::RDS::DBSnapshot",
                        region=region,
                        account_id=account_id,
                        raw_data=snapshot,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_cluster_snapshots(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all manual Aurora cluster snapshots with sharing permissions."""
        resources = []

        try:
            rds = session.client("rds", region_name=region)

            try:
                cluster_snapshot_paginator = rds.get_paginator("describe_db_cluster_snapshots")
                for page in cluster_snapshot_paginator.paginate(SnapshotType="manual"):
                    for snapshot in page.get("DBClusterSnapshots", []):
                        snapshot_id = snapshot["DBClusterSnapshotIdentifier"]
                        snapshot_arn = snapshot["DBClusterSnapshotArn"]

                        # Get snapshot attributes (public/shared)
                        is_public = False
                        shared_accounts = []
                        try:
                            attr_response = rds.describe_db_cluster_snapshot_attributes(
                                DBClusterSnapshotIdentifier=snapshot_id
                            )
                            attributes_result = attr_response.get("DBClusterSnapshotAttributesResult", {})
                            for attr in attributes_result.get("DBClusterSnapshotAttributes", []):
                                if attr.get("AttributeName") == "restore":
                                    values = attr.get("AttributeValues", [])
                                    if "all" in values:
                                        is_public = True
                                    shared_accounts = [v for v in values if v != "all"]
                        except ClientError:
                            pass

                        # Get tags
                        tags = {}
                        try:
                            tags_response = rds.list_tags_for_resource(ResourceName=snapshot_arn)
                            for tag in tags_response.get("TagList", []):
                                tags[tag["Key"]] = tag["Value"]
                        except ClientError:
                            pass

                        attributes = {
                            "snapshot_id": snapshot_id,
                            "db_cluster_id": snapshot.get("DBClusterIdentifier"),
                            "engine": snapshot.get("Engine"),
                            "engine_version": snapshot.get("EngineVersion"),
                            "is_public": is_public,
                            "shared_accounts": shared_accounts,
                            "snapshot_type": snapshot.get("SnapshotType"),
                            "status": snapshot.get("Status"),
                            "storage_encrypted": snapshot.get("StorageEncrypted", False),
                            "kms_key_id": snapshot.get("KmsKeyId"),
                            "snapshot_create_time": str(snapshot.get("SnapshotCreateTime")) if snapshot.get("SnapshotCreateTime") else None,
                            "allocated_storage": snapshot.get("AllocatedStorage"),
                            "is_cluster_snapshot": True,
                            "tags": tags,
                        }

                        resource = FetchedResource(
                            resource_id=snapshot_arn,
                            resource_name=snapshot_id,
                            resource_type="AWS::RDS::DBClusterSnapshot",
                            region=region,
                            account_id=account_id,
                            raw_data=snapshot,
                            attributes=attributes,
                        )
                        resources.append(resource)

            except ClientError:
                # Cluster snapshots might not be available in all configurations
                pass

        except ClientError:
            pass

        return resources
