"""EC2 resource fetcher - fetches EC2 instances, EBS volumes, snapshots, and AMIs."""

from typing import List, Dict, Any
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class EC2ResourceFetcher(ResourceFetcher):
    """
    Fetches EC2 resources including instances, volumes, snapshots, and AMIs.

    This fetcher collects:
    - EC2 instances with network configuration
    - EBS volumes with encryption status
    - EBS snapshots with permissions
    - AMIs with launch permissions
    """

    resource_types = [
        "AWS::EC2::Instance",
        "AWS::EC2::Volume",
        "AWS::EC2::Snapshot",
        "AWS::EC2::Image",
    ]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch EC2 resources based on resource type."""
        if resource_type == "AWS::EC2::Instance":
            return await self._fetch_instances(session, region, account_id)
        elif resource_type == "AWS::EC2::Volume":
            return await self._fetch_volumes(session, region, account_id)
        elif resource_type == "AWS::EC2::Snapshot":
            return await self._fetch_snapshots(session, region, account_id)
        elif resource_type == "AWS::EC2::Image":
            return await self._fetch_images(session, region, account_id)
        return []

    async def _fetch_instances(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all EC2 instances."""
        resources = []

        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")

            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance_id = instance["InstanceId"]
                        owner_id = instance.get("OwnerId", account_id)

                        # Get instance name from tags
                        instance_name = instance_id
                        tags = {}
                        for tag in instance.get("Tags", []):
                            tags[tag["Key"]] = tag["Value"]
                            if tag["Key"] == "Name":
                                instance_name = tag["Value"]

                        attributes = {
                            "instance_id": instance_id,
                            "instance_type": instance.get("InstanceType"),
                            "instance_state": instance.get("State", {}).get("Name"),
                            "public_ip": instance.get("PublicIpAddress"),
                            "public_dns": instance.get("PublicDnsName"),
                            "private_ip": instance.get("PrivateIpAddress"),
                            "private_dns": instance.get("PrivateDnsName"),
                            "vpc_id": instance.get("VpcId"),
                            "subnet_id": instance.get("SubnetId"),
                            "security_groups": instance.get("SecurityGroups", []),
                            "iam_instance_profile": instance.get("IamInstanceProfile"),
                            "launch_time": instance.get("LaunchTime"),
                            "platform": instance.get("Platform"),
                            "architecture": instance.get("Architecture"),
                            "root_device_type": instance.get("RootDeviceType"),
                            "tags": tags,
                        }

                        resource = FetchedResource(
                            resource_id=f"arn:aws:ec2:{region}:{owner_id}:instance/{instance_id}",
                            resource_name=instance_name,
                            resource_type="AWS::EC2::Instance",
                            region=region,
                            account_id=owner_id,
                            raw_data=instance,
                            attributes=attributes,
                        )
                        resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_volumes(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all EBS volumes."""
        resources = []

        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_volumes")

            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    volume_id = volume["VolumeId"]

                    # Get volume name from tags
                    volume_name = volume_id
                    tags = {}
                    for tag in volume.get("Tags", []):
                        tags[tag["Key"]] = tag["Value"]
                        if tag["Key"] == "Name":
                            volume_name = tag["Value"]

                    # Get attached instance
                    attachments = volume.get("Attachments", [])
                    attached_instance = attachments[0].get("InstanceId") if attachments else None

                    attributes = {
                        "volume_id": volume_id,
                        "encrypted": volume.get("Encrypted", False),
                        "kms_key_id": volume.get("KmsKeyId"),
                        "volume_type": volume.get("VolumeType"),
                        "size_gb": volume.get("Size"),
                        "state": volume.get("State"),
                        "availability_zone": volume.get("AvailabilityZone"),
                        "attached_instance": attached_instance,
                        "attachments": attachments,
                        "iops": volume.get("Iops"),
                        "throughput": volume.get("Throughput"),
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}",
                        resource_name=volume_name,
                        resource_type="AWS::EC2::Volume",
                        region=region,
                        account_id=account_id,
                        raw_data=volume,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_snapshots(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all EBS snapshots owned by this account."""
        resources = []

        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_snapshots")

            for page in paginator.paginate(OwnerIds=["self"]):
                for snapshot in page.get("Snapshots", []):
                    snapshot_id = snapshot["SnapshotId"]

                    # Get snapshot name from tags
                    snapshot_name = snapshot_id
                    tags = {}
                    for tag in snapshot.get("Tags", []):
                        tags[tag["Key"]] = tag["Value"]
                        if tag["Key"] == "Name":
                            snapshot_name = tag["Value"]

                    # Check snapshot permissions (public/shared)
                    is_public = False
                    shared_accounts = []
                    try:
                        attr_response = ec2.describe_snapshot_attribute(
                            SnapshotId=snapshot_id,
                            Attribute="createVolumePermission"
                        )
                        permissions = attr_response.get("CreateVolumePermissions", [])
                        is_public = any(perm.get("Group") == "all" for perm in permissions)
                        shared_accounts = [perm.get("UserId") for perm in permissions if perm.get("UserId")]
                    except ClientError:
                        pass

                    attributes = {
                        "snapshot_id": snapshot_id,
                        "encrypted": snapshot.get("Encrypted", False),
                        "kms_key_id": snapshot.get("KmsKeyId"),
                        "volume_id": snapshot.get("VolumeId"),
                        "volume_size": snapshot.get("VolumeSize"),
                        "state": snapshot.get("State"),
                        "description": snapshot.get("Description", ""),
                        "is_public": is_public,
                        "shared_accounts": shared_accounts,
                        "start_time": snapshot.get("StartTime"),
                        "progress": snapshot.get("Progress"),
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=f"arn:aws:ec2:{region}:{account_id}:snapshot/{snapshot_id}",
                        resource_name=snapshot_name,
                        resource_type="AWS::EC2::Snapshot",
                        region=region,
                        account_id=account_id,
                        raw_data=snapshot,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_images(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all AMIs owned by this account."""
        resources = []

        try:
            ec2 = session.client("ec2", region_name=region)

            # Get owned AMIs
            response = ec2.describe_images(Owners=["self"])

            for image in response.get("Images", []):
                image_id = image["ImageId"]
                image_name = image.get("Name", image_id)
                is_public = image.get("Public", False)

                # Get launch permissions
                shared_accounts = []
                try:
                    attr_response = ec2.describe_image_attribute(
                        ImageId=image_id,
                        Attribute="launchPermission"
                    )
                    permissions = attr_response.get("LaunchPermissions", [])
                    shared_accounts = [perm.get("UserId") for perm in permissions if perm.get("UserId")]
                except ClientError:
                    pass

                tags = {}
                for tag in image.get("Tags", []):
                    tags[tag["Key"]] = tag["Value"]

                attributes = {
                    "image_id": image_id,
                    "is_public": is_public,
                    "shared_accounts": shared_accounts,
                    "state": image.get("State"),
                    "architecture": image.get("Architecture"),
                    "platform": image.get("PlatformDetails"),
                    "creation_date": image.get("CreationDate"),
                    "description": image.get("Description", ""),
                    "image_type": image.get("ImageType"),
                    "root_device_type": image.get("RootDeviceType"),
                    "virtualization_type": image.get("VirtualizationType"),
                    "tags": tags,
                }

                resource = FetchedResource(
                    resource_id=f"arn:aws:ec2:{region}:{account_id}:image/{image_id}",
                    resource_name=image_name,
                    resource_type="AWS::EC2::Image",
                    region=region,
                    account_id=account_id,
                    raw_data=image,
                    attributes=attributes,
                )
                resources.append(resource)

        except ClientError:
            pass

        return resources
