"""Security Group resource fetcher - fetches all security group data needed by rules."""

from typing import List, Dict, Any
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class SecurityGroupResourceFetcher(ResourceFetcher):
    """
    Fetches EC2 Security Groups with all attributes needed by security group rules.

    This fetcher collects:
    - All security groups with inbound/outbound rules
    - Network interface attachments (to determine if SG is in use)
    - Associated launch configurations and templates
    - Load balancer and RDS associations

    All security group rules can then evaluate against this pre-fetched data
    without making additional API calls.
    """

    resource_types = ["AWS::EC2::SecurityGroup"]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch all security groups with their configurations."""
        resources = []

        try:
            ec2 = session.client("ec2", region_name=region)

            # Collect all security group IDs in use
            used_sg_ids = set()

            # Get security groups attached to network interfaces
            try:
                eni_paginator = ec2.get_paginator("describe_network_interfaces")
                eni_to_sg: Dict[str, List[Dict[str, Any]]] = {}  # sg_id -> list of ENI info

                for page in eni_paginator.paginate():
                    for eni in page.get("NetworkInterfaces", []):
                        eni_info = {
                            "network_interface_id": eni["NetworkInterfaceId"],
                            "interface_type": eni.get("InterfaceType", "unknown"),
                            "description": eni.get("Description", ""),
                            "status": eni.get("Status"),
                            "private_ip": eni.get("PrivateIpAddress"),
                            "availability_zone": eni.get("AvailabilityZone"),
                        }

                        # Determine attached resource
                        attachment = eni.get("Attachment", {})
                        description = eni.get("Description", "").lower()

                        if attachment.get("InstanceId"):
                            eni_info["attached_resource_type"] = "EC2 Instance"
                            eni_info["attached_resource_id"] = attachment["InstanceId"]
                        elif "rds" in description:
                            eni_info["attached_resource_type"] = "RDS Instance"
                            eni_info["attached_resource_id"] = eni.get("Description", "")
                        elif "elb" in description:
                            eni_info["attached_resource_type"] = "Load Balancer"
                            eni_info["attached_resource_id"] = eni.get("Description", "")
                        elif "lambda" in description:
                            eni_info["attached_resource_type"] = "Lambda Function"
                            eni_info["attached_resource_id"] = eni.get("Description", "")
                        elif eni.get("InterfaceType") == "nat_gateway":
                            eni_info["attached_resource_type"] = "NAT Gateway"
                            eni_info["attached_resource_id"] = eni.get("Description", "")
                        elif eni.get("InterfaceType") == "vpc_endpoint":
                            eni_info["attached_resource_type"] = "VPC Endpoint"
                            eni_info["attached_resource_id"] = eni.get("Description", "")
                        else:
                            eni_info["attached_resource_type"] = eni.get("InterfaceType", "unknown")
                            eni_info["attached_resource_id"] = eni.get("Description", "") or eni["NetworkInterfaceId"]

                        for group in eni.get("Groups", []):
                            sg_id = group["GroupId"]
                            used_sg_ids.add(sg_id)
                            if sg_id not in eni_to_sg:
                                eni_to_sg[sg_id] = []
                            eni_to_sg[sg_id].append(eni_info)
            except ClientError:
                eni_to_sg = {}

            # Check launch configurations
            try:
                autoscaling = session.client("autoscaling", region_name=region)
                lc_paginator = autoscaling.get_paginator("describe_launch_configurations")
                for page in lc_paginator.paginate():
                    for lc in page.get("LaunchConfigurations", []):
                        for sg_id in lc.get("SecurityGroups", []):
                            used_sg_ids.add(sg_id)
            except ClientError:
                pass

            # Check launch templates
            try:
                lt_paginator = ec2.get_paginator("describe_launch_templates")
                for page in lt_paginator.paginate():
                    for lt in page.get("LaunchTemplates", []):
                        try:
                            lt_version = ec2.describe_launch_template_versions(
                                LaunchTemplateId=lt["LaunchTemplateId"],
                                Versions=["$Default"]
                            )
                            for version in lt_version.get("LaunchTemplateVersions", []):
                                lt_data = version.get("LaunchTemplateData", {})
                                for sg in lt_data.get("SecurityGroupIds", []):
                                    used_sg_ids.add(sg)
                                for ni in lt_data.get("NetworkInterfaces", []):
                                    for sg in ni.get("Groups", []):
                                        used_sg_ids.add(sg)
                        except ClientError:
                            pass
            except ClientError:
                pass

            # Check classic ELBs
            try:
                elb = session.client("elb", region_name=region)
                elb_response = elb.describe_load_balancers()
                for lb in elb_response.get("LoadBalancerDescriptions", []):
                    for sg_id in lb.get("SecurityGroups", []):
                        used_sg_ids.add(sg_id)
            except ClientError:
                pass

            # Check ALBs/NLBs
            try:
                elbv2 = session.client("elbv2", region_name=region)
                elbv2_paginator = elbv2.get_paginator("describe_load_balancers")
                for page in elbv2_paginator.paginate():
                    for lb in page.get("LoadBalancers", []):
                        for sg_id in lb.get("SecurityGroups", []):
                            used_sg_ids.add(sg_id)
            except ClientError:
                pass

            # Check RDS instances
            try:
                rds = session.client("rds", region_name=region)
                rds_paginator = rds.get_paginator("describe_db_instances")
                for page in rds_paginator.paginate():
                    for db in page.get("DBInstances", []):
                        for sg in db.get("VpcSecurityGroups", []):
                            sg_id = sg.get("VpcSecurityGroupId")
                            if sg_id:
                                used_sg_ids.add(sg_id)
            except ClientError:
                pass

            # Get all security groups
            sg_paginator = ec2.get_paginator("describe_security_groups")
            all_sgs = []

            for page in sg_paginator.paginate():
                all_sgs.extend(page.get("SecurityGroups", []))

            # Check security groups referenced by other security groups
            for sg in all_sgs:
                for rule in sg.get("IpPermissions", []):
                    for pair in rule.get("UserIdGroupPairs", []):
                        ref_sg_id = pair.get("GroupId")
                        if ref_sg_id:
                            used_sg_ids.add(ref_sg_id)
                for rule in sg.get("IpPermissionsEgress", []):
                    for pair in rule.get("UserIdGroupPairs", []):
                        ref_sg_id = pair.get("GroupId")
                        if ref_sg_id:
                            used_sg_ids.add(ref_sg_id)

            # Build FetchedResource for each security group
            for sg in all_sgs:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", sg_id)
                vpc_id = sg.get("VpcId", "EC2-Classic")
                owner_id = sg.get("OwnerId", account_id)

                is_default = sg_name == "default"
                is_used = sg_id in used_sg_ids
                attached_resources = eni_to_sg.get(sg_id, [])

                attributes = {
                    "security_group_id": sg_id,
                    "security_group_name": sg_name,
                    "vpc_id": vpc_id,
                    "description": sg.get("Description", ""),
                    "is_default": is_default,
                    "is_used": is_used,
                    "inbound_rules": sg.get("IpPermissions", []),
                    "outbound_rules": sg.get("IpPermissionsEgress", []),
                    "inbound_rules_count": len(sg.get("IpPermissions", [])),
                    "outbound_rules_count": len(sg.get("IpPermissionsEgress", [])),
                    "attached_resources": attached_resources,
                    "attached_resource_count": len(attached_resources),
                    "tags": {tag["Key"]: tag["Value"] for tag in sg.get("Tags", [])},
                }

                resource = FetchedResource(
                    resource_id=f"arn:aws:ec2:{region}:{owner_id}:security-group/{sg_id}",
                    resource_name=sg_name,
                    resource_type="AWS::EC2::SecurityGroup",
                    region=region,
                    account_id=owner_id,
                    raw_data=sg,
                    attributes=attributes,
                )
                resources.append(resource)

        except ClientError:
            pass

        return resources
