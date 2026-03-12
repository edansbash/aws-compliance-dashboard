"""VPC resource fetcher - fetches VPCs, subnets, NACLs, and flow logs."""

from typing import List
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class VPCResourceFetcher(ResourceFetcher):
    """
    Fetches VPC resources including VPCs, subnets, network ACLs, and flow logs.

    This fetcher collects:
    - VPCs with flow log status
    - Subnets with route table associations
    - Network ACLs with rules
    - Flow logs
    """

    resource_types = [
        "AWS::EC2::VPC",
        "AWS::EC2::Subnet",
        "AWS::EC2::NetworkAcl",
        "AWS::EC2::FlowLog",
    ]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch VPC resources based on resource type."""
        if resource_type == "AWS::EC2::VPC":
            return await self._fetch_vpcs(session, region, account_id)
        elif resource_type == "AWS::EC2::Subnet":
            return await self._fetch_subnets(session, region, account_id)
        elif resource_type == "AWS::EC2::NetworkAcl":
            return await self._fetch_network_acls(session, region, account_id)
        elif resource_type == "AWS::EC2::FlowLog":
            return await self._fetch_flow_logs(session, region, account_id)
        return []

    async def _fetch_vpcs(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all VPCs with flow log status."""
        resources = []

        try:
            ec2 = session.client("ec2", region_name=region)

            # Get all flow logs to determine which VPCs have them
            flow_logs_by_vpc = {}
            try:
                fl_paginator = ec2.get_paginator("describe_flow_logs")
                for page in fl_paginator.paginate():
                    for fl in page.get("FlowLogs", []):
                        resource_id = fl.get("ResourceId")
                        if resource_id:
                            if resource_id not in flow_logs_by_vpc:
                                flow_logs_by_vpc[resource_id] = []
                            flow_logs_by_vpc[resource_id].append({
                                "flow_log_id": fl.get("FlowLogId"),
                                "traffic_type": fl.get("TrafficType"),
                                "log_destination_type": fl.get("LogDestinationType"),
                                "log_destination": fl.get("LogDestination"),
                                "flow_log_status": fl.get("FlowLogStatus"),
                            })
            except ClientError:
                pass

            # Get all VPCs
            vpc_paginator = ec2.get_paginator("describe_vpcs")
            for page in vpc_paginator.paginate():
                for vpc in page.get("Vpcs", []):
                    vpc_id = vpc["VpcId"]
                    owner_id = vpc.get("OwnerId", account_id)

                    # Get VPC name from tags
                    vpc_name = vpc_id
                    tags = {}
                    for tag in vpc.get("Tags", []):
                        tags[tag["Key"]] = tag["Value"]
                        if tag["Key"] == "Name":
                            vpc_name = tag["Value"]

                    vpc_flow_logs = flow_logs_by_vpc.get(vpc_id, [])

                    # Get default security group
                    default_sg = None
                    try:
                        sg_response = ec2.describe_security_groups(
                            Filters=[
                                {"Name": "vpc-id", "Values": [vpc_id]},
                                {"Name": "group-name", "Values": ["default"]},
                            ]
                        )
                        if sg_response.get("SecurityGroups"):
                            default_sg = sg_response["SecurityGroups"][0]
                    except ClientError:
                        pass

                    attributes = {
                        "vpc_id": vpc_id,
                        "cidr_block": vpc.get("CidrBlock"),
                        "is_default": vpc.get("IsDefault", False),
                        "state": vpc.get("State"),
                        "instance_tenancy": vpc.get("InstanceTenancy"),
                        "flow_logs": vpc_flow_logs,
                        "has_flow_logs": len(vpc_flow_logs) > 0,
                        "default_security_group": default_sg,
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:vpc/{vpc_id}",
                        resource_name=vpc_name,
                        resource_type="AWS::EC2::VPC",
                        region=region,
                        account_id=owner_id,
                        raw_data=vpc,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_subnets(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all subnets with flow log status."""
        resources = []

        try:
            ec2 = session.client("ec2", region_name=region)

            # Get all flow logs
            flow_logs_by_subnet = {}
            try:
                fl_paginator = ec2.get_paginator("describe_flow_logs")
                for page in fl_paginator.paginate():
                    for fl in page.get("FlowLogs", []):
                        resource_id = fl.get("ResourceId")
                        if resource_id and resource_id.startswith("subnet-"):
                            if resource_id not in flow_logs_by_subnet:
                                flow_logs_by_subnet[resource_id] = []
                            flow_logs_by_subnet[resource_id].append({
                                "flow_log_id": fl.get("FlowLogId"),
                                "traffic_type": fl.get("TrafficType"),
                                "log_destination_type": fl.get("LogDestinationType"),
                            })
            except ClientError:
                pass

            # Get all subnets
            subnet_paginator = ec2.get_paginator("describe_subnets")
            for page in subnet_paginator.paginate():
                for subnet in page.get("Subnets", []):
                    subnet_id = subnet["SubnetId"]
                    owner_id = subnet.get("OwnerId", account_id)

                    # Get subnet name from tags
                    subnet_name = subnet_id
                    tags = {}
                    for tag in subnet.get("Tags", []):
                        tags[tag["Key"]] = tag["Value"]
                        if tag["Key"] == "Name":
                            subnet_name = tag["Value"]

                    subnet_flow_logs = flow_logs_by_subnet.get(subnet_id, [])

                    attributes = {
                        "subnet_id": subnet_id,
                        "vpc_id": subnet.get("VpcId"),
                        "cidr_block": subnet.get("CidrBlock"),
                        "availability_zone": subnet.get("AvailabilityZone"),
                        "available_ip_address_count": subnet.get("AvailableIpAddressCount"),
                        "default_for_az": subnet.get("DefaultForAz", False),
                        "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch", False),
                        "state": subnet.get("State"),
                        "flow_logs": subnet_flow_logs,
                        "has_flow_logs": len(subnet_flow_logs) > 0,
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:subnet/{subnet_id}",
                        resource_name=subnet_name,
                        resource_type="AWS::EC2::Subnet",
                        region=region,
                        account_id=owner_id,
                        raw_data=subnet,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_network_acls(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all network ACLs with rules."""
        resources = []

        try:
            ec2 = session.client("ec2", region_name=region)

            nacl_paginator = ec2.get_paginator("describe_network_acls")
            for page in nacl_paginator.paginate():
                for nacl in page.get("NetworkAcls", []):
                    nacl_id = nacl["NetworkAclId"]
                    owner_id = nacl.get("OwnerId", account_id)

                    # Get NACL name from tags
                    nacl_name = nacl_id
                    tags = {}
                    for tag in nacl.get("Tags", []):
                        tags[tag["Key"]] = tag["Value"]
                        if tag["Key"] == "Name":
                            nacl_name = tag["Value"]

                    # Separate ingress and egress rules
                    ingress_rules = []
                    egress_rules = []
                    for entry in nacl.get("Entries", []):
                        rule = {
                            "rule_number": entry.get("RuleNumber"),
                            "protocol": entry.get("Protocol"),
                            "rule_action": entry.get("RuleAction"),
                            "cidr_block": entry.get("CidrBlock"),
                            "ipv6_cidr_block": entry.get("Ipv6CidrBlock"),
                            "port_range": entry.get("PortRange"),
                            "icmp_type_code": entry.get("IcmpTypeCode"),
                        }
                        if entry.get("Egress"):
                            egress_rules.append(rule)
                        else:
                            ingress_rules.append(rule)

                    # Get associated subnets
                    associated_subnets = [
                        assoc.get("SubnetId") for assoc in nacl.get("Associations", [])
                    ]

                    attributes = {
                        "network_acl_id": nacl_id,
                        "vpc_id": nacl.get("VpcId"),
                        "is_default": nacl.get("IsDefault", False),
                        "ingress_rules": ingress_rules,
                        "egress_rules": egress_rules,
                        "associations": nacl.get("Associations", []),
                        "associated_subnets": associated_subnets,
                        "is_used": len(associated_subnets) > 0,
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:network-acl/{nacl_id}",
                        resource_name=nacl_name,
                        resource_type="AWS::EC2::NetworkAcl",
                        region=region,
                        account_id=owner_id,
                        raw_data=nacl,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_flow_logs(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all VPC flow logs."""
        resources = []

        try:
            ec2 = session.client("ec2", region_name=region)

            fl_paginator = ec2.get_paginator("describe_flow_logs")
            for page in fl_paginator.paginate():
                for fl in page.get("FlowLogs", []):
                    fl_id = fl["FlowLogId"]

                    tags = {}
                    for tag in fl.get("Tags", []):
                        tags[tag["Key"]] = tag["Value"]

                    fl_name = tags.get("Name", fl_id)

                    attributes = {
                        "flow_log_id": fl_id,
                        "resource_id": fl.get("ResourceId"),
                        "traffic_type": fl.get("TrafficType"),
                        "log_destination_type": fl.get("LogDestinationType"),
                        "log_destination": fl.get("LogDestination"),
                        "log_group_name": fl.get("LogGroupName"),
                        "flow_log_status": fl.get("FlowLogStatus"),
                        "deliver_logs_status": fl.get("DeliverLogsStatus"),
                        "creation_time": str(fl.get("CreationTime")) if fl.get("CreationTime") else None,
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=f"arn:aws:ec2:{region}:{account_id}:flow-log/{fl_id}",
                        resource_name=fl_name,
                        resource_type="AWS::EC2::FlowLog",
                        region=region,
                        account_id=account_id,
                        raw_data=fl,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources
