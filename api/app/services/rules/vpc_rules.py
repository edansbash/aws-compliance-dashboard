"""VPC compliance rules for subnets, NACLs, and security groups."""
import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from app.services.rules.base import ComplianceRule, RuleResult, Severity

logger = logging.getLogger(__name__)


class VPCSubnetFlowLogEnabledRule(ComplianceRule):
    """Ensures VPC subnets have flow logs enabled."""

    rule_id = "VPC_SUBNET_FLOW_LOG_ENABLED"
    name = "VPC Subnet Flow Log Enabled"
    description = "Ensures VPC subnets have flow logs enabled for network traffic monitoring"
    resource_type = "AWS::EC2::Subnet"
    severity = Severity.MEDIUM
    has_remediation = True
    remediation_tested = True

    # S3 bucket for flow logs destination
    FLOW_LOG_BUCKET = "compsci-central-vpc-flow-logs"

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate subnets for flow log coverage."""
        results = []

        try:
            ec2 = session.client("ec2", region_name=region)

            # Get all subnets (with pagination)
            subnets = []
            subnets_paginator = ec2.get_paginator("describe_subnets")
            for page in subnets_paginator.paginate():
                subnets.extend(page.get("Subnets", []))

            # Get all flow logs (with pagination)
            flow_logs = []
            flow_logs_paginator = ec2.get_paginator("describe_flow_logs")
            for page in flow_logs_paginator.paginate():
                flow_logs.extend(page.get("FlowLogs", []))

            # Build a set of resource IDs that have flow logs
            # Flow logs can be attached to VPC, Subnet, or ENI
            resources_with_flow_logs = set()
            vpc_flow_logs = set()

            for fl in flow_logs:
                if fl.get("FlowLogStatus") == "ACTIVE":
                    resource_id = fl.get("ResourceId", "")
                    resources_with_flow_logs.add(resource_id)
                    # Detect VPC flow logs by ID prefix (vpc-*)
                    if resource_id.startswith("vpc-"):
                        vpc_flow_logs.add(resource_id)

            for subnet in subnets:
                subnet_id = subnet["SubnetId"]
                vpc_id = subnet["VpcId"]
                subnet_name = ""
                for tag in subnet.get("Tags", []):
                    if tag["Key"] == "Name":
                        subnet_name = tag["Value"]
                        break

                # Check if subnet has flow log directly OR its VPC has flow log
                has_flow_log = subnet_id in resources_with_flow_logs or vpc_id in vpc_flow_logs

                results.append(RuleResult(
                    resource_id=subnet_id,
                    resource_name=subnet_name or subnet_id,
                    status="PASS" if has_flow_log else "FAIL",
                    details={
                        "subnet_id": subnet_id,
                        "vpc_id": vpc_id,
                        "availability_zone": subnet.get("AvailabilityZone"),
                        "has_direct_flow_log": subnet_id in resources_with_flow_logs,
                        "vpc_has_flow_log": vpc_id in vpc_flow_logs,
                        "message": "Subnet has flow log coverage" if has_flow_log else "Subnet does not have flow logs enabled (neither directly nor via VPC)"
                    }
                ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return f"Create VPC Flow Log to S3 bucket ({cls.FLOW_LOG_BUCKET}) with 10-minute aggregation"

    async def remediate(self, session, resource_id: str, region: str, finding_details: Dict[str, Any] = None) -> bool:
        """
        Create a VPC flow log for the subnet's VPC, sending logs to S3.
        We create at VPC level so all subnets in the VPC are covered.
        """
        logger.info(f"[FlowLog Remediation] Starting for resource {resource_id} in {region}")
        logger.info(f"[FlowLog Remediation] Finding details: {finding_details}")

        ec2 = session.client("ec2", region_name=region)

        # Get the VPC ID from the finding details
        vpc_id = finding_details.get("vpc_id") if finding_details else None
        logger.info(f"[FlowLog Remediation] VPC ID from details: {vpc_id}")

        if not vpc_id:
            # If no VPC ID in details, look it up from the subnet
            logger.info(f"[FlowLog Remediation] Looking up VPC ID from subnet {resource_id}")
            subnet_response = ec2.describe_subnets(SubnetIds=[resource_id])
            subnets = subnet_response.get("Subnets", [])
            if not subnets:
                raise Exception(f"Subnet {resource_id} not found")
            vpc_id = subnets[0]["VpcId"]
            logger.info(f"[FlowLog Remediation] Found VPC ID: {vpc_id}")

        # Check if VPC already has a flow log (avoid duplicates)
        logger.info(f"[FlowLog Remediation] Checking for existing flow logs on VPC {vpc_id}")
        flow_logs_response = ec2.describe_flow_logs(
            Filters=[
                {"Name": "resource-id", "Values": [vpc_id]},
                {"Name": "log-destination-type", "Values": ["s3"]}
            ]
        )
        existing_flow_logs = flow_logs_response.get("FlowLogs", [])
        logger.info(f"[FlowLog Remediation] Found {len(existing_flow_logs)} existing S3 flow logs: {existing_flow_logs}")

        active_flow_logs = [fl for fl in existing_flow_logs if fl.get("FlowLogStatus") == "ACTIVE"]
        logger.info(f"[FlowLog Remediation] Active flow logs: {len(active_flow_logs)}")

        if active_flow_logs:
            # VPC already has an active S3 flow log
            logger.info(f"[FlowLog Remediation] Skipping - VPC {vpc_id} already has active S3 flow log(s)")
            return True

        # Create flow log to S3
        s3_bucket_arn = f"arn:aws:s3:::{self.FLOW_LOG_BUCKET}"
        logger.info(f"[FlowLog Remediation] Creating flow log for VPC {vpc_id} -> {s3_bucket_arn}")

        response = ec2.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogDestinationType="s3",
            LogDestination=s3_bucket_arn,
            MaxAggregationInterval=600,  # 10 minutes
            TagSpecifications=[
                {
                    "ResourceType": "vpc-flow-log",
                    "Tags": [
                        {"Key": "Name", "Value": f"flow-log-{vpc_id}"},
                        {"Key": "CreatedBy", "Value": "compliance-dashboard-remediation"},
                    ]
                }
            ]
        )

        logger.info(f"[FlowLog Remediation] create_flow_logs response: {response}")

        # Check for errors in the response
        unsuccessful = response.get("Unsuccessful", [])
        if unsuccessful:
            error_msg = unsuccessful[0].get("Error", {}).get("Message", "Unknown error")
            logger.error(f"[FlowLog Remediation] Failed to create flow log: {error_msg}")
            raise Exception(f"Failed to create flow log: {error_msg}")

        flow_log_ids = response.get("FlowLogIds", [])
        logger.info(f"[FlowLog Remediation] Successfully created flow log(s): {flow_log_ids}")

        return True

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "vpc_has_flow_log": True,
            "flow_log_destination": f"s3://{cls.FLOW_LOG_BUCKET}",
            "message": "VPC has flow log enabled to S3"
        }


class NetworkACLAllowsAllEgressRule(ComplianceRule):
    """Ensures Network ACLs do not allow all egress traffic as the first rule."""

    rule_id = "NACL_ALLOWS_ALL_EGRESS"
    name = "Network ACL Allows All Egress"
    description = "Ensures Network ACLs do not have an allow-all egress rule as the first/lowest priority rule (0.0.0.0/0 on all ports)"
    resource_type = "AWS::EC2::NetworkAcl"
    severity = Severity.MEDIUM
    has_remediation = True
    remediation_tested = True

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate NACLs for overly permissive egress rules."""
        results = []

        try:
            ec2 = session.client("ec2", region_name=region)

            # Get all NACLs
            nacls_response = ec2.describe_network_acls()
            nacls = nacls_response.get("NetworkAcls", [])

            for nacl in nacls:
                nacl_id = nacl["NetworkAclId"]
                vpc_id = nacl["VpcId"]
                is_default = nacl.get("IsDefault", False)

                nacl_name = ""
                for tag in nacl.get("Tags", []):
                    if tag["Key"] == "Name":
                        nacl_name = tag["Value"]
                        break

                # Get egress rules sorted by rule number (lower = higher priority)
                # Exclude rule 32767 which is the default deny rule
                egress_rules = [
                    entry for entry in nacl.get("Entries", [])
                    if entry.get("Egress", False) and entry.get("RuleNumber", 32767) != 32767
                ]
                egress_rules.sort(key=lambda x: x.get("RuleNumber", 32767))

                # Check if the first (lowest numbered) rule is an allow-all rule
                has_violation = False
                violating_rule = None

                if egress_rules:
                    first_rule = egress_rules[0]
                    rule_number = first_rule.get("RuleNumber")
                    rule_action = first_rule.get("RuleAction")
                    cidr = first_rule.get("CidrBlock", "")
                    ipv6_cidr = first_rule.get("Ipv6CidrBlock", "")
                    protocol = first_rule.get("Protocol", "")

                    is_allow = rule_action == "allow"
                    is_all_traffic = (cidr == "0.0.0.0/0" or ipv6_cidr == "::/0")
                    is_all_protocols = protocol == "-1"

                    if is_allow and is_all_traffic and is_all_protocols:
                        has_violation = True
                        violating_rule = {
                            "rule_number": rule_number,
                            "cidr": cidr or ipv6_cidr,
                            "protocol": "all",
                            "ports": "all"
                        }

                # Get associated subnets
                associated_subnets = [
                    assoc["SubnetId"]
                    for assoc in nacl.get("Associations", [])
                ]

                results.append(RuleResult(
                    resource_id=nacl_id,
                    resource_name=nacl_name or nacl_id,
                    status="FAIL" if has_violation else "PASS",
                    details={
                        "nacl_id": nacl_id,
                        "vpc_id": vpc_id,
                        "is_default": is_default,
                        "associated_subnets": associated_subnets,
                        "violating_rule": violating_rule,
                        "message": f"NACL has allow-all egress as first rule (rule {violating_rule['rule_number']})" if has_violation else "NACL does not have allow-all egress as first rule"
                    }
                ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Add a deny rule with priority 50 to block traffic on port 9050, which takes precedence over the allow-all rule"

    async def remediate(self, session, resource_id: str, region: str, finding_details: Dict[str, Any] = None) -> bool:
        """
        Add a deny rule on port 9050 with priority 50 (egress).
        This rule will be evaluated before the default allow-all rule at priority 100.
        """
        ec2 = session.client("ec2", region_name=region)

        # Add deny rule for TCP port 9050 with rule number 50 (egress)
        ec2.create_network_acl_entry(
            NetworkAclId=resource_id,
            RuleNumber=50,
            Protocol="6",  # TCP
            RuleAction="deny",
            Egress=True,
            CidrBlock="0.0.0.0/0",
            PortRange={
                "From": 9050,
                "To": 9050
            }
        )

        return True

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "has_deny_rule_50": True,
            "message": "NACL has deny rule at priority 50 blocking port 9050 egress"
        }


class NetworkACLAllowsAllIngressRule(ComplianceRule):
    """Ensures Network ACLs do not allow all ingress traffic as the first rule."""

    rule_id = "NACL_ALLOWS_ALL_INGRESS"
    name = "Network ACL Allows All Ingress"
    description = "Ensures Network ACLs do not have an allow-all ingress rule as the first/lowest priority rule (0.0.0.0/0 on all ports)"
    resource_type = "AWS::EC2::NetworkAcl"
    severity = Severity.HIGH
    has_remediation = True
    remediation_tested = True

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate NACLs for overly permissive ingress rules."""
        results = []

        try:
            ec2 = session.client("ec2", region_name=region)

            # Get all NACLs
            nacls_response = ec2.describe_network_acls()
            nacls = nacls_response.get("NetworkAcls", [])

            for nacl in nacls:
                nacl_id = nacl["NetworkAclId"]
                vpc_id = nacl["VpcId"]
                is_default = nacl.get("IsDefault", False)

                nacl_name = ""
                for tag in nacl.get("Tags", []):
                    if tag["Key"] == "Name":
                        nacl_name = tag["Value"]
                        break

                # Get ingress rules sorted by rule number (lower = higher priority)
                # Exclude rule 32767 which is the default deny rule
                ingress_rules = [
                    entry for entry in nacl.get("Entries", [])
                    if not entry.get("Egress", False) and entry.get("RuleNumber", 32767) != 32767
                ]
                ingress_rules.sort(key=lambda x: x.get("RuleNumber", 32767))

                # Check if the first (lowest numbered) rule is an allow-all rule
                has_violation = False
                violating_rule = None

                if ingress_rules:
                    first_rule = ingress_rules[0]
                    rule_number = first_rule.get("RuleNumber")
                    rule_action = first_rule.get("RuleAction")
                    cidr = first_rule.get("CidrBlock", "")
                    ipv6_cidr = first_rule.get("Ipv6CidrBlock", "")
                    protocol = first_rule.get("Protocol", "")

                    is_allow = rule_action == "allow"
                    is_all_traffic = (cidr == "0.0.0.0/0" or ipv6_cidr == "::/0")
                    is_all_protocols = protocol == "-1"

                    if is_allow and is_all_traffic and is_all_protocols:
                        has_violation = True
                        violating_rule = {
                            "rule_number": rule_number,
                            "cidr": cidr or ipv6_cidr,
                            "protocol": "all",
                            "ports": "all"
                        }

                # Get associated subnets
                associated_subnets = [
                    assoc["SubnetId"]
                    for assoc in nacl.get("Associations", [])
                ]

                results.append(RuleResult(
                    resource_id=nacl_id,
                    resource_name=nacl_name or nacl_id,
                    status="FAIL" if has_violation else "PASS",
                    details={
                        "nacl_id": nacl_id,
                        "vpc_id": vpc_id,
                        "is_default": is_default,
                        "associated_subnets": associated_subnets,
                        "violating_rule": violating_rule,
                        "message": f"NACL has allow-all ingress as first rule (rule {violating_rule['rule_number']})" if has_violation else "NACL does not have allow-all ingress as first rule"
                    }
                ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Add a deny rule with priority 50 to block traffic on port 9050, which takes precedence over the allow-all rule"

    async def remediate(self, session, resource_id: str, region: str, finding_details: Dict[str, Any] = None) -> bool:
        """
        Add a deny rule on port 9050 with priority 50 (ingress).
        This rule will be evaluated before the default allow-all rule at priority 100.
        """
        ec2 = session.client("ec2", region_name=region)

        # Add deny rule for TCP port 9050 with rule number 50 (ingress)
        ec2.create_network_acl_entry(
            NetworkAclId=resource_id,
            RuleNumber=50,
            Protocol="6",  # TCP
            RuleAction="deny",
            Egress=False,
            CidrBlock="0.0.0.0/0",
            PortRange={
                "From": 9050,
                "To": 9050
            }
        )

        return True

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "has_deny_rule_50": True,
            "message": "NACL has deny rule at priority 50 blocking port 9050 ingress"
        }


class VPCNetworkACLNotUsedRule(ComplianceRule):
    """Ensures Network ACLs are associated with at least one subnet."""

    rule_id = "VPC_NACL_NOT_USED"
    name = "VPC Network ACL Not Used"
    description = "Identifies Network ACLs that are not associated with any subnet"
    resource_type = "AWS::EC2::NetworkAcl"
    severity = Severity.LOW
    has_remediation = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate NACLs for usage."""
        results = []

        try:
            ec2 = session.client("ec2", region_name=region)

            # Get all NACLs
            nacls_response = ec2.describe_network_acls()
            nacls = nacls_response.get("NetworkAcls", [])

            for nacl in nacls:
                nacl_id = nacl["NetworkAclId"]
                vpc_id = nacl["VpcId"]
                is_default = nacl.get("IsDefault", False)

                nacl_name = ""
                for tag in nacl.get("Tags", []):
                    if tag["Key"] == "Name":
                        nacl_name = tag["Value"]
                        break

                # Get associated subnets
                associations = nacl.get("Associations", [])
                associated_subnets = [assoc["SubnetId"] for assoc in associations]

                # Default NACLs can't be deleted and are always valid
                # Non-default NACLs without associations are unused
                is_unused = not is_default and len(associated_subnets) == 0

                results.append(RuleResult(
                    resource_id=nacl_id,
                    resource_name=nacl_name or nacl_id,
                    status="FAIL" if is_unused else "PASS",
                    details={
                        "nacl_id": nacl_id,
                        "vpc_id": vpc_id,
                        "is_default": is_default,
                        "associated_subnet_count": len(associated_subnets),
                        "associated_subnets": associated_subnets,
                        "message": "Network ACL is not associated with any subnet" if is_unused else f"Network ACL is associated with {len(associated_subnets)} subnet(s)"
                    }
                ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Delete unused Network ACLs or associate them with subnets"


class VPCDefaultSecurityGroupAllowsInboundRule(ComplianceRule):
    """Ensures default security groups do not allow inbound traffic."""

    rule_id = "VPC_DEFAULT_SG_ALLOWS_INBOUND"
    name = "VPC Default Security Group Allows Inbound Traffic"
    description = "Ensures the default security group in each VPC does not have rules allowing inbound traffic"
    resource_type = "AWS::EC2::SecurityGroup"
    severity = Severity.HIGH
    has_remediation = True
    remediation_tested = True

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Evaluate default security groups for inbound rules."""
        results = []

        try:
            ec2 = session.client("ec2", region_name=region)

            # Get all security groups with name 'default'
            sgs_response = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": ["default"]}]
            )
            security_groups = sgs_response.get("SecurityGroups", [])

            for sg in security_groups:
                sg_id = sg["GroupId"]
                vpc_id = sg.get("VpcId", "")
                sg_name = sg.get("GroupName", "default")

                # Check inbound rules
                inbound_rules = sg.get("IpPermissions", [])
                violating_rules = []

                for rule in inbound_rules:
                    # Any inbound rule in default SG is a violation
                    ip_ranges = rule.get("IpRanges", [])
                    ipv6_ranges = rule.get("Ipv6Ranges", [])
                    user_id_group_pairs = rule.get("UserIdGroupPairs", [])

                    if ip_ranges or ipv6_ranges or user_id_group_pairs:
                        from_port = rule.get("FromPort", "all")
                        to_port = rule.get("ToPort", "all")
                        protocol = rule.get("IpProtocol", "-1")

                        sources = []
                        for ip_range in ip_ranges:
                            sources.append(ip_range.get("CidrIp", ""))
                        for ipv6_range in ipv6_ranges:
                            sources.append(ipv6_range.get("CidrIpv6", ""))
                        for group_pair in user_id_group_pairs:
                            sources.append(f"sg:{group_pair.get('GroupId', '')}")

                        violating_rules.append({
                            "protocol": protocol if protocol != "-1" else "all",
                            "from_port": from_port,
                            "to_port": to_port,
                            "sources": sources
                        })

                has_violation = len(violating_rules) > 0

                results.append(RuleResult(
                    resource_id=sg_id,
                    resource_name=f"default ({vpc_id})",
                    status="FAIL" if has_violation else "PASS",
                    details={
                        "security_group_id": sg_id,
                        "vpc_id": vpc_id,
                        "inbound_rule_count": len(violating_rules),
                        "violating_rules": violating_rules,
                        "message": f"Default security group has {len(violating_rules)} inbound rule(s) allowing traffic" if has_violation else "Default security group has no inbound rules"
                    }
                ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove all inbound rules from the default security group and use custom security groups instead"

    async def remediate(self, session, resource_id: str, region: str, finding_details: Dict[str, Any] = None) -> bool:
        """
        Remove all inbound rules from the default security group.
        """
        ec2 = session.client("ec2", region_name=region)

        # Get current inbound rules
        sg_response = ec2.describe_security_groups(GroupIds=[resource_id])
        security_groups = sg_response.get("SecurityGroups", [])

        if not security_groups:
            return True  # Security group not found, nothing to do

        sg = security_groups[0]
        inbound_rules = sg.get("IpPermissions", [])

        if not inbound_rules:
            return True  # No inbound rules to remove

        # Revoke all inbound rules
        ec2.revoke_security_group_ingress(
            GroupId=resource_id,
            IpPermissions=inbound_rules
        )

        return True

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "inbound_rule_count": 0,
            "violating_rules": [],
            "message": "Default security group has no inbound rules"
        }
