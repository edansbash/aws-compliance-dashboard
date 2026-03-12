"""Security Group compliance rules using pre-fetched resource data."""

from typing import List, Dict, Any, TYPE_CHECKING
from botocore.exceptions import ClientError

from app.services.rules.base import ComplianceRule, RuleResult, Severity

if TYPE_CHECKING:
    from app.services.fetchers.base import FetchedResource


# ============================================================================
# Helper functions for security group rule evaluation
# ============================================================================


def check_port_open_to_internet(
    inbound_rules: List[Dict],
    target_port: int,
    target_protocol: str = "tcp",
) -> tuple[bool, List[Dict]]:
    """
    Check if a specific port is open to the internet (0.0.0.0/0 or ::/0).

    Returns:
        Tuple of (is_open, list of violating rules)
    """
    is_open = False
    violating_rules = []

    for rule in inbound_rules:
        protocol = rule.get("IpProtocol", "")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        # Check if this rule applies to our target port
        port_matches = False

        # -1 protocol means all traffic
        if protocol == "-1":
            port_matches = True
        elif protocol.lower() == target_protocol:
            if from_port is not None and to_port is not None:
                if from_port <= target_port <= to_port:
                    port_matches = True

        if not port_matches:
            continue

        # Check for 0.0.0.0/0 or ::/0
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                is_open = True
                violating_rules.append({
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                    "description": ip_range.get("Description", "")
                })

        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6", "")
            if cidr == "::/0":
                is_open = True
                violating_rules.append({
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                    "description": ip_range.get("Description", "")
                })

    return is_open, violating_rules


def check_all_ports_open(
    inbound_rules: List[Dict],
    protocol_filter: str = None,
) -> tuple[bool, List[Dict]]:
    """
    Check if all ports are open to the internet.

    Args:
        inbound_rules: List of inbound rules
        protocol_filter: Optional filter for "tcp", "udp", or None for all

    Returns:
        Tuple of (is_open, list of violating rules)
    """
    is_open = False
    violating_rules = []

    for rule in inbound_rules:
        protocol = rule.get("IpProtocol", "")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        # Check for all traffic/ports
        all_ports = False
        if protocol == "-1":
            all_ports = True
        elif protocol_filter is None:
            if protocol.lower() in ["tcp", "udp"]:
                if from_port == 0 and to_port == 65535:
                    all_ports = True
        elif protocol.lower() == protocol_filter:
            if from_port == 0 and to_port == 65535:
                all_ports = True

        if not all_ports:
            continue

        # Check for 0.0.0.0/0 or ::/0
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                is_open = True
                violating_rules.append({
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                })

        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6", "")
            if cidr == "::/0":
                is_open = True
                violating_rules.append({
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                })

    return is_open, violating_rules


# ============================================================================
# Base class for port-specific rules
# ============================================================================


class SecurityGroupOpenPortRule(ComplianceRule):
    """
    Base class for security group rules that check for open ports.
    Subclasses define specific ports and protocols to check.
    """

    resource_type = "AWS::EC2::SecurityGroup"
    has_remediation = False
    supports_prefetch = True

    # To be overridden by subclasses
    target_port: int = 0
    target_protocol: str = "tcp"
    port_name: str = ""

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate security groups for open port access using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            inbound_rules = attrs.get("inbound_rules", [])

            is_open, violating_rules = check_port_open_to_internet(
                inbound_rules, self.target_port, self.target_protocol
            )

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "target_port": self.target_port,
                "port_name": self.port_name,
                "is_open_to_all": is_open,
                "violating_rules": violating_rules,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if is_open else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method - kept for backward compatibility."""
        results = []

        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    vpc_id = sg.get("VpcId", "EC2-Classic")
                    owner_id = sg.get("OwnerId", "unknown")

                    is_open, violating_rules = check_port_open_to_internet(
                        sg.get("IpPermissions", []),
                        self.target_port,
                        self.target_protocol
                    )

                    results.append(RuleResult(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:security-group/{sg_id}",
                        resource_name=sg_name,
                        status="FAIL" if is_open else "PASS",
                        details={
                            "security_group_id": sg_id,
                            "security_group_name": sg_name,
                            "vpc_id": vpc_id,
                            "target_port": self.target_port,
                            "port_name": self.port_name,
                            "is_open_to_all": is_open,
                            "violating_rules": violating_rules,
                        }
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return f"Remove inbound rules allowing {cls.port_name} (port {cls.target_port}) access from 0.0.0.0/0"


# ============================================================================
# Port-specific security group rules
# ============================================================================


class SecurityGroupSSHOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow SSH (port 22) from anywhere."""
    rule_id = "SG_SSH_OPEN"
    name = "Security Group SSH Open to All"
    description = "Ensures EC2 security groups do not allow SSH (port 22) access from 0.0.0.0/0"
    severity = Severity.CRITICAL
    target_port = 22
    target_protocol = "tcp"
    port_name = "SSH"


class SecurityGroupRDPOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow RDP (port 3389) from anywhere."""
    rule_id = "SG_RDP_OPEN"
    name = "Security Group RDP Open to All"
    description = "Ensures EC2 security groups do not allow RDP (port 3389) access from 0.0.0.0/0"
    severity = Severity.CRITICAL
    target_port = 3389
    target_protocol = "tcp"
    port_name = "RDP"


class SecurityGroupFTPOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow FTP (port 21) from anywhere."""
    rule_id = "SG_FTP_OPEN"
    name = "Security Group FTP (Cleartext) Open to All"
    description = "Ensures EC2 security groups do not allow FTP (port 21) access from 0.0.0.0/0 - FTP transmits credentials in cleartext"
    severity = Severity.HIGH
    target_port = 21
    target_protocol = "tcp"
    port_name = "FTP"


class SecurityGroupTelnetOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow Telnet (port 23) from anywhere."""
    rule_id = "SG_TELNET_OPEN"
    name = "Security Group Telnet (Cleartext) Open to All"
    description = "Ensures EC2 security groups do not allow Telnet (port 23) access from 0.0.0.0/0 - Telnet transmits in cleartext"
    severity = Severity.HIGH
    target_port = 23
    target_protocol = "tcp"
    port_name = "Telnet"


class SecurityGroupPostgresOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow PostgreSQL (port 5432) from anywhere."""
    rule_id = "SG_POSTGRES_OPEN"
    name = "Security Group PostgreSQL Open to All"
    description = "Ensures EC2 security groups do not allow PostgreSQL (port 5432) access from 0.0.0.0/0"
    severity = Severity.HIGH
    target_port = 5432
    target_protocol = "tcp"
    port_name = "PostgreSQL"


class SecurityGroupSMTPOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow SMTP (port 25) from anywhere."""
    rule_id = "SG_SMTP_OPEN"
    name = "Security Group SMTP Open to All"
    description = "Ensures EC2 security groups do not allow SMTP (port 25) access from 0.0.0.0/0"
    severity = Severity.HIGH
    target_port = 25
    target_protocol = "tcp"
    port_name = "SMTP"


class SecurityGroupNFSOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow NFS (port 2049) from anywhere."""
    rule_id = "SG_NFS_OPEN"
    name = "Security Group NFS Open to All"
    description = "Ensures EC2 security groups do not allow NFS (port 2049) access from 0.0.0.0/0"
    severity = Severity.HIGH
    target_port = 2049
    target_protocol = "tcp"
    port_name = "NFS"


class SecurityGroupOracleOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow Oracle (port 1521) from anywhere."""
    rule_id = "SG_ORACLE_OPEN"
    name = "Security Group Oracle Open to All"
    description = "Ensures EC2 security groups do not allow Oracle (port 1521) access from 0.0.0.0/0"
    severity = Severity.HIGH
    target_port = 1521
    target_protocol = "tcp"
    port_name = "Oracle"


class SecurityGroupMsSQLOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow MsSQL (port 1433) from anywhere."""
    rule_id = "SG_MSSQL_OPEN"
    name = "Security Group MsSQL Open to All"
    description = "Ensures EC2 security groups do not allow MsSQL (port 1433) access from 0.0.0.0/0"
    severity = Severity.HIGH
    target_port = 1433
    target_protocol = "tcp"
    port_name = "MsSQL"


class SecurityGroupMongoDBOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow MongoDB (port 27017) from anywhere."""
    rule_id = "SG_MONGODB_OPEN"
    name = "Security Group MongoDB Open to All"
    description = "Ensures EC2 security groups do not allow MongoDB (port 27017) access from 0.0.0.0/0"
    severity = Severity.HIGH
    target_port = 27017
    target_protocol = "tcp"
    port_name = "MongoDB"


class SecurityGroupDNSOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow DNS (port 53) from anywhere."""
    rule_id = "SG_DNS_OPEN"
    name = "Security Group DNS Open to All"
    description = "Ensures EC2 security groups do not allow DNS (port 53) access from 0.0.0.0/0"
    severity = Severity.MEDIUM
    target_port = 53
    target_protocol = "tcp"
    port_name = "DNS"


class SecurityGroupMySQLOpenRule(SecurityGroupOpenPortRule):
    """Ensures security groups do not allow MySQL (port 3306) from anywhere."""
    rule_id = "SG_MYSQL_OPEN"
    name = "Security Group MySQL Open to All"
    description = "Ensures EC2 security groups do not allow MySQL (port 3306) access from 0.0.0.0/0"
    severity = Severity.HIGH
    target_port = 3306
    target_protocol = "tcp"
    port_name = "MySQL"


# ============================================================================
# All traffic/ports rules
# ============================================================================


class SecurityGroupAllTCPOpenRule(ComplianceRule):
    """Ensures security groups do not allow all TCP ports from anywhere."""
    rule_id = "SG_ALL_TCP_OPEN"
    name = "Security Group All TCP Ports Open to All"
    description = "Ensures EC2 security groups do not allow all TCP ports (0-65535) access from 0.0.0.0/0"
    resource_type = "AWS::EC2::SecurityGroup"
    severity = Severity.CRITICAL
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate security groups using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            inbound_rules = attrs.get("inbound_rules", [])

            is_open, violating_rules = check_all_ports_open(inbound_rules, "tcp")

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "is_open_to_all": is_open,
                "violating_rules": violating_rules,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if is_open else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    vpc_id = sg.get("VpcId", "EC2-Classic")
                    owner_id = sg.get("OwnerId", "unknown")

                    is_open, violating_rules = check_all_ports_open(
                        sg.get("IpPermissions", []), "tcp"
                    )

                    results.append(RuleResult(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:security-group/{sg_id}",
                        resource_name=sg_name,
                        status="FAIL" if is_open else "PASS",
                        details={
                            "security_group_id": sg_id,
                            "security_group_name": sg_name,
                            "vpc_id": vpc_id,
                            "is_open_to_all": is_open,
                            "violating_rules": violating_rules,
                        }
                    ))
        except ClientError:
            pass
        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove inbound rules allowing all TCP ports from 0.0.0.0/0"


class SecurityGroupAllUDPOpenRule(ComplianceRule):
    """Ensures security groups do not allow all UDP ports from anywhere."""
    rule_id = "SG_ALL_UDP_OPEN"
    name = "Security Group All UDP Ports Open to All"
    description = "Ensures EC2 security groups do not allow all UDP ports access from 0.0.0.0/0"
    resource_type = "AWS::EC2::SecurityGroup"
    severity = Severity.CRITICAL
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate security groups using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            inbound_rules = attrs.get("inbound_rules", [])

            is_open, violating_rules = check_all_ports_open(inbound_rules, "udp")

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "is_open_to_all": is_open,
                "violating_rules": violating_rules,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if is_open else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    vpc_id = sg.get("VpcId", "EC2-Classic")
                    owner_id = sg.get("OwnerId", "unknown")

                    is_open, violating_rules = check_all_ports_open(
                        sg.get("IpPermissions", []), "udp"
                    )

                    results.append(RuleResult(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:security-group/{sg_id}",
                        resource_name=sg_name,
                        status="FAIL" if is_open else "PASS",
                        details={
                            "security_group_id": sg_id,
                            "security_group_name": sg_name,
                            "vpc_id": vpc_id,
                            "is_open_to_all": is_open,
                            "violating_rules": violating_rules,
                        }
                    ))
        except ClientError:
            pass
        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove inbound rules allowing all UDP ports from 0.0.0.0/0"


class SecurityGroupAllPortsOpenRule(ComplianceRule):
    """Ensures security groups do not allow all traffic from anywhere."""
    rule_id = "SG_ALL_PORTS_OPEN"
    name = "Security Group All Ports Open to All"
    description = "Ensures EC2 security groups do not allow all traffic (all ports and protocols) from 0.0.0.0/0"
    resource_type = "AWS::EC2::SecurityGroup"
    severity = Severity.CRITICAL
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate security groups using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            inbound_rules = attrs.get("inbound_rules", [])

            is_open = False
            violating_rules = []

            for rule in inbound_rules:
                protocol = rule.get("IpProtocol", "")
                if protocol != "-1":
                    continue

                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        is_open = True
                        violating_rules.append({"protocol": "all", "cidr": "0.0.0.0/0"})

                for ip_range in rule.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        is_open = True
                        violating_rules.append({"protocol": "all", "cidr": "::/0"})

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "is_open_to_all": is_open,
                "violating_rules": violating_rules,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if is_open else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    vpc_id = sg.get("VpcId", "EC2-Classic")
                    owner_id = sg.get("OwnerId", "unknown")

                    is_open = False
                    violating_rules = []

                    for rule in sg.get("IpPermissions", []):
                        if rule.get("IpProtocol") != "-1":
                            continue

                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                is_open = True
                                violating_rules.append({"protocol": "all", "cidr": "0.0.0.0/0"})

                        for ip_range in rule.get("Ipv6Ranges", []):
                            if ip_range.get("CidrIpv6") == "::/0":
                                is_open = True
                                violating_rules.append({"protocol": "all", "cidr": "::/0"})

                    results.append(RuleResult(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:security-group/{sg_id}",
                        resource_name=sg_name,
                        status="FAIL" if is_open else "PASS",
                        details={
                            "security_group_id": sg_id,
                            "security_group_name": sg_name,
                            "vpc_id": vpc_id,
                            "is_open_to_all": is_open,
                            "violating_rules": violating_rules,
                        }
                    ))
        except ClientError:
            pass
        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove inbound rules allowing all traffic from 0.0.0.0/0"


class SecurityGroupICMPOpenRule(ComplianceRule):
    """Ensures security groups do not allow ICMP from anywhere."""
    rule_id = "SG_ICMP_OPEN"
    name = "Security Group ICMP Open to All"
    description = "Ensures EC2 security groups do not allow ICMP access from 0.0.0.0/0"
    resource_type = "AWS::EC2::SecurityGroup"
    severity = Severity.MEDIUM
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate security groups using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            inbound_rules = attrs.get("inbound_rules", [])

            is_open = False
            violating_rules = []

            for rule in inbound_rules:
                protocol = rule.get("IpProtocol", "")
                if protocol not in ["icmp", "icmpv6", "-1"]:
                    continue

                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        is_open = True
                        violating_rules.append({"protocol": protocol, "cidr": "0.0.0.0/0"})

                for ip_range in rule.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        is_open = True
                        violating_rules.append({"protocol": protocol, "cidr": "::/0"})

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "is_open_to_all": is_open,
                "violating_rules": violating_rules,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if is_open else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    vpc_id = sg.get("VpcId", "EC2-Classic")
                    owner_id = sg.get("OwnerId", "unknown")

                    is_open = False
                    violating_rules = []

                    for rule in sg.get("IpPermissions", []):
                        protocol = rule.get("IpProtocol", "")
                        if protocol not in ["icmp", "icmpv6", "-1"]:
                            continue

                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                is_open = True
                                violating_rules.append({"protocol": protocol, "cidr": "0.0.0.0/0"})

                        for ip_range in rule.get("Ipv6Ranges", []):
                            if ip_range.get("CidrIpv6") == "::/0":
                                is_open = True
                                violating_rules.append({"protocol": protocol, "cidr": "::/0"})

                    results.append(RuleResult(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:security-group/{sg_id}",
                        resource_name=sg_name,
                        status="FAIL" if is_open else "PASS",
                        details={
                            "security_group_id": sg_id,
                            "security_group_name": sg_name,
                            "vpc_id": vpc_id,
                            "is_open_to_all": is_open,
                            "violating_rules": violating_rules,
                        }
                    ))
        except ClientError:
            pass
        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove inbound rules allowing ICMP from 0.0.0.0/0"


# ============================================================================
# Port range and special rules
# ============================================================================


class SecurityGroupPortRangeRule(ComplianceRule):
    """Ensures security groups do not open port ranges to the internet."""
    rule_id = "SG_PORT_RANGE_OPEN"
    name = "Security Group Opens Port Range"
    description = "Ensures EC2 security groups do not open port ranges (multiple consecutive ports) to 0.0.0.0/0"
    resource_type = "AWS::EC2::SecurityGroup"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate security groups using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            inbound_rules = attrs.get("inbound_rules", [])

            has_port_range = False
            violating_rules = []

            for rule in inbound_rules:
                protocol = rule.get("IpProtocol", "")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                if protocol == "-1" or protocol.lower() not in ["tcp", "udp"]:
                    continue
                if from_port is None or to_port is None or from_port == to_port:
                    continue

                is_open = any(
                    ip.get("CidrIp") == "0.0.0.0/0" for ip in rule.get("IpRanges", [])
                ) or any(
                    ip.get("CidrIpv6") == "::/0" for ip in rule.get("Ipv6Ranges", [])
                )

                if is_open:
                    has_port_range = True
                    violating_rules.append({
                        "protocol": protocol,
                        "from_port": from_port,
                        "to_port": to_port,
                        "port_count": to_port - from_port + 1,
                    })

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "has_port_range": has_port_range,
                "violating_rules": violating_rules,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if has_port_range else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    vpc_id = sg.get("VpcId", "EC2-Classic")
                    owner_id = sg.get("OwnerId", "unknown")

                    has_port_range = False
                    violating_rules = []

                    for rule in sg.get("IpPermissions", []):
                        protocol = rule.get("IpProtocol", "")
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")

                        if protocol == "-1" or protocol.lower() not in ["tcp", "udp"]:
                            continue
                        if from_port is None or to_port is None or from_port == to_port:
                            continue

                        is_open = any(
                            ip.get("CidrIp") == "0.0.0.0/0" for ip in rule.get("IpRanges", [])
                        ) or any(
                            ip.get("CidrIpv6") == "::/0" for ip in rule.get("Ipv6Ranges", [])
                        )

                        if is_open:
                            has_port_range = True
                            violating_rules.append({
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "port_count": to_port - from_port + 1,
                            })

                    results.append(RuleResult(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:security-group/{sg_id}",
                        resource_name=sg_name,
                        status="FAIL" if has_port_range else "PASS",
                        details={
                            "security_group_id": sg_id,
                            "security_group_name": sg_name,
                            "vpc_id": vpc_id,
                            "has_port_range": has_port_range,
                            "violating_rules": violating_rules,
                        }
                    ))
        except ClientError:
            pass
        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Replace port range rules with specific single-port rules for only required ports"


class SecurityGroupAllPortsToSelfRule(ComplianceRule):
    """Ensures security groups do not allow all ports to themselves."""
    rule_id = "SG_ALL_PORTS_TO_SELF"
    name = "Security Group Opens All Ports to Self"
    description = "Ensures EC2 security groups do not allow all ports/protocols to themselves via self-referencing rules"
    resource_type = "AWS::EC2::SecurityGroup"
    severity = Severity.MEDIUM
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate security groups using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            sg_id = attrs.get("security_group_id")
            inbound_rules = attrs.get("inbound_rules", [])

            all_ports_to_self = False
            violating_rules = []

            for rule in inbound_rules:
                protocol = rule.get("IpProtocol", "")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                is_all_ports = (
                    protocol == "-1" or
                    (protocol.lower() == "tcp" and from_port == 0 and to_port == 65535) or
                    (protocol.lower() == "udp" and from_port == 0 and to_port == 65535)
                )

                if not is_all_ports:
                    continue

                for sg_pair in rule.get("UserIdGroupPairs", []):
                    if sg_pair.get("GroupId") == sg_id:
                        all_ports_to_self = True
                        violating_rules.append({
                            "protocol": protocol if protocol != "-1" else "all",
                            "from_port": from_port,
                            "to_port": to_port,
                            "referenced_sg": sg_id,
                        })

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "all_ports_to_self": all_ports_to_self,
                "violating_rules": violating_rules,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if all_ports_to_self else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    vpc_id = sg.get("VpcId", "EC2-Classic")
                    owner_id = sg.get("OwnerId", "unknown")

                    all_ports_to_self = False
                    violating_rules = []

                    for rule in sg.get("IpPermissions", []):
                        protocol = rule.get("IpProtocol", "")
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")

                        is_all_ports = (
                            protocol == "-1" or
                            (protocol.lower() == "tcp" and from_port == 0 and to_port == 65535) or
                            (protocol.lower() == "udp" and from_port == 0 and to_port == 65535)
                        )

                        if not is_all_ports:
                            continue

                        for sg_pair in rule.get("UserIdGroupPairs", []):
                            if sg_pair.get("GroupId") == sg_id:
                                all_ports_to_self = True
                                violating_rules.append({
                                    "protocol": protocol if protocol != "-1" else "all",
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "referenced_sg": sg_id,
                                })

                    results.append(RuleResult(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:security-group/{sg_id}",
                        resource_name=sg_name,
                        status="FAIL" if all_ports_to_self else "PASS",
                        details={
                            "security_group_id": sg_id,
                            "security_group_name": sg_name,
                            "vpc_id": vpc_id,
                            "all_ports_to_self": all_ports_to_self,
                            "violating_rules": violating_rules,
                        }
                    ))
        except ClientError:
            pass
        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Remove self-referencing all-ports rules from the security group."""
        sg_id = resource_id.split("/")[-1]
        ec2 = session.client("ec2", region_name=region)

        violating_rules = finding_details.get("violating_rules", []) if finding_details else []

        for rule in violating_rules:
            protocol = rule.get("protocol")
            from_port = rule.get("from_port")
            to_port = rule.get("to_port")

            # Build the permission to revoke
            ip_permission = {
                "UserIdGroupPairs": [{"GroupId": sg_id}],
            }

            if protocol == "all":
                ip_permission["IpProtocol"] = "-1"
            else:
                ip_permission["IpProtocol"] = protocol
                if from_port is not None:
                    ip_permission["FromPort"] = from_port
                if to_port is not None:
                    ip_permission["ToPort"] = to_port

            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[ip_permission]
            )

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Remove self-referencing rules that allow all ports/protocols"

    @classmethod
    def get_expected_state(cls, current_details: dict) -> dict:
        return {
            **current_details,
            "all_ports_to_self": False,
            "violating_rules": [],
        }


class SecurityGroupAWSIPRangeRule(ComplianceRule):
    """Ensures security groups do not whitelist broad AWS IP ranges."""
    rule_id = "SG_AWS_IP_RANGE"
    name = "Security Group Whitelists AWS IP Range"
    description = "Ensures EC2 security groups do not whitelist broad AWS public IP ranges"
    resource_type = "AWS::EC2::SecurityGroup"
    severity = Severity.MEDIUM
    has_remediation = False
    supports_prefetch = True

    AWS_IP_PREFIXES = [
        "3.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8", "18.0.0.0/8",
        "34.0.0.0/8", "35.0.0.0/8", "44.0.0.0/8", "46.0.0.0/8",
        "52.0.0.0/8", "54.0.0.0/8", "99.0.0.0/8", "100.0.0.0/8",
    ]

    def _cidr_matches(self, cidr: str, aws_prefix: str) -> bool:
        """Check if CIDR matches AWS prefix."""
        try:
            if "/" not in cidr:
                return False
            cidr_ip, cidr_mask = cidr.split("/")
            aws_ip, _ = aws_prefix.split("/")
            if int(cidr_mask) > 16:
                return False
            return cidr_ip.split(".")[0] == aws_ip.split(".")[0]
        except (ValueError, IndexError):
            return False

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate security groups using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            inbound_rules = attrs.get("inbound_rules", [])

            has_aws_range = False
            violating_rules = []

            for rule in inbound_rules:
                protocol = rule.get("IpProtocol", "")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    for aws_prefix in self.AWS_IP_PREFIXES:
                        if self._cidr_matches(cidr, aws_prefix):
                            has_aws_range = True
                            violating_rules.append({
                                "protocol": protocol if protocol != "-1" else "all",
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": cidr,
                                "aws_prefix_match": aws_prefix,
                            })
                            break

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "has_aws_ip_range": has_aws_range,
                "violating_rules": violating_rules,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if has_aws_range else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    vpc_id = sg.get("VpcId", "EC2-Classic")
                    owner_id = sg.get("OwnerId", "unknown")

                    has_aws_range = False
                    violating_rules = []

                    for rule in sg.get("IpPermissions", []):
                        protocol = rule.get("IpProtocol", "")
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")

                        for ip_range in rule.get("IpRanges", []):
                            cidr = ip_range.get("CidrIp", "")
                            for aws_prefix in self.AWS_IP_PREFIXES:
                                if self._cidr_matches(cidr, aws_prefix):
                                    has_aws_range = True
                                    violating_rules.append({
                                        "protocol": protocol if protocol != "-1" else "all",
                                        "from_port": from_port,
                                        "to_port": to_port,
                                        "cidr": cidr,
                                        "aws_prefix_match": aws_prefix,
                                    })
                                    break

                    results.append(RuleResult(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:security-group/{sg_id}",
                        resource_name=sg_name,
                        status="FAIL" if has_aws_range else "PASS",
                        details={
                            "security_group_id": sg_id,
                            "security_group_name": sg_name,
                            "vpc_id": vpc_id,
                            "has_aws_ip_range": has_aws_range,
                            "violating_rules": violating_rules,
                        }
                    ))
        except ClientError:
            pass
        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Replace broad AWS IP range rules with specific IP addresses or security group references"


# ============================================================================
# Usage-based rules (use pre-fetched attached_resources data)
# ============================================================================


class DefaultSecurityGroupInUseRule(ComplianceRule):
    """Ensures default security groups are not used by any resources."""
    rule_id = "DEFAULT_SECURITY_GROUP_IN_USE"
    name = "Default Security Group In Use"
    description = "Ensures default security groups are not attached to any network interfaces"
    resource_type = "AWS::EC2::SecurityGroup"
    severity = Severity.MEDIUM
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate default security groups using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            # Only check default security groups
            if not attrs.get("is_default"):
                continue

            attached_resources = attrs.get("attached_resources", [])
            is_in_use = len(attached_resources) > 0

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "is_in_use": is_in_use,
                "attached_resource_count": len(attached_resources),
                "message": f"Default security group is attached to {len(attached_resources)} resource(s)" if is_in_use else "Default security group is not in use"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=f"default ({attrs.get('vpc_id')})",
                status="FAIL" if is_in_use else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method - simplified version."""
        results = []
        try:
            ec2 = session.client("ec2", region_name=region)

            # Get default security groups
            sg_paginator = ec2.get_paginator("describe_security_groups")
            for page in sg_paginator.paginate(Filters=[{"Name": "group-name", "Values": ["default"]}]):
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg["GroupId"]
                    vpc_id = sg.get("VpcId", "EC2-Classic")
                    owner_id = sg.get("OwnerId", "unknown")

                    # Check ENIs
                    eni_paginator = ec2.get_paginator("describe_network_interfaces")
                    attached_resources = []
                    for eni_page in eni_paginator.paginate(Filters=[{"Name": "group-id", "Values": [sg_id]}]):
                        for eni in eni_page.get("NetworkInterfaces", []):
                            attached_resources.append({
                                "network_interface_id": eni["NetworkInterfaceId"],
                                "interface_type": eni.get("InterfaceType", "unknown"),
                            })

                    is_in_use = len(attached_resources) > 0

                    results.append(RuleResult(
                        resource_id=f"arn:aws:ec2:{region}:{owner_id}:security-group/{sg_id}",
                        resource_name=f"default ({vpc_id})",
                        status="FAIL" if is_in_use else "PASS",
                        details={
                            "security_group_id": sg_id,
                            "vpc_id": vpc_id,
                            "is_in_use": is_in_use,
                            "attached_resource_count": len(attached_resources),
                            "attached_resources": attached_resources,
                        }
                    ))
        except ClientError:
            pass
        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Create custom security groups and migrate all resources away from the default security group"


class UnusedSecurityGroupRule(ComplianceRule):
    """Identifies security groups that are not attached to any resources."""
    rule_id = "UNUSED_SECURITY_GROUP"
    name = "Unused Security Group"
    description = "Identifies security groups that are not attached to any resources and may be candidates for removal"
    resource_type = "AWS::EC2::SecurityGroup"
    severity = Severity.LOW
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate security groups using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            # Skip default security groups
            if attrs.get("is_default"):
                continue

            is_unused = not attrs.get("is_used", True)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "is_unused": is_unused,
                "message": "Security group is not attached to any resources" if is_unused else "Security group is in use"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if is_unused else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method - uses fetcher logic inline."""
        # Import fetcher to reuse logic
        from app.services.fetchers.security_group_fetcher import SecurityGroupResourceFetcher
        from app.services.fetchers.base import ResourceCache

        fetcher = SecurityGroupResourceFetcher()
        cache = ResourceCache()

        # Get account ID
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        resources = await fetcher.fetch(session, region, account_id, "AWS::EC2::SecurityGroup")
        return await self.evaluate_resources(resources, session, region)

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Delete the unused security group."""
        sg_id = resource_id.split("/")[-1]
        ec2 = session.client("ec2", region_name=region)
        ec2.delete_security_group(GroupId=sg_id)
        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Delete the unused security group after confirming it is no longer needed"
