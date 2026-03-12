"""ELBv2 (Application/Network Load Balancer) compliance rules."""

from typing import List, Dict, Any

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


class ELBv2DeletionProtectionRule(ComplianceRule):
    """Ensures ELBv2 load balancers have deletion protection enabled."""

    rule_id = "ELBV2_DELETION_PROTECTION"
    name = "ELBv2 Deletion Protection Disabled"
    description = "Ensures Application and Network Load Balancers have deletion protection enabled to prevent accidental deletion"
    resource_type = "AWS::ElasticLoadBalancingV2::LoadBalancer"
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
        """Evaluate pre-fetched ELBv2 load balancers for deletion protection."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            lb_name = attrs.get("load_balancer_name", resource.resource_name)

            deletion_protection = attrs.get("deletion_protection_enabled", False)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "deletion_protection_enabled": deletion_protection,
                "message": "Deletion protection is enabled" if deletion_protection else "Deletion protection is not enabled"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=lb_name,
                status="PASS" if deletion_protection else "FAIL",
                details=details
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Enable deletion protection on the load balancer."""
        elbv2 = session.client("elbv2", region_name=region)
        elbv2.modify_load_balancer_attributes(
            LoadBalancerArn=resource_id,
            Attributes=[
                {
                    "Key": "deletion_protection.enabled",
                    "Value": "true"
                }
            ]
        )
        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable deletion protection on the load balancer to prevent accidental deletion"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "deletion_protection_enabled": True,
        }


class ELBv2ListenerAllowsCleartextRule(ComplianceRule):
    """Ensures ELBv2 listeners do not allow cleartext (HTTP) traffic."""

    rule_id = "ELBV2_LISTENER_ALLOWS_CLEARTEXT"
    name = "ELBv2 Listener Allows Cleartext"
    description = "Ensures Application Load Balancer listeners do not accept unencrypted HTTP traffic on non-redirect rules"
    resource_type = "AWS::ElasticLoadBalancingV2::LoadBalancer"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched ELBv2 listeners for cleartext traffic."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            lb_name = attrs.get("load_balancer_name", resource.resource_name)
            lb_type = attrs.get("load_balancer_type")

            # Only check Application Load Balancers (ALBs)
            if lb_type != "application":
                continue

            listeners = attrs.get("listeners", [])
            allows_cleartext = False
            cleartext_listeners = []

            for listener in listeners:
                protocol = listener.get("protocol", "")
                port = listener.get("port")

                # Check if listener uses HTTP (cleartext)
                if protocol == "HTTP":
                    is_redirect_only = listener.get("is_redirect_to_https", False)

                    if not is_redirect_only:
                        allows_cleartext = True
                        cleartext_listeners.append({
                            "listener_arn": listener.get("listener_arn"),
                            "protocol": protocol,
                            "port": port,
                            "is_redirect_only": is_redirect_only,
                        })

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "allows_cleartext": allows_cleartext,
                "cleartext_listeners": cleartext_listeners,
                "total_listeners": len(listeners),
                "message": f"Load balancer has {len(cleartext_listeners)} listener(s) allowing cleartext traffic" if allows_cleartext else "All listeners use encrypted protocols or redirect to HTTPS"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=lb_name,
                status="FAIL" if allows_cleartext else "PASS",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Configure HTTP listeners to redirect to HTTPS or remove them and use HTTPS listeners only"


class ELBv2NoAccessLogsRule(ComplianceRule):
    """Ensures ELBv2 load balancers have access logging enabled."""

    rule_id = "ELBV2_NO_ACCESS_LOGS"
    name = "ELBv2 Access Logs Disabled"
    description = "Ensures Application and Network Load Balancers have access logging enabled for security monitoring"
    resource_type = "AWS::ElasticLoadBalancingV2::LoadBalancer"
    severity = Severity.MEDIUM
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    # S3 bucket for access logs in the logging account
    ACCESS_LOGS_BUCKET = "compsci-loadbalancer-logs"

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched ELBv2 load balancers for access logging."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            lb_name = attrs.get("load_balancer_name", resource.resource_name)

            access_logs_enabled = attrs.get("access_logs_enabled", False)
            access_logs_bucket = attrs.get("access_logs_bucket", "")
            access_logs_prefix = attrs.get("access_logs_prefix", "")

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "access_logs_enabled": access_logs_enabled,
                "access_logs_bucket": access_logs_bucket if access_logs_enabled else None,
                "access_logs_prefix": access_logs_prefix if access_logs_enabled else None,
                "message": "Access logging is enabled" if access_logs_enabled else "Access logging is not enabled"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=lb_name,
                status="PASS" if access_logs_enabled else "FAIL",
                details=details
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Enable access logging on the load balancer."""
        elbv2 = session.client("elbv2", region_name=region)

        # Use load balancer name as prefix
        lb_name = finding_details.get("load_balancer_name", "") if finding_details else ""
        if not lb_name:
            # Extract from ARN if not in details: arn:aws:elasticloadbalancing:region:account:loadbalancer/type/name/id
            parts = resource_id.split("/")
            if len(parts) >= 3:
                lb_name = parts[-2]

        elbv2.modify_load_balancer_attributes(
            LoadBalancerArn=resource_id,
            Attributes=[
                {
                    "Key": "access_logs.s3.enabled",
                    "Value": "true"
                },
                {
                    "Key": "access_logs.s3.bucket",
                    "Value": self.ACCESS_LOGS_BUCKET
                },
                {
                    "Key": "access_logs.s3.prefix",
                    "Value": lb_name
                }
            ]
        )
        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable access logging and configure an S3 bucket to store the access logs"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        lb_name = current_details.get("load_balancer_name", "")
        return {
            **current_details,
            "access_logs_enabled": True,
            "access_logs_bucket": cls.ACCESS_LOGS_BUCKET,
            "access_logs_prefix": lb_name,
        }


class ELBv2OlderSSLPolicyRule(ComplianceRule):
    """Ensures ELBv2 HTTPS listeners use modern SSL/TLS policies."""

    rule_id = "ELBV2_OLDER_SSL_POLICY"
    name = "ELBv2 Using Older SSL Policy"
    description = "Ensures Application Load Balancer HTTPS listeners use modern SSL/TLS security policies"
    resource_type = "AWS::ElasticLoadBalancingV2::LoadBalancer"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    # Recommended modern SSL policies
    MODERN_SSL_POLICIES = [
        "ELBSecurityPolicy-TLS13-1-2-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
        "ELBSecurityPolicy-TLS13-1-3-2021-06",
        "ELBSecurityPolicy-FS-1-2-2019-08",
        "ELBSecurityPolicy-FS-1-2-Res-2019-08",
        "ELBSecurityPolicy-FS-1-2-Res-2020-10",
    ]

    # Deprecated/older policies that should not be used
    DEPRECATED_SSL_POLICIES = [
        "ELBSecurityPolicy-2016-08",
        "ELBSecurityPolicy-TLS-1-0-2015-04",
        "ELBSecurityPolicy-TLS-1-1-2017-01",
        "ELBSecurityPolicy-2015-05",
        "ELBSecurityPolicy-2015-03",
        "ELBSecurityPolicy-2015-02",
    ]

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched ELBv2 listeners for SSL policy compliance."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            lb_name = attrs.get("load_balancer_name", resource.resource_name)
            lb_type = attrs.get("load_balancer_type")

            # Only check Application Load Balancers
            if lb_type != "application":
                continue

            listeners = attrs.get("listeners", [])

            has_older_policy = False
            older_policy_listeners = []
            https_listeners = []

            for listener in listeners:
                protocol = listener.get("protocol", "")
                port = listener.get("port")
                ssl_policy = listener.get("ssl_policy")

                # Only check HTTPS listeners
                if protocol != "HTTPS":
                    continue

                https_listeners.append({
                    "listener_arn": listener.get("listener_arn"),
                    "port": port,
                    "ssl_policy": ssl_policy,
                })

                # Check if using an older/deprecated policy
                is_modern = ssl_policy in self.MODERN_SSL_POLICIES
                is_deprecated = ssl_policy in self.DEPRECATED_SSL_POLICIES

                if is_deprecated or not is_modern:
                    has_older_policy = True
                    older_policy_listeners.append({
                        "listener_arn": listener.get("listener_arn"),
                        "port": port,
                        "ssl_policy": ssl_policy,
                        "is_deprecated": is_deprecated,
                    })

            # Only report if there are HTTPS listeners
            if https_listeners:
                # Preserve all resource attributes (including tags) and add compliance-specific fields
                details = dict(attrs)
                details.update({
                    "has_older_ssl_policy": has_older_policy,
                    "https_listeners": https_listeners,
                    "older_policy_listeners": older_policy_listeners,
                    "recommended_policies": self.MODERN_SSL_POLICIES[:3],
                    "message": f"Load balancer has {len(older_policy_listeners)} listener(s) using older SSL policies" if has_older_policy else "All HTTPS listeners use modern SSL policies"
                })

                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=lb_name,
                    status="FAIL" if has_older_policy else "PASS",
                    details=details
                ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Update HTTPS listeners to use a modern SSL policy such as ELBSecurityPolicy-TLS13-1-2-2021-06"


class ELBv2DropInvalidHeaderFieldsRule(ComplianceRule):
    """Ensures ELBv2 load balancers drop invalid HTTP header fields."""

    rule_id = "ELBV2_DROP_INVALID_HEADER_FIELDS_DISABLED"
    name = "ELBv2 Drop Invalid Header Fields Disabled"
    description = "Ensures Application Load Balancers are configured to drop HTTP headers with invalid header fields"
    resource_type = "AWS::ElasticLoadBalancingV2::LoadBalancer"
    severity = Severity.MEDIUM
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched ELBv2 load balancers for drop invalid header fields setting."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            lb_name = attrs.get("load_balancer_name", resource.resource_name)
            lb_type = attrs.get("load_balancer_type")

            # Only check Application Load Balancers
            if lb_type != "application":
                continue

            drop_invalid_headers = attrs.get("drop_invalid_header_fields_enabled", False)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "drop_invalid_header_fields_enabled": drop_invalid_headers,
                "message": "Drop invalid header fields is enabled" if drop_invalid_headers else "Drop invalid header fields is not enabled"
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=lb_name,
                status="PASS" if drop_invalid_headers else "FAIL",
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable the 'Drop Invalid Header Fields' attribute on the Application Load Balancer"
