"""ELBv2 resource fetcher - fetches Application and Network Load Balancers."""

from typing import List
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class ELBv2ResourceFetcher(ResourceFetcher):
    """
    Fetches ELBv2 resources including ALBs, NLBs, and their listeners.

    This fetcher collects:
    - Load balancers with attributes
    - Listeners with SSL policies
    """

    resource_types = [
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "AWS::ElasticLoadBalancingV2::Listener",
    ]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch ELBv2 resources based on resource type."""
        if resource_type == "AWS::ElasticLoadBalancingV2::LoadBalancer":
            return await self._fetch_load_balancers(session, region, account_id)
        elif resource_type == "AWS::ElasticLoadBalancingV2::Listener":
            return await self._fetch_listeners(session, region, account_id)
        return []

    async def _fetch_load_balancers(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all ALBs and NLBs with their attributes."""
        resources = []

        try:
            elbv2 = session.client("elbv2", region_name=region)

            paginator = elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    lb_arn = lb["LoadBalancerArn"]
                    lb_name = lb.get("LoadBalancerName", lb_arn.split("/")[-1])

                    # Get load balancer attributes
                    lb_attributes = {}
                    try:
                        attr_response = elbv2.describe_load_balancer_attributes(
                            LoadBalancerArn=lb_arn
                        )
                        for attr in attr_response.get("Attributes", []):
                            lb_attributes[attr["Key"]] = attr["Value"]
                    except ClientError:
                        pass

                    # Get tags
                    tags = {}
                    try:
                        tags_response = elbv2.describe_tags(ResourceArns=[lb_arn])
                        for tag_desc in tags_response.get("TagDescriptions", []):
                            for tag in tag_desc.get("Tags", []):
                                tags[tag["Key"]] = tag["Value"]
                    except ClientError:
                        pass

                    # Get listeners
                    listeners = []
                    try:
                        listener_paginator = elbv2.get_paginator("describe_listeners")
                        for listener_page in listener_paginator.paginate(LoadBalancerArn=lb_arn):
                            listeners.extend(listener_page.get("Listeners", []))
                    except ClientError:
                        pass

                    attributes = {
                        "load_balancer_arn": lb_arn,
                        "load_balancer_name": lb_name,
                        "dns_name": lb.get("DNSName"),
                        "type": lb.get("Type"),
                        "scheme": lb.get("Scheme"),
                        "vpc_id": lb.get("VpcId"),
                        "state": lb.get("State", {}).get("Code"),
                        "availability_zones": lb.get("AvailabilityZones", []),
                        "security_groups": lb.get("SecurityGroups", []),
                        "ip_address_type": lb.get("IpAddressType"),
                        "created_time": str(lb.get("CreatedTime")) if lb.get("CreatedTime") else None,
                        # Parsed attributes
                        "deletion_protection_enabled": lb_attributes.get("deletion_protection.enabled", "false") == "true",
                        "access_logs_enabled": lb_attributes.get("access_logs.s3.enabled", "false") == "true",
                        "access_logs_bucket": lb_attributes.get("access_logs.s3.bucket"),
                        "drop_invalid_header_fields": lb_attributes.get("routing.http.drop_invalid_header_fields.enabled", "false") == "true",
                        "idle_timeout": lb_attributes.get("idle_timeout.timeout_seconds"),
                        "lb_attributes": lb_attributes,
                        "listeners": listeners,
                        "listener_count": len(listeners),
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=lb_arn,
                        resource_name=lb_name,
                        resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
                        region=region,
                        account_id=account_id,
                        raw_data=lb,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_listeners(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all listeners across all load balancers."""
        resources = []

        try:
            elbv2 = session.client("elbv2", region_name=region)

            # First get all load balancers
            lb_paginator = elbv2.get_paginator("describe_load_balancers")
            for lb_page in lb_paginator.paginate():
                for lb in lb_page.get("LoadBalancers", []):
                    lb_arn = lb["LoadBalancerArn"]
                    lb_name = lb.get("LoadBalancerName", "")
                    lb_type = lb.get("Type")

                    # Get listeners for this load balancer
                    try:
                        listener_paginator = elbv2.get_paginator("describe_listeners")
                        for listener_page in listener_paginator.paginate(LoadBalancerArn=lb_arn):
                            for listener in listener_page.get("Listeners", []):
                                listener_arn = listener["ListenerArn"]
                                port = listener.get("Port")
                                protocol = listener.get("Protocol")

                                listener_name = f"{lb_name}:{port}"

                                # Check for cleartext protocols
                                is_cleartext = protocol in ["HTTP", "TCP", "UDP", "TCP_UDP"]

                                attributes = {
                                    "listener_arn": listener_arn,
                                    "load_balancer_arn": lb_arn,
                                    "load_balancer_name": lb_name,
                                    "load_balancer_type": lb_type,
                                    "port": port,
                                    "protocol": protocol,
                                    "is_cleartext": is_cleartext,
                                    "ssl_policy": listener.get("SslPolicy"),
                                    "certificates": listener.get("Certificates", []),
                                    "default_actions": listener.get("DefaultActions", []),
                                    "alpn_policy": listener.get("AlpnPolicy", []),
                                }

                                resource = FetchedResource(
                                    resource_id=listener_arn,
                                    resource_name=listener_name,
                                    resource_type="AWS::ElasticLoadBalancingV2::Listener",
                                    region=region,
                                    account_id=account_id,
                                    raw_data=listener,
                                    attributes=attributes,
                                )
                                resources.append(resource)

                    except ClientError:
                        pass

        except ClientError:
            pass

        return resources
