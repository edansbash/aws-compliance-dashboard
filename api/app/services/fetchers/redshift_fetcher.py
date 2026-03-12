"""Redshift resource fetcher - fetches Redshift clusters."""

from typing import List
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class RedshiftResourceFetcher(ResourceFetcher):
    """
    Fetches Redshift clusters with configurations.

    This fetcher collects:
    - Redshift clusters with encryption, security, and logging settings
    - Parameter groups for SSL and logging configuration
    """

    resource_types = ["AWS::Redshift::Cluster"]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch Redshift clusters."""
        resources = []

        try:
            redshift = session.client("redshift", region_name=region)
            ec2 = session.client("ec2", region_name=region)

            # Get parameter groups for SSL and logging config
            param_groups = {}
            try:
                pg_paginator = redshift.get_paginator("describe_cluster_parameter_groups")
                for pg_page in pg_paginator.paginate():
                    for pg in pg_page.get("ParameterGroups", []):
                        pg_name = pg["ParameterGroupName"]
                        # Get parameters for this group
                        try:
                            params_paginator = redshift.get_paginator("describe_cluster_parameters")
                            params = []
                            for params_page in params_paginator.paginate(ParameterGroupName=pg_name):
                                params.extend(params_page.get("Parameters", []))
                            param_groups[pg_name] = {param["ParameterName"]: param.get("ParameterValue") for param in params}
                        except ClientError:
                            pass
            except ClientError:
                pass

            # Get all clusters
            paginator = redshift.get_paginator("describe_clusters")
            for page in paginator.paginate():
                for cluster in page.get("Clusters", []):
                    cluster_id = cluster["ClusterIdentifier"]

                    # Get cluster ARN
                    cluster_arn = f"arn:aws:redshift:{region}:{account_id}:cluster:{cluster_id}"

                    # Get security group details
                    vpc_security_groups = cluster.get("VpcSecurityGroups", [])
                    sg_ids = [sg["VpcSecurityGroupId"] for sg in vpc_security_groups if sg.get("Status") == "active"]

                    security_group_details = []
                    if sg_ids:
                        try:
                            sg_response = ec2.describe_security_groups(GroupIds=sg_ids)
                            security_group_details = sg_response.get("SecurityGroups", [])
                        except ClientError:
                            pass

                    # Get parameter group settings
                    cluster_param_group_name = None
                    cluster_params = {}
                    for pg in cluster.get("ClusterParameterGroups", []):
                        if pg.get("ParameterApplyStatus") == "in-sync":
                            cluster_param_group_name = pg.get("ParameterGroupName")
                            cluster_params = param_groups.get(cluster_param_group_name, {})
                            break

                    # Get logging status
                    logging_enabled = False
                    logging_bucket = None
                    logging_prefix = None
                    try:
                        logging_response = redshift.describe_logging_status(ClusterIdentifier=cluster_id)
                        logging_enabled = logging_response.get("LoggingEnabled", False)
                        logging_bucket = logging_response.get("BucketName")
                        logging_prefix = logging_response.get("S3KeyPrefix")
                    except ClientError:
                        pass

                    # Check SSL setting from parameters
                    require_ssl = cluster_params.get("require_ssl", "false") == "true"

                    # Get tags
                    tags = {}
                    for tag in cluster.get("Tags", []):
                        tags[tag["Key"]] = tag["Value"]

                    attributes = {
                        "cluster_identifier": cluster_id,
                        "node_type": cluster.get("NodeType"),
                        "cluster_status": cluster.get("ClusterStatus"),
                        "number_of_nodes": cluster.get("NumberOfNodes"),
                        "encrypted": cluster.get("Encrypted", False),
                        "kms_key_id": cluster.get("KmsKeyId"),
                        "publicly_accessible": cluster.get("PubliclyAccessible", False),
                        "endpoint_address": cluster.get("Endpoint", {}).get("Address"),
                        "endpoint_port": cluster.get("Endpoint", {}).get("Port"),
                        "vpc_id": cluster.get("VpcId"),
                        "availability_zone": cluster.get("AvailabilityZone"),
                        "allow_version_upgrade": cluster.get("AllowVersionUpgrade", True),
                        "cluster_version": cluster.get("ClusterVersion"),
                        "automated_snapshot_retention_period": cluster.get("AutomatedSnapshotRetentionPeriod"),
                        "cluster_parameter_group": cluster_param_group_name,
                        "cluster_parameters": cluster_params,
                        "require_ssl": require_ssl,
                        "logging_enabled": logging_enabled,
                        "logging_bucket": logging_bucket,
                        "logging_prefix": logging_prefix,
                        "vpc_security_groups": vpc_security_groups,
                        "security_group_ids": sg_ids,
                        "security_group_details": security_group_details,
                        "db_name": cluster.get("DBName"),
                        "master_username": cluster.get("MasterUsername"),
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=cluster_arn,
                        resource_name=cluster_id,
                        resource_type="AWS::Redshift::Cluster",
                        region=region,
                        account_id=account_id,
                        raw_data=cluster,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources
