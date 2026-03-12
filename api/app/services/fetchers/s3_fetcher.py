"""S3 resource fetcher - fetches all S3 bucket data needed by S3 rules."""

import json
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class S3ResourceFetcher(ResourceFetcher):
    """
    Fetches S3 buckets with all attributes needed by S3 compliance rules.

    This fetcher collects:
    - Bucket list and basic info
    - Bucket locations (to filter by region)
    - Versioning configuration
    - Encryption configuration
    - Bucket policies
    - Public access block settings

    All S3 rules can then evaluate against this pre-fetched data
    without making additional API calls.
    """

    resource_types = ["AWS::S3::Bucket"]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch all S3 buckets with their configurations for the given region."""
        resources = []

        try:
            s3 = session.client("s3", region_name=region)

            # List all buckets (S3 ListBuckets is global, returns all buckets)
            response = s3.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]

                try:
                    # Get bucket location to determine if it belongs to this region
                    location_response = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get("LocationConstraint") or "us-east-1"

                    # Only process buckets in the target region
                    if bucket_region != region:
                        continue

                    # Initialize attributes dict
                    attributes: Dict[str, Any] = {
                        "bucket_name": bucket_name,
                        "bucket_region": bucket_region,
                        "creation_date": bucket.get("CreationDate"),
                    }

                    # Fetch versioning configuration
                    try:
                        versioning_response = s3.get_bucket_versioning(Bucket=bucket_name)
                        attributes["versioning_status"] = versioning_response.get("Status", "Disabled")
                        attributes["mfa_delete_status"] = versioning_response.get("MFADelete", "Disabled")
                    except ClientError as e:
                        attributes["versioning_status"] = "ERROR"
                        attributes["versioning_error"] = str(e)

                    # Fetch encryption configuration
                    try:
                        encryption_response = s3.get_bucket_encryption(Bucket=bucket_name)
                        rules = encryption_response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                        attributes["encryption_enabled"] = len(rules) > 0
                        if rules:
                            apply_sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                            attributes["encryption_type"] = apply_sse.get("SSEAlgorithm")
                            attributes["kms_key_id"] = apply_sse.get("KMSMasterKeyID")
                        else:
                            attributes["encryption_type"] = None
                            attributes["kms_key_id"] = None
                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code", "Unknown")
                        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                            attributes["encryption_enabled"] = False
                            attributes["encryption_type"] = None
                            attributes["kms_key_id"] = None
                        else:
                            attributes["encryption_enabled"] = "ERROR"
                            attributes["encryption_error"] = str(e)

                    # Fetch bucket policy
                    try:
                        policy_response = s3.get_bucket_policy(Bucket=bucket_name)
                        policy_str = policy_response.get("Policy", "{}")
                        attributes["policy"] = json.loads(policy_str)
                        attributes["policy_exists"] = True
                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code", "Unknown")
                        if error_code == "NoSuchBucketPolicy":
                            attributes["policy"] = None
                            attributes["policy_exists"] = False
                        else:
                            attributes["policy"] = None
                            attributes["policy_exists"] = "ERROR"
                            attributes["policy_error"] = str(e)

                    # Fetch public access block configuration
                    try:
                        public_access_response = s3.get_public_access_block(Bucket=bucket_name)
                        config = public_access_response.get("PublicAccessBlockConfiguration", {})
                        attributes["public_access_block"] = {
                            "block_public_acls": config.get("BlockPublicAcls", False),
                            "ignore_public_acls": config.get("IgnorePublicAcls", False),
                            "block_public_policy": config.get("BlockPublicPolicy", False),
                            "restrict_public_buckets": config.get("RestrictPublicBuckets", False),
                        }
                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code", "Unknown")
                        if error_code == "NoSuchPublicAccessBlockConfiguration":
                            attributes["public_access_block"] = None
                        else:
                            attributes["public_access_block"] = "ERROR"
                            attributes["public_access_block_error"] = str(e)

                    # Fetch bucket ACL
                    try:
                        acl_response = s3.get_bucket_acl(Bucket=bucket_name)
                        attributes["acl"] = {
                            "owner": acl_response.get("Owner", {}),
                            "grants": acl_response.get("Grants", []),
                        }
                    except ClientError:
                        attributes["acl"] = None

                    # Fetch bucket tags
                    tags = {}
                    try:
                        tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
                        for tag in tags_response.get("TagSet", []):
                            tags[tag["Key"]] = tag["Value"]
                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code", "Unknown")
                        if error_code != "NoSuchTagSet":
                            # Ignore NoSuchTagSet (bucket has no tags)
                            pass
                    attributes["tags"] = tags

                    # Create the FetchedResource
                    resource = FetchedResource(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        resource_type="AWS::S3::Bucket",
                        region=bucket_region,
                        account_id=account_id,
                        raw_data=bucket,
                        attributes=attributes,
                    )
                    resources.append(resource)

                except ClientError as e:
                    # Log error but continue with other buckets
                    error_code = e.response.get("Error", {}).get("Code", "Unknown")
                    # Create a resource with error status
                    resource = FetchedResource(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        resource_type="AWS::S3::Bucket",
                        region=region,
                        account_id=account_id,
                        raw_data=bucket,
                        attributes={
                            "bucket_name": bucket_name,
                            "error": f"{error_code}: {str(e)}",
                            "fetch_failed": True,
                        },
                    )
                    resources.append(resource)

        except ClientError:
            # If we can't list buckets, return empty list
            pass

        return resources
