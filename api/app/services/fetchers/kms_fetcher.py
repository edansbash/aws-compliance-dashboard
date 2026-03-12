"""KMS resource fetcher - fetches KMS keys with rotation status."""

from typing import List
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class KMSResourceFetcher(ResourceFetcher):
    """
    Fetches KMS keys with their rotation status.

    This fetcher collects:
    - Customer-managed KMS keys
    - Key rotation status
    """

    resource_types = ["AWS::KMS::Key"]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch KMS keys with rotation status."""
        resources = []

        try:
            kms = session.client("kms", region_name=region)

            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key in page.get("Keys", []):
                    key_id = key["KeyId"]
                    key_arn = key["KeyArn"]

                    # Get key details
                    key_metadata = {}
                    try:
                        describe_response = kms.describe_key(KeyId=key_id)
                        key_metadata = describe_response.get("KeyMetadata", {})
                    except ClientError:
                        continue

                    # Skip AWS-managed keys
                    key_manager = key_metadata.get("KeyManager")
                    if key_manager == "AWS":
                        continue

                    # Skip keys that are not enabled
                    key_state = key_metadata.get("KeyState")
                    if key_state != "Enabled":
                        continue

                    # Get key rotation status (only for symmetric keys)
                    key_rotation_enabled = False
                    key_spec = key_metadata.get("KeySpec", "")
                    if key_spec == "SYMMETRIC_DEFAULT":
                        try:
                            rotation_response = kms.get_key_rotation_status(KeyId=key_id)
                            key_rotation_enabled = rotation_response.get("KeyRotationEnabled", False)
                        except ClientError:
                            pass

                    # Get tags
                    tags = {}
                    try:
                        tags_response = kms.list_resource_tags(KeyId=key_id)
                        for tag in tags_response.get("Tags", []):
                            tags[tag["TagKey"]] = tag["TagValue"]
                    except ClientError:
                        pass

                    # Get aliases
                    aliases = []
                    try:
                        aliases_response = kms.list_aliases(KeyId=key_id)
                        aliases = [a["AliasName"] for a in aliases_response.get("Aliases", [])]
                    except ClientError:
                        pass

                    key_name = aliases[0] if aliases else key_id

                    attributes = {
                        "key_id": key_id,
                        "key_arn": key_arn,
                        "key_manager": key_manager,
                        "key_state": key_state,
                        "key_spec": key_spec,
                        "key_usage": key_metadata.get("KeyUsage"),
                        "origin": key_metadata.get("Origin"),
                        "description": key_metadata.get("Description"),
                        "creation_date": str(key_metadata.get("CreationDate")) if key_metadata.get("CreationDate") else None,
                        "enabled": key_metadata.get("Enabled", False),
                        "key_rotation_enabled": key_rotation_enabled,
                        "is_symmetric": key_spec == "SYMMETRIC_DEFAULT",
                        "aliases": aliases,
                        "multi_region": key_metadata.get("MultiRegion", False),
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=key_arn,
                        resource_name=key_name,
                        resource_type="AWS::KMS::Key",
                        region=region,
                        account_id=account_id,
                        raw_data=key_metadata,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources
