"""SQS resource fetcher - fetches SQS queues with policies and encryption."""

import json
from typing import List
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class SQSResourceFetcher(ResourceFetcher):
    """
    Fetches SQS queues with their policies and attributes.

    This fetcher collects:
    - SQS queues with access policies for world access checks
    - Encryption settings (KMS)
    """

    resource_types = ["AWS::SQS::Queue"]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch SQS queues with policies and attributes."""
        resources = []

        try:
            sqs = session.client("sqs", region_name=region)

            # List all queues
            paginator = sqs.get_paginator("list_queues")
            for page in paginator.paginate():
                for queue_url in page.get("QueueUrls", []):
                    queue_name = queue_url.split("/")[-1]

                    # Get queue attributes
                    policy = None
                    attributes = {}
                    queue_arn = None
                    try:
                        attr_response = sqs.get_queue_attributes(
                            QueueUrl=queue_url,
                            AttributeNames=["All"]
                        )
                        attributes = attr_response.get("Attributes", {})
                        queue_arn = attributes.get("QueueArn")

                        policy_str = attributes.get("Policy")
                        if policy_str:
                            policy = json.loads(policy_str)
                    except ClientError:
                        pass

                    if not queue_arn:
                        queue_arn = f"arn:aws:sqs:{region}:{account_id}:{queue_name}"

                    # Get tags
                    tags = {}
                    try:
                        tags_response = sqs.list_queue_tags(QueueUrl=queue_url)
                        tags = tags_response.get("Tags", {})
                    except ClientError:
                        pass

                    # Check encryption
                    kms_key_id = attributes.get("KmsMasterKeyId")
                    sqs_managed_encryption = attributes.get("SqsManagedSseEnabled", "false") == "true"
                    is_encrypted = bool(kms_key_id) or sqs_managed_encryption

                    resource_attributes = {
                        "queue_url": queue_url,
                        "queue_name": queue_name,
                        "queue_arn": queue_arn,
                        "policy": policy,
                        "policy_exists": policy is not None,
                        "kms_master_key_id": kms_key_id,
                        "sqs_managed_sse_enabled": sqs_managed_encryption,
                        "is_encrypted": is_encrypted,
                        "visibility_timeout": attributes.get("VisibilityTimeout"),
                        "maximum_message_size": attributes.get("MaximumMessageSize"),
                        "message_retention_period": attributes.get("MessageRetentionPeriod"),
                        "delay_seconds": attributes.get("DelaySeconds"),
                        "approximate_number_of_messages": attributes.get("ApproximateNumberOfMessages"),
                        "approximate_number_of_messages_not_visible": attributes.get("ApproximateNumberOfMessagesNotVisible"),
                        "created_timestamp": attributes.get("CreatedTimestamp"),
                        "last_modified_timestamp": attributes.get("LastModifiedTimestamp"),
                        "redrive_policy": attributes.get("RedrivePolicy"),
                        "fifo_queue": attributes.get("FifoQueue", "false") == "true",
                        "content_based_deduplication": attributes.get("ContentBasedDeduplication", "false") == "true",
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=queue_arn,
                        resource_name=queue_name,
                        resource_type="AWS::SQS::Queue",
                        region=region,
                        account_id=account_id,
                        raw_data={"QueueUrl": queue_url, "Attributes": attributes},
                        attributes=resource_attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources
