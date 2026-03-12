"""SNS resource fetcher - fetches SNS topics with policies."""

import json
from typing import List
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class SNSResourceFetcher(ResourceFetcher):
    """
    Fetches SNS topics with their policies.

    This fetcher collects:
    - SNS topics with access policies for world access checks
    """

    resource_types = ["AWS::SNS::Topic"]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch SNS topics with policies."""
        resources = []

        try:
            sns = session.client("sns", region_name=region)

            paginator = sns.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []):
                    topic_arn = topic["TopicArn"]
                    topic_name = topic_arn.split(":")[-1]

                    # Get topic attributes including policy
                    policy = None
                    attributes = {}
                    try:
                        attr_response = sns.get_topic_attributes(TopicArn=topic_arn)
                        attributes = attr_response.get("Attributes", {})
                        policy_str = attributes.get("Policy", "{}")
                        policy = json.loads(policy_str)
                    except ClientError:
                        pass

                    # Get tags
                    tags = {}
                    try:
                        tags_response = sns.list_tags_for_resource(ResourceArn=topic_arn)
                        for tag in tags_response.get("Tags", []):
                            tags[tag["Key"]] = tag["Value"]
                    except ClientError:
                        pass

                    resource_attributes = {
                        "topic_arn": topic_arn,
                        "topic_name": topic_name,
                        "policy": policy,
                        "policy_exists": policy is not None,
                        "display_name": attributes.get("DisplayName"),
                        "owner": attributes.get("Owner"),
                        "subscriptions_confirmed": int(attributes.get("SubscriptionsConfirmed", 0)),
                        "subscriptions_pending": int(attributes.get("SubscriptionsPending", 0)),
                        "subscriptions_deleted": int(attributes.get("SubscriptionsDeleted", 0)),
                        "kms_master_key_id": attributes.get("KmsMasterKeyId"),
                        "effective_delivery_policy": attributes.get("EffectiveDeliveryPolicy"),
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=topic_arn,
                        resource_name=topic_name,
                        resource_type="AWS::SNS::Topic",
                        region=region,
                        account_id=account_id,
                        raw_data=topic,
                        attributes=resource_attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources
