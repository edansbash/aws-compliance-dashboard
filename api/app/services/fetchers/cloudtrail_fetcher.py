"""CloudTrail resource fetcher."""

from typing import List
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class CloudTrailResourceFetcher(ResourceFetcher):
    """Fetches CloudTrail trails with their configuration details."""

    resource_types = ["AWS::CloudTrail::Trail"]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch CloudTrail trails with their configuration."""
        resources = []

        try:
            cloudtrail = session.client("cloudtrail", region_name=region)

            # Get all trails
            response = cloudtrail.describe_trails(includeShadowTrails=False)
            trails = response.get("trailList", [])

            for trail in trails:
                trail_name = trail.get("Name", "")
                trail_arn = trail.get("TrailARN", "")
                home_region = trail.get("HomeRegion", "")

                # Only process trails that belong to this region
                # (avoid duplicates from multi-region trails)
                if home_region != region:
                    continue

                # Get trail status
                is_logging = False
                try:
                    status_response = cloudtrail.get_trail_status(Name=trail_name)
                    is_logging = status_response.get("IsLogging", False)
                except ClientError:
                    pass

                # Get event selectors to check configuration
                event_selectors = []
                try:
                    selectors_response = cloudtrail.get_event_selectors(TrailName=trail_name)
                    event_selectors = selectors_response.get("EventSelectors", [])
                except ClientError:
                    pass

                # Get tags
                tags = {}
                try:
                    tags_response = cloudtrail.list_tags(ResourceIdList=[trail_arn])
                    for resource_tag in tags_response.get("ResourceTagList", []):
                        if resource_tag.get("ResourceId") == trail_arn:
                            for tag in resource_tag.get("TagsList", []):
                                tags[tag["Key"]] = tag["Value"]
                except ClientError:
                    pass

                # Build attributes
                attributes = {
                    "trail_name": trail_name,
                    "trail_arn": trail_arn,
                    "home_region": home_region,
                    "is_multi_region_trail": trail.get("IsMultiRegionTrail", False),
                    "is_organization_trail": trail.get("IsOrganizationTrail", False),
                    "s3_bucket_name": trail.get("S3BucketName"),
                    "s3_key_prefix": trail.get("S3KeyPrefix"),
                    "sns_topic_name": trail.get("SnsTopicName"),
                    "sns_topic_arn": trail.get("SnsTopicARN"),
                    "include_global_service_events": trail.get("IncludeGlobalServiceEvents", False),
                    "is_logging": is_logging,
                    "log_file_validation_enabled": trail.get("LogFileValidationEnabled", False),
                    "cloud_watch_logs_log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                    "cloud_watch_logs_role_arn": trail.get("CloudWatchLogsRoleArn"),
                    "kms_key_id": trail.get("KMSKeyId"),
                    "has_custom_event_selectors": trail.get("HasCustomEventSelectors", False),
                    "has_insight_selectors": trail.get("HasInsightSelectors", False),
                    "event_selectors": event_selectors,
                    "tags": tags,
                }

                resource = FetchedResource(
                    resource_id=trail_arn,
                    resource_name=trail_name,
                    resource_type="AWS::CloudTrail::Trail",
                    region=region,
                    account_id=account_id,
                    raw_data=trail,
                    attributes=attributes,
                )
                resources.append(resource)

        except ClientError as e:
            # Log but don't fail - return empty list
            pass

        return resources
