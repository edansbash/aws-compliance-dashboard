"""SES resource fetcher - fetches SES identities with policies and DKIM."""

import json
from typing import List
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class SESResourceFetcher(ResourceFetcher):
    """
    Fetches SES identities with their policies and DKIM settings.

    This fetcher collects:
    - SES identities (email addresses and domains)
    - Identity policies for authorization checks
    - DKIM verification status
    """

    resource_types = ["AWS::SES::Identity"]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch SES identities with policies and DKIM status."""
        resources = []

        try:
            ses = session.client("ses", region_name=region)

            # List all identities
            identities = []
            try:
                response = ses.list_identities()
                identities = response.get("Identities", [])
            except ClientError:
                pass

            for identity in identities:
                # Determine identity type (email or domain)
                identity_type = "Domain" if "@" not in identity else "EmailAddress"

                # Get identity verification attributes
                verification_status = None
                dkim_enabled = False
                dkim_verification_status = None
                dkim_tokens = []
                try:
                    verify_response = ses.get_identity_verification_attributes(
                        Identities=[identity]
                    )
                    verify_attrs = verify_response.get("VerificationAttributes", {}).get(identity, {})
                    verification_status = verify_attrs.get("VerificationStatus")
                except ClientError:
                    pass

                # Get DKIM attributes
                try:
                    dkim_response = ses.get_identity_dkim_attributes(Identities=[identity])
                    dkim_attrs = dkim_response.get("DkimAttributes", {}).get(identity, {})
                    dkim_enabled = dkim_attrs.get("DkimEnabled", False)
                    dkim_verification_status = dkim_attrs.get("DkimVerificationStatus")
                    dkim_tokens = dkim_attrs.get("DkimTokens", [])
                except ClientError:
                    pass

                # Get identity policies
                policies = {}
                policy_names = []
                try:
                    policy_names_response = ses.list_identity_policies(Identity=identity)
                    policy_names = policy_names_response.get("PolicyNames", [])

                    if policy_names:
                        policies_response = ses.get_identity_policies(
                            Identity=identity,
                            PolicyNames=policy_names
                        )
                        for name, policy_str in policies_response.get("Policies", {}).items():
                            try:
                                policies[name] = json.loads(policy_str)
                            except json.JSONDecodeError:
                                policies[name] = policy_str
                except ClientError:
                    pass

                # Get notification attributes
                notification_attrs = {}
                try:
                    notif_response = ses.get_identity_notification_attributes(
                        Identities=[identity]
                    )
                    notification_attrs = notif_response.get("NotificationAttributes", {}).get(identity, {})
                except ClientError:
                    pass

                identity_arn = f"arn:aws:ses:{region}:{account_id}:identity/{identity}"

                attributes = {
                    "identity": identity,
                    "identity_type": identity_type,
                    "verification_status": verification_status,
                    "is_verified": verification_status == "Success",
                    "dkim_enabled": dkim_enabled,
                    "dkim_verification_status": dkim_verification_status,
                    "dkim_verified": dkim_verification_status == "Success",
                    "dkim_tokens": dkim_tokens,
                    "policies": policies,
                    "policy_names": policy_names,
                    "has_policies": len(policies) > 0,
                    "bounce_topic": notification_attrs.get("BounceTopic"),
                    "complaint_topic": notification_attrs.get("ComplaintTopic"),
                    "delivery_topic": notification_attrs.get("DeliveryTopic"),
                    "forwarding_enabled": notification_attrs.get("ForwardingEnabled", True),
                }

                resource = FetchedResource(
                    resource_id=identity_arn,
                    resource_name=identity,
                    resource_type="AWS::SES::Identity",
                    region=region,
                    account_id=account_id,
                    raw_data={"Identity": identity},
                    attributes=attributes,
                )
                resources.append(resource)

        except ClientError:
            pass

        return resources
