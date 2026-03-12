"""ACM resource fetcher - fetches ACM certificates with expiration."""

from typing import List
from datetime import datetime, timezone
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class ACMResourceFetcher(ResourceFetcher):
    """
    Fetches ACM certificates with expiration status.

    This fetcher collects:
    - ACM certificates with validity periods
    - Days until expiration calculation
    """

    resource_types = ["AWS::ACM::Certificate"]

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch ACM certificates with expiration info."""
        resources = []

        try:
            acm = session.client("acm", region_name=region)

            paginator = acm.get_paginator("list_certificates")
            for page in paginator.paginate():
                for cert_summary in page.get("CertificateSummaryList", []):
                    cert_arn = cert_summary["CertificateArn"]
                    domain_name = cert_summary.get("DomainName", "")

                    # Get full certificate details
                    try:
                        describe_response = acm.describe_certificate(CertificateArn=cert_arn)
                        cert = describe_response.get("Certificate", {})
                    except ClientError:
                        continue

                    # Calculate days until expiration
                    not_after = cert.get("NotAfter")
                    days_until_expiry = None
                    is_expired = False
                    if not_after:
                        now = datetime.now(timezone.utc)
                        if not_after.tzinfo is None:
                            not_after = not_after.replace(tzinfo=timezone.utc)
                        days_until_expiry = (not_after - now).days
                        is_expired = days_until_expiry < 0

                    # Get tags
                    tags = {}
                    try:
                        tags_response = acm.list_tags_for_certificate(CertificateArn=cert_arn)
                        for tag in tags_response.get("Tags", []):
                            tags[tag["Key"]] = tag["Value"]
                    except ClientError:
                        pass

                    attributes = {
                        "certificate_arn": cert_arn,
                        "domain_name": domain_name,
                        "subject_alternative_names": cert.get("SubjectAlternativeNames", []),
                        "status": cert.get("Status"),
                        "type": cert.get("Type"),
                        "issuer": cert.get("Issuer"),
                        "not_before": str(cert.get("NotBefore")) if cert.get("NotBefore") else None,
                        "not_after": str(not_after) if not_after else None,
                        "days_until_expiry": days_until_expiry,
                        "is_expired": is_expired,
                        "key_algorithm": cert.get("KeyAlgorithm"),
                        "signature_algorithm": cert.get("SignatureAlgorithm"),
                        "in_use_by": cert.get("InUseBy", []),
                        "renewal_eligibility": cert.get("RenewalEligibility"),
                        "renewal_summary": cert.get("RenewalSummary"),
                        "failure_reason": cert.get("FailureReason"),
                        "created_at": str(cert.get("CreatedAt")) if cert.get("CreatedAt") else None,
                        "imported_at": str(cert.get("ImportedAt")) if cert.get("ImportedAt") else None,
                        "issued_at": str(cert.get("IssuedAt")) if cert.get("IssuedAt") else None,
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=cert_arn,
                        resource_name=domain_name,
                        resource_type="AWS::ACM::Certificate",
                        region=region,
                        account_id=account_id,
                        raw_data=cert,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources
