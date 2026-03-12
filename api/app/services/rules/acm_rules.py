"""ACM (AWS Certificate Manager) compliance rules."""

from typing import List

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


class ACMCertificateExpirationRule(ComplianceRule):
    """Ensures ACM certificates are not close to expiration."""

    rule_id = "ACM_CERTIFICATE_EXPIRATION"
    name = "ACM Certificate Close to Expiration"
    description = "Ensures ACM certificates are not expiring within 30 days to prevent service disruption"
    resource_type = "AWS::ACM::Certificate"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    # Number of days before expiration to trigger warning
    EXPIRATION_THRESHOLD_DAYS = 30

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched ACM certificates for expiration status."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            cert_arn = attrs.get("certificate_arn", resource.resource_id)
            domain_name = attrs.get("domain_name", resource.resource_name)
            status = attrs.get("status")

            # Skip certificates that aren't issued
            if status != "ISSUED":
                continue

            days_until_expiry = attrs.get("days_until_expiry")
            is_expired = attrs.get("is_expired", False)

            # Determine status
            is_expiring_soon = False
            if days_until_expiry is not None:
                is_expiring_soon = days_until_expiry <= self.EXPIRATION_THRESHOLD_DAYS and not is_expired

            # Determine status message
            if is_expired:
                message = f"Certificate has expired ({abs(days_until_expiry)} days ago)"
                status_result = "FAIL"
            elif is_expiring_soon:
                message = f"Certificate expires in {days_until_expiry} days"
                status_result = "FAIL"
            else:
                message = f"Certificate expires in {days_until_expiry} days"
                status_result = "PASS"

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "days_until_expiration": days_until_expiry,
                "is_expired": is_expired,
                "is_expiring_soon": is_expiring_soon,
                "threshold_days": self.EXPIRATION_THRESHOLD_DAYS,
                "message": message
            })

            results.append(RuleResult(
                resource_id=cert_arn,
                resource_name=domain_name,
                status=status_result,
                details=details
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Renew or replace the certificate before it expires. For ACM-issued certificates, ensure auto-renewal is working. For imported certificates, import a new certificate."
