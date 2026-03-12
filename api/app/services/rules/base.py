from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, TYPE_CHECKING
from dataclasses import dataclass
from enum import Enum

if TYPE_CHECKING:
    from app.services.fetchers.base import FetchedResource


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RuleResult:
    """Result of evaluating a rule against a resource."""
    resource_id: str
    resource_name: str
    status: str  # PASS, FAIL, ERROR
    details: Dict[str, Any]


class ComplianceRule(ABC):
    """
    Base class for all compliance rules.

    Rules can operate in two modes:
    1. Legacy mode: evaluate() fetches resources directly from AWS
    2. Optimized mode: evaluate_resources() processes pre-fetched resources

    For backward compatibility, rules only need to implement evaluate().
    For optimized scanning, rules should implement evaluate_resources().
    """

    rule_id: str = ""
    name: str = ""
    description: str = ""
    resource_type: str = ""
    severity: Severity = Severity.MEDIUM
    has_remediation: bool = False
    remediation_tested: bool = False  # Set to True after remediation has been verified in production

    # Set to True if the rule supports the optimized evaluate_resources() method
    supports_prefetch: bool = False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """
        Evaluate the rule against resources in the given region.

        This is the legacy method that fetches resources directly.
        Rules that set supports_prefetch=True should implement evaluate_resources() instead.

        Args:
            session: boto3 session (possibly assumed role)
            region: AWS region to scan

        Returns:
            List of RuleResult for each resource evaluated
        """
        # Default implementation for rules that only implement evaluate_resources()
        # This should not be called directly for prefetch-enabled rules
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement evaluate(). "
            f"Use evaluate_resources() instead (supports_prefetch={self.supports_prefetch})"
        )

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """
        Evaluate the rule against pre-fetched resources.

        This is the optimized method that uses pre-fetched resource data.
        Rules should implement this method to avoid redundant AWS API calls.

        Args:
            resources: List of pre-fetched resources matching this rule's resource_type
            session: boto3 session (for any additional API calls if needed)
            region: AWS region

        Returns:
            List of RuleResult for each resource evaluated
        """
        # Default implementation falls back to legacy evaluate()
        # Rules should override this to use pre-fetched data
        return await self.evaluate(session, region)

    async def remediate(self, session, resource_id: str, region: str, finding_details: Dict[str, Any] = None) -> bool:
        """
        Remediate a non-compliant resource.

        Args:
            session: boto3 session
            resource_id: AWS resource ARN or ID
            region: AWS region
            finding_details: Optional dict containing the finding details (resource attributes)

        Returns:
            True if remediation succeeded
        """
        raise NotImplementedError("Remediation not implemented for this rule")

    @classmethod
    def get_remediation_description(cls) -> str:
        """Get a human-readable description of what remediation does."""
        return "No remediation available"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        """Get the expected state after remediation."""
        return {}
