"""JIRA notification service for compliance findings."""
import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import httpx
from sqlalchemy import select

from app.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

# Default timeout for JIRA API requests
DEFAULT_TIMEOUT = 30.0
# Max concurrent ticket creations to avoid overwhelming JIRA API
MAX_CONCURRENT_TICKETS = 5

# Severity priority for comparison (higher number = more severe)
SEVERITY_PRIORITY = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# JIRA priority mapping from severity
SEVERITY_TO_JIRA_PRIORITY = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Lowest",
}

# Due date offsets in days based on severity
SEVERITY_DUE_DAYS = {
    "CRITICAL": 15,
    "HIGH": 30,
    "MEDIUM": 60,
    "LOW": 90,
    "INFO": 120,
}

def _format_datetime(dt: Optional[datetime]) -> Optional[str]:
    """Format datetime for JIRA (ISO 8601)."""
    if dt:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    return None


def _parse_datetime(value) -> Optional[datetime]:
    """Parse datetime from string or return as-is if already datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None


# AWS Security Hub custom field IDs (from compscience.atlassian.net)
AWS_CUSTOM_FIELDS = {
    "aws_account": "customfield_10338",
    "aws_region": "customfield_10342",
    "aws_finding_created_at": "customfield_10339",
    "aws_finding_modified_at": "customfield_10352",
    "aws_finding_last_seen_at": "customfield_10341",
    "aws_finding_first_seen_at": "customfield_10347",
    "aws_finding_source": "customfield_10348",
    "aws_finding_id": "customfield_10343",
    "aws_compliance_status": "customfield_10340",
    "aws_finding_status": "customfield_10351",
    "aws_finding_verification_state": "customfield_10349",
    "aws_finding_remediation_text": "customfield_10353",
    "aws_finding_remediation_urls": "customfield_10344",
    "aws_finding_related_findings": "customfield_10345",
    "aws_finding_ocsf_json": "customfield_10346",
    "aws_finding_resources": "customfield_10350",
}


class JiraNotifier:
    """Handles JIRA ticket creation for compliance findings."""

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str,
        issue_type: str = "Security Issue",
        min_severity: str = "CRITICAL",
        assignee_email: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
    ):
        """
        Initialize the JIRA notifier.

        Args:
            base_url: JIRA Cloud instance URL (e.g., https://yourcompany.atlassian.net)
            email: JIRA account email
            api_token: JIRA API token
            project_key: JIRA project key for ticket creation
            issue_type: Issue type name (default: "Security Issue")
            min_severity: Minimum severity to create tickets for
            assignee_email: Email of user to assign new tickets to
            client: Optional shared httpx.AsyncClient for connection reuse
        """
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.api_token = api_token
        self.project_key = project_key
        self.issue_type = issue_type
        self.min_severity = min_severity
        self.assignee_email = assignee_email
        self._assignee_account_id: Optional[str] = None  # Cached account ID
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self):
        """Context manager entry - create client if not provided."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close client if we created it."""
        if self._owns_client and self._client:
            await self._client.aclose()
            self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        """Get the HTTP client, creating one if needed."""
        if self._client is None:
            # Fallback for non-context-manager usage
            self._client = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
            self._owns_client = True
        return self._client

    def should_notify(self, severity: str) -> bool:
        """Check if the finding severity meets the minimum threshold."""
        finding_priority = SEVERITY_PRIORITY.get(severity, 0)
        min_priority = SEVERITY_PRIORITY.get(self.min_severity, 4)
        return finding_priority >= min_priority

    def _get_auth(self) -> tuple:
        """Get basic auth tuple for JIRA API."""
        return (self.email, self.api_token)

    def _calculate_due_date(self, severity: str) -> str:
        """Calculate due date based on severity."""
        days = SEVERITY_DUE_DAYS.get(severity, 90)
        due_date = datetime.utcnow() + timedelta(days=days)
        return due_date.strftime("%Y-%m-%d")

    async def _get_assignee_account_id(self) -> Optional[str]:
        """
        Look up the JIRA account ID for the configured assignee email.

        Returns:
            Account ID string if found, None otherwise
        """
        if not self.assignee_email:
            return None

        # Return cached value if available
        if self._assignee_account_id:
            return self._assignee_account_id

        try:
            client = self._get_client()
            # Search for user by email
            response = await client.get(
                f"{self.base_url}/rest/api/3/user/search",
                params={"query": self.assignee_email},
                auth=self._get_auth(),
            )
            response.raise_for_status()
            users = response.json()

            if users:
                # Find exact email match
                for user in users:
                    if user.get("emailAddress", "").lower() == self.assignee_email.lower():
                        self._assignee_account_id = user.get("accountId")
                        logger.info(f"Found JIRA account ID for {self.assignee_email}: {self._assignee_account_id}")
                        return self._assignee_account_id

                # Fall back to first result if no exact match
                self._assignee_account_id = users[0].get("accountId")
                logger.info(f"Using first match for {self.assignee_email}: {self._assignee_account_id}")
                return self._assignee_account_id

            logger.warning(f"No JIRA user found for email: {self.assignee_email}")
            return None

        except Exception as e:
            logger.error(f"Failed to look up JIRA account ID for {self.assignee_email}: {e}")
            return None

    async def _check_finding_ticket_exists(self, finding_id: str) -> Optional[dict]:
        """
        Check if a ticket already exists for this finding.

        Args:
            finding_id: Unique finding identifier

        Returns:
            Dict with 'key' and 'status' if exists, None otherwise
        """
        # Search by finding-id label (more reliable than custom field search)
        jql = f'project = "{self.project_key}" AND labels = "finding-{finding_id}"'

        try:
            client = self._get_client()
            # Use new /search/jql endpoint (JIRA deprecated /search in 2024)
            response = await client.post(
                f"{self.base_url}/rest/api/3/search/jql",
                json={"jql": jql, "maxResults": 1, "fields": ["status"]},
                auth=self._get_auth(),
            )
            response.raise_for_status()
            data = response.json()

            if data.get("issues"):
                issue = data["issues"][0]
                return {
                    "key": issue["key"],
                    "status": issue["fields"]["status"]["name"],
                }
            return None

        except Exception as e:
            logger.error(f"Failed to check for existing finding ticket: {e}")
            return None

    async def _transition_ticket(self, issue_key: str, transition_id: str) -> bool:
        """
        Transition a ticket to a new status.

        Args:
            issue_key: JIRA issue key (e.g., CORE-123)
            transition_id: Transition ID to execute

        Returns:
            True if successful
        """
        try:
            client = self._get_client()
            response = await client.post(
                f"{self.base_url}/rest/api/3/issue/{issue_key}/transitions",
                json={"transition": {"id": transition_id}},
                auth=self._get_auth(),
            )
            response.raise_for_status()
            logger.info(f"Transitioned {issue_key} using transition {transition_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to transition {issue_key}: {e}")
            return False

    async def _add_comment(self, issue_key: str, comment: str) -> bool:
        """
        Add a comment to a JIRA ticket.

        Args:
            issue_key: JIRA issue key
            comment: Comment text

        Returns:
            True if successful
        """
        try:
            client = self._get_client()
            response = await client.post(
                f"{self.base_url}/rest/api/3/issue/{issue_key}/comment",
                json={
                    "body": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [{"type": "text", "text": comment}]
                            }
                        ]
                    }
                },
                auth=self._get_auth(),
            )
            response.raise_for_status()
            logger.info(f"Added comment to {issue_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to add comment to {issue_key}: {e}")
            return False

    async def _update_custom_fields(self, issue_key: str, fields: dict) -> bool:
        """
        Update custom fields on a JIRA ticket.

        Args:
            issue_key: JIRA issue key
            fields: Dict of field IDs to values

        Returns:
            True if successful
        """
        try:
            client = self._get_client()
            response = await client.put(
                f"{self.base_url}/rest/api/3/issue/{issue_key}",
                json={"fields": fields},
                auth=self._get_auth(),
            )
            response.raise_for_status()
            logger.info(f"Updated custom fields on {issue_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to update custom fields on {issue_key}: {e}")
            return False

    async def _reopen_ticket_for_regression(self, issue_key: str, status: str) -> bool:
        """
        Reopen a closed ticket for a regression finding.

        Args:
            issue_key: JIRA issue key
            status: Current ticket status

        Returns:
            True if ticket was reopened or already open
        """
        # Statuses that indicate the ticket is "closed" and needs reopening
        # Exact names from your workflow: RELEASED, REJECTED, CLOSED
        closed_statuses = {
            "RELEASED", "REJECTED", "CLOSED",
            "Released", "Rejected", "Closed",
            "Done", "Resolved",
        }

        if status not in closed_statuses:
            logger.info(f"Ticket {issue_key} is already open (status: {status})")
            return True

        # Find and use Intake transition dynamically
        transitions = await self._get_available_transitions(issue_key)
        intake_transition = None

        # Look for Intake transition (exact name from your workflow)
        intake_names = {"INTAKE", "Intake", "Reopen", "Re-open", "Open", "To Do", "Backlog"}
        for t in transitions:
            if t.get("name") in intake_names:
                intake_transition = t
                break

        if intake_transition:
            success = await self._transition_ticket(issue_key, intake_transition["id"])
            if success:
                logger.info(f"Reopened ticket {issue_key} from {status} to {intake_transition['name']}")
            return success
        else:
            available = [t.get("name") for t in transitions]
            logger.warning(f"No 'Intake' transition found for {issue_key}. Available: {available}")
            return False

    async def _get_available_transitions(self, issue_key: str) -> List[dict]:
        """
        Get available transitions for a ticket.

        Args:
            issue_key: JIRA issue key

        Returns:
            List of available transitions with 'id' and 'name'
        """
        try:
            client = self._get_client()
            response = await client.get(
                f"{self.base_url}/rest/api/3/issue/{issue_key}/transitions",
                auth=self._get_auth(),
            )
            response.raise_for_status()
            data = response.json()
            return data.get("transitions", [])
        except Exception as e:
            logger.error(f"Failed to get transitions for {issue_key}: {e}")
            return []

    def _find_close_transition(self, transitions: List[dict]) -> Optional[dict]:
        """
        Find the best transition to close a ticket, preferring CLOSED over RELEASED.

        Args:
            transitions: List of available transitions from JIRA

        Returns:
            The best matching transition dict, or None if not found
        """
        # Ordered list of preferred transition names (first match wins)
        # CLOSED is preferred over RELEASED
        preferred_names = [
            "CLOSED", "Closed", "Close",
            "Done", "Resolve Issue", "Resolved", "Close Issue", "Complete",
            "RELEASED", "Released", "Release",
            "REJECTED", "Rejected", "Reject",
        ]

        # Build a map of transition names to transitions
        transition_map = {t.get("name"): t for t in transitions}

        # Find first matching preferred transition
        for name in preferred_names:
            if name in transition_map:
                return transition_map[name]

        return None

    async def resolve_ticket_for_remediation(
        self,
        issue_key: str,
        resource_name: str,
        remediation_action: str,
        performed_by: str = "system",
    ) -> bool:
        """
        Resolve/close a JIRA ticket after successful auto-remediation.

        This method:
        1. Checks if ticket is already resolved
        2. Adds a comment documenting the remediation
        3. Transitions to Done/Resolved status
        4. Updates custom fields

        Args:
            issue_key: JIRA issue key (e.g., "CORE-123")
            resource_name: Name of the remediated resource
            remediation_action: Description of the remediation action taken
            performed_by: User who initiated the remediation

        Returns:
            True if ticket was resolved (or already resolved), False on error
        """
        now = datetime.utcnow()

        try:
            client = self._get_client()

            # Get current ticket status
            response = await client.get(
                f"{self.base_url}/rest/api/3/issue/{issue_key}",
                params={"fields": "status"},
                auth=self._get_auth(),
            )
            response.raise_for_status()
            data = response.json()
            current_status = data["fields"]["status"]["name"]

            # Check if already resolved (exact names from your JIRA workflow)
            resolved_statuses = {"RELEASED", "REJECTED", "CLOSED", "Released", "Rejected", "Closed", "Done", "Resolved"}
            if current_status in resolved_statuses:
                logger.info(f"Ticket {issue_key} is already resolved (status: {current_status})")
                return True

            # Add comment about remediation
            remediation_comment = (
                f"✅ Auto-Remediation Completed\n\n"
                f"Resource: {resource_name}\n"
                f"Action: {remediation_action}\n"
                f"Performed by: {performed_by}\n"
                f"Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                f"The compliance issue has been automatically remediated and verified."
            )
            await self._add_comment(issue_key, remediation_comment)

            # Update timestamp fields (status fields are read-only in JIRA)
            await self._update_custom_fields(issue_key, {
                AWS_CUSTOM_FIELDS["aws_finding_modified_at"]: _format_datetime(now),
                AWS_CUSTOM_FIELDS["aws_finding_last_seen_at"]: _format_datetime(now),
            })

            # Find a transition to close the ticket (prefers CLOSED over RELEASED)
            transitions = await self._get_available_transitions(issue_key)
            done_transition = self._find_close_transition(transitions)

            if done_transition:
                success = await self._transition_ticket(issue_key, done_transition["id"])
                if success:
                    logger.info(f"Resolved ticket {issue_key} via transition '{done_transition['name']}' after remediation")
                    return True
                else:
                    logger.warning(f"Failed to transition {issue_key}, but comment was added")
                    return False
            else:
                available = [t.get("name") for t in transitions]
                logger.warning(f"No 'Done' transition found for {issue_key}. Available: {available}")
                # Comment was still added, so partial success
                return True

        except Exception as e:
            logger.error(f"Failed to resolve ticket {issue_key} for remediation: {e}")
            return False

    async def close_ticket_for_rescan_pass(
        self,
        issue_key: str,
        resource_name: str,
        rule_name: str,
    ) -> bool:
        """
        Close a JIRA ticket when a rescan shows the resource is now compliant.

        Args:
            issue_key: JIRA issue key (e.g., "CORE-123")
            resource_name: Name of the resource that now passes
            rule_name: Name of the compliance rule

        Returns:
            True if ticket was closed (or already closed), False on error
        """
        now = datetime.utcnow()

        try:
            client = self._get_client()

            # Get current ticket status
            response = await client.get(
                f"{self.base_url}/rest/api/3/issue/{issue_key}",
                params={"fields": "status"},
                auth=self._get_auth(),
            )
            response.raise_for_status()
            data = response.json()
            current_status = data["fields"]["status"]["name"]

            # Check if already resolved
            resolved_statuses = {"RELEASED", "REJECTED", "CLOSED", "Released", "Rejected", "Closed", "Done", "Resolved"}
            if current_status in resolved_statuses:
                logger.info(f"Ticket {issue_key} is already closed (status: {current_status})")
                return True

            # Add comment about rescan pass
            rescan_comment = (
                f"✅ Rescan Passed\n\n"
                f"Resource: {resource_name}\n"
                f"Rule: {rule_name}\n"
                f"Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                f"The resource is now compliant. Closing ticket."
            )
            await self._add_comment(issue_key, rescan_comment)

            # Update timestamp fields (status fields are read-only in JIRA)
            await self._update_custom_fields(issue_key, {
                AWS_CUSTOM_FIELDS["aws_finding_modified_at"]: _format_datetime(now),
                AWS_CUSTOM_FIELDS["aws_finding_last_seen_at"]: _format_datetime(now),
            })

            # Find a transition to close the ticket (prefers CLOSED over RELEASED)
            transitions = await self._get_available_transitions(issue_key)
            done_transition = self._find_close_transition(transitions)

            if done_transition:
                success = await self._transition_ticket(issue_key, done_transition["id"])
                if success:
                    logger.info(f"Closed ticket {issue_key} via transition '{done_transition['name']}' after rescan pass")
                    return True
                else:
                    logger.warning(f"Failed to transition {issue_key}, but comment was added")
                    return False
            else:
                available = [t.get("name") for t in transitions]
                logger.warning(f"No 'Close' transition found for {issue_key}. Available: {available}")
                return True

        except Exception as e:
            logger.error(f"Failed to close ticket {issue_key} for rescan pass: {e}")
            return False

    async def close_ticket_for_exception(
        self,
        issue_key: str,
        resource_name: str,
        justification: str,
        created_by: str = "system",
    ) -> bool:
        """
        Close a JIRA ticket when an exception is created for the finding.

        Sets AWS Finding Status to "EXCEPTION" to indicate the finding
        was explicitly excepted rather than remediated.

        Args:
            issue_key: JIRA issue key (e.g., "CORE-123")
            resource_name: Name of the resource with exception
            justification: Justification for the exception
            created_by: User who created the exception

        Returns:
            True if ticket was closed (or already closed), False on error
        """
        now = datetime.utcnow()

        try:
            client = self._get_client()

            # Get current ticket status
            response = await client.get(
                f"{self.base_url}/rest/api/3/issue/{issue_key}",
                params={"fields": "status"},
                auth=self._get_auth(),
            )
            response.raise_for_status()
            data = response.json()
            current_status = data["fields"]["status"]["name"]

            # Check if already resolved
            resolved_statuses = {"RELEASED", "REJECTED", "CLOSED", "Released", "Rejected", "Closed", "Done", "Resolved"}
            if current_status in resolved_statuses:
                logger.info(f"Ticket {issue_key} is already closed (status: {current_status})")
                # Update timestamp (status fields are read-only in JIRA)
                await self._update_custom_fields(issue_key, {
                    AWS_CUSTOM_FIELDS["aws_finding_modified_at"]: _format_datetime(now),
                })
                return True

            # Add comment about exception
            exception_comment = (
                f"🔕 Exception Created\n\n"
                f"Resource: {resource_name}\n"
                f"Justification: {justification}\n"
                f"Created by: {created_by}\n"
                f"Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                f"An exception has been granted for this finding. Closing ticket."
            )
            await self._add_comment(issue_key, exception_comment)

            # Update timestamp fields (status fields are read-only in JIRA)
            await self._update_custom_fields(issue_key, {
                AWS_CUSTOM_FIELDS["aws_finding_modified_at"]: _format_datetime(now),
                AWS_CUSTOM_FIELDS["aws_finding_last_seen_at"]: _format_datetime(now),
            })

            # Find a transition to close the ticket (prefers CLOSED over RELEASED)
            transitions = await self._get_available_transitions(issue_key)
            done_transition = self._find_close_transition(transitions)

            if done_transition:
                success = await self._transition_ticket(issue_key, done_transition["id"])
                if success:
                    logger.info(f"Closed ticket {issue_key} via transition '{done_transition['name']}' after exception created")
                    return True
                else:
                    logger.warning(f"Failed to transition {issue_key}, but comment was added")
                    return False
            else:
                available = [t.get("name") for t in transitions]
                logger.warning(f"No 'Close' transition found for {issue_key}. Available: {available}")
                return True

        except Exception as e:
            logger.error(f"Failed to close ticket {issue_key} for exception: {e}")
            return False

    async def reopen_ticket_for_exception_deleted(
        self,
        issue_key: str,
        resource_name: str,
    ) -> bool:
        """
        Reopen a JIRA ticket when the exception for a finding is deleted.

        Args:
            issue_key: JIRA issue key (e.g., "CORE-123")
            resource_name: Name of the resource

        Returns:
            True if ticket was reopened (or already open), False on error
        """
        now = datetime.utcnow()

        try:
            client = self._get_client()

            # Get current ticket status
            response = await client.get(
                f"{self.base_url}/rest/api/3/issue/{issue_key}",
                params={"fields": "status"},
                auth=self._get_auth(),
            )
            response.raise_for_status()
            data = response.json()
            current_status = data["fields"]["status"]["name"]

            # Use existing reopen logic
            reopened = await self._reopen_ticket_for_regression(issue_key, current_status)

            # Add comment about exception deletion
            comment = (
                f"🔄 Exception Deleted\n\n"
                f"Resource: {resource_name}\n"
                f"Timestamp: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                f"The exception for this finding has been removed. Ticket reopened."
            )
            await self._add_comment(issue_key, comment)

            # Update timestamp
            await self._update_custom_fields(issue_key, {
                AWS_CUSTOM_FIELDS["aws_finding_modified_at"]: _format_datetime(now),
            })

            if reopened:
                logger.info(f"Reopened ticket {issue_key} after exception deleted")
            else:
                logger.info(f"Ticket {issue_key} was already open after exception deleted")

            return True

        except Exception as e:
            logger.error(f"Failed to reopen ticket {issue_key} for exception deletion: {e}")
            return False

    async def create_finding_ticket(
        self,
        finding_id: str,
        finding_type: str,
        rule_id: str,
        rule_name: str,
        rule_description: str,
        rule_severity: str,
        resource_id: str,
        resource_name: str,
        resource_type: str,
        account_id: str,
        region: str,
        created_at: Optional[datetime] = None,
        first_seen_at: Optional[datetime] = None,
        details: Optional[dict] = None,
        remediation_text: Optional[str] = None,
        skip_duplicate_check: bool = False,
        existing_ticket_key: Optional[str] = None,
    ) -> Optional[str]:
        """
        Create a JIRA ticket for a compliance finding with AWS custom fields.

        Args:
            finding_id: Unique finding identifier (UUID)
            finding_type: Type of finding ("new" or "regression")
            rule_id: Unique rule identifier
            rule_name: Human-readable rule name
            rule_description: Rule description
            rule_severity: Severity level
            resource_id: AWS resource ID
            resource_name: Human-readable resource name
            resource_type: Type of AWS resource
            account_id: AWS account ID
            region: AWS region
            created_at: When the finding was created
            first_seen_at: When the finding was first seen
            details: Additional finding details
            remediation_text: How to remediate the finding
            skip_duplicate_check: Skip checking for existing ticket (caller handles it)
            existing_ticket_key: Known ticket key from DB (skips JIRA API search)

        Returns:
            JIRA issue key of created/updated ticket, or None if failed/skipped
        """
        now = datetime.utcnow()

        # If we have a known ticket key from DB, use it directly (faster, no API call)
        if existing_ticket_key:
            if finding_type == "regression":
                logger.info(f"Using stored ticket key {existing_ticket_key} for regression (skipping JIRA search)")
                # Get current status to determine if reopening is needed
                try:
                    client = self._get_client()
                    response = await client.get(
                        f"{self.base_url}/rest/api/3/issue/{existing_ticket_key}",
                        params={"fields": "status"},
                        auth=self._get_auth(),
                    )
                    response.raise_for_status()
                    data = response.json()
                    status = data["fields"]["status"]["name"]

                    # Reopen if closed
                    await self._reopen_ticket_for_regression(existing_ticket_key, status)

                    # Update timestamp fields (status fields are read-only in JIRA)
                    await self._update_custom_fields(existing_ticket_key, {
                        AWS_CUSTOM_FIELDS["aws_finding_last_seen_at"]: _format_datetime(now),
                        AWS_CUSTOM_FIELDS["aws_finding_modified_at"]: _format_datetime(now),
                    })

                    # Add regression comment
                    regression_comment = (
                        f"⚠️ Finding Regression Detected\n\n"
                        f"This finding has regressed (resource is failing again).\n"
                        f"Detected: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                    )
                    await self._add_comment(existing_ticket_key, regression_comment)

                    logger.info(f"Updated existing ticket {existing_ticket_key} for regression")
                    return existing_ticket_key
                except Exception as e:
                    logger.error(f"Failed to update stored ticket {existing_ticket_key}: {e}")
                    # Fall through to API search as fallback
            else:
                # New finding but we have a stored ticket - skip creation
                logger.info(f"Ticket {existing_ticket_key} already stored for finding {finding_id}, skipping")
                return None

        # Check if ticket already exists for this finding (API search fallback)
        if not skip_duplicate_check:
            existing = await self._check_finding_ticket_exists(finding_id)
            if existing:
                issue_key = existing["key"]
                status = existing["status"]

                if finding_type == "regression":
                    # Reopen the ticket if it was closed
                    logger.info(f"Found existing ticket {issue_key} (status: {status}) for regression finding")
                    await self._reopen_ticket_for_regression(issue_key, status)

                    # Update timestamp fields (status fields are read-only in JIRA)
                    await self._update_custom_fields(issue_key, {
                        AWS_CUSTOM_FIELDS["aws_finding_last_seen_at"]: _format_datetime(now),
                        AWS_CUSTOM_FIELDS["aws_finding_modified_at"]: _format_datetime(now),
                    })

                    # Add a comment about the regression
                    regression_comment = (
                        f"⚠️ Finding Regression Detected\n\n"
                        f"This finding has regressed (resource is failing again).\n"
                        f"Detected: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                    )
                    await self._add_comment(issue_key, regression_comment)

                    logger.info(f"Updated existing ticket {issue_key} for regression")
                    return issue_key
                else:
                    # New finding but ticket exists - just skip
                    logger.info(f"Ticket {issue_key} already exists for finding {finding_id}, skipping")
                    return None

        # Build description content
        description_content = [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": f"{'New Finding' if finding_type == 'new' else 'Regression'}: ",
                        "marks": [{"type": "strong"}]
                    },
                    {
                        "type": "text",
                        "text": rule_description or rule_name,
                    }
                ]
            },
            {
                "type": "heading",
                "attrs": {"level": 3},
                "content": [{"type": "text", "text": "Resource Details"}]
            },
            {
                "type": "bulletList",
                "content": [
                    {
                        "type": "listItem",
                        "content": [{"type": "paragraph", "content": [
                            {"type": "text", "text": "Resource ID: ", "marks": [{"type": "strong"}]},
                            {"type": "text", "text": resource_id, "marks": [{"type": "code"}]}
                        ]}]
                    },
                    {
                        "type": "listItem",
                        "content": [{"type": "paragraph", "content": [
                            {"type": "text", "text": "Resource Name: ", "marks": [{"type": "strong"}]},
                            {"type": "text", "text": resource_name}
                        ]}]
                    },
                    {
                        "type": "listItem",
                        "content": [{"type": "paragraph", "content": [
                            {"type": "text", "text": "Resource Type: ", "marks": [{"type": "strong"}]},
                            {"type": "text", "text": resource_type}
                        ]}]
                    },
                    {
                        "type": "listItem",
                        "content": [{"type": "paragraph", "content": [
                            {"type": "text", "text": "Rule: ", "marks": [{"type": "strong"}]},
                            {"type": "text", "text": f"{rule_name} ({rule_id})"}
                        ]}]
                    },
                ]
            },
        ]

        # Add remediation if present
        if remediation_text:
            description_content.append({
                "type": "heading",
                "attrs": {"level": 3},
                "content": [{"type": "text", "text": "Remediation"}]
            })
            description_content.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": remediation_text}]
            })

        # Add details if present
        if details:
            details_items = []
            for key, value in details.items():
                if value is not None:
                    details_items.append({
                        "type": "listItem",
                        "content": [{"type": "paragraph", "content": [
                            {"type": "text", "text": f"{key}: ", "marks": [{"type": "strong"}]},
                            {"type": "text", "text": str(value)[:500]}
                        ]}]
                    })

            if details_items:
                description_content.append({
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Additional Details"}]
                })
                description_content.append({
                    "type": "bulletList",
                    "content": details_items
                })

        priority = SEVERITY_TO_JIRA_PRIORITY.get(rule_severity, "Medium")
        due_date = self._calculate_due_date(rule_severity)

        # Look up assignee account ID if configured
        assignee_account_id = await self._get_assignee_account_id()

        # Determine if issue_type is an ID (numeric) or name
        issue_type_field = {"id": self.issue_type} if self.issue_type.isdigit() else {"name": self.issue_type}

        # Determine if project_key is an ID (numeric) or key
        project_field = {"id": self.project_key} if self.project_key.isdigit() else {"key": self.project_key}

        # Build payload with AWS custom fields
        payload = {
            "fields": {
                "project": project_field,
                "summary": f"[{rule_severity}] {rule_name}: {resource_name}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": description_content,
                },
                "issuetype": issue_type_field,
                "priority": {"name": priority},
                "duedate": due_date,
                "labels": [
                    f"finding-{finding_id}",  # Used for duplicate detection
                    f"rule-{rule_id}",
                    f"severity-{rule_severity.lower()}",
                    f"account-{account_id}",
                    f"region-{region}",
                    "compliance",
                    "auto-created",
                    "new-finding" if finding_type == "new" else "regression",
                ],
                # AWS Custom Fields
                AWS_CUSTOM_FIELDS["aws_account"]: account_id,
                AWS_CUSTOM_FIELDS["aws_region"]: region,
                AWS_CUSTOM_FIELDS["aws_finding_id"]: finding_id,
                AWS_CUSTOM_FIELDS["aws_finding_source"]: "AWS Compliance Dashboard",
                AWS_CUSTOM_FIELDS["aws_compliance_status"]: "FAILED",
                AWS_CUSTOM_FIELDS["aws_finding_status"]: "NEW" if finding_type == "new" else "REGRESSION",
                AWS_CUSTOM_FIELDS["aws_finding_created_at"]: _format_datetime(created_at or now),
                AWS_CUSTOM_FIELDS["aws_finding_first_seen_at"]: _format_datetime(first_seen_at or created_at or now),
                AWS_CUSTOM_FIELDS["aws_finding_last_seen_at"]: _format_datetime(now),
                AWS_CUSTOM_FIELDS["aws_finding_modified_at"]: _format_datetime(now),
                AWS_CUSTOM_FIELDS["aws_finding_resources"]: {"Type": resource_type, "Id": resource_id},
            }
        }

        # Add optional fields if provided
        if remediation_text:
            payload["fields"][AWS_CUSTOM_FIELDS["aws_finding_remediation_text"]] = remediation_text

        # Add assignee if configured
        if assignee_account_id:
            payload["fields"]["assignee"] = {"accountId": assignee_account_id}

        try:
            client = self._get_client()
            response = await client.post(
                f"{self.base_url}/rest/api/3/issue",
                json=payload,
                auth=self._get_auth(),
            )
            response.raise_for_status()
            data = response.json()
            issue_key = data["key"]
            logger.info(f"Created JIRA ticket {issue_key} for finding: {rule_name} - {resource_name}")
            return issue_key

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to create JIRA ticket: {e.response.status_code} - {e.response.text}")
            return None
        except Exception as e:
            logger.error(f"Failed to create JIRA ticket: {e}")
            return None

    async def test_connection(self) -> tuple[bool, str]:
        """
        Test the JIRA connection and project access.

        Returns:
            Tuple of (success, message)
        """
        try:
            client = self._get_client()
            # Test authentication by getting current user
            response = await client.get(
                f"{self.base_url}/rest/api/3/myself",
                auth=self._get_auth(),
            )
            response.raise_for_status()
            user_data = response.json()

            # Test project access
            response = await client.get(
                f"{self.base_url}/rest/api/3/project/{self.project_key}",
                auth=self._get_auth(),
            )
            response.raise_for_status()
            project_data = response.json()

            return True, f"Connected as {user_data.get('displayName', user_data.get('emailAddress'))} to project {project_data.get('name')}"

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                return False, "Authentication failed. Check email and API token."
            elif e.response.status_code == 404:
                return False, f"Project '{self.project_key}' not found or you don't have access."
            else:
                return False, f"JIRA API error: {e.response.status_code} - {e.response.text}"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

    async def get_issue_types(self) -> List[dict]:
        """
        Fetch available issue types for the configured project.

        Returns:
            List of issue type dicts with 'id', 'name', and 'subtask' fields
        """
        try:
            client = self._get_client()
            response = await client.get(
                f"{self.base_url}/rest/api/3/issue/createmeta/{self.project_key}/issuetypes",
                auth=self._get_auth(),
            )
            response.raise_for_status()
            data = response.json()

            issue_types = []
            for it in data.get("issueTypes", []):
                # Skip sub-task types as they can't be parent tickets
                if not it.get("subtask", False):
                    issue_types.append({
                        "id": it.get("id"),
                        "name": it.get("name"),
                        "description": it.get("description", ""),
                    })

            return issue_types

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to fetch JIRA issue types: {e.response.status_code} - {e.response.text}")
            return []
        except Exception as e:
            logger.error(f"Failed to fetch JIRA issue types: {e}")
            return []

    async def get_custom_fields(self) -> List[dict]:
        """
        Fetch all custom fields from JIRA.

        Returns:
            List of custom field dicts with 'id', 'name', and 'schema' fields
        """
        try:
            client = self._get_client()
            response = await client.get(
                f"{self.base_url}/rest/api/3/field",
                auth=self._get_auth(),
            )
            response.raise_for_status()
            fields = response.json()

            # Filter to only custom fields and format response
            custom_fields = []
            for field in fields:
                if field.get("custom", False):
                    custom_fields.append({
                        "id": field.get("id"),  # e.g., "customfield_10001"
                        "name": field.get("name"),  # e.g., "AWS Account"
                        "type": field.get("schema", {}).get("type", "unknown"),
                        "custom_type": field.get("schema", {}).get("custom", ""),
                    })

            # Sort by name for easier reading
            custom_fields.sort(key=lambda x: x["name"])
            return custom_fields

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to fetch JIRA custom fields: {e.response.status_code} - {e.response.text}")
            return []
        except Exception as e:
            logger.error(f"Failed to fetch JIRA custom fields: {e}")
            return []

    async def get_boards(self) -> List[dict]:
        """
        Fetch all boards the user has access to.

        Returns:
            List of board dicts with 'id', 'name', and 'type' fields
        """
        try:
            client = self._get_client()
            response = await client.get(
                f"{self.base_url}/rest/agile/1.0/board",
                params={"projectKeyOrId": self.project_key},
                auth=self._get_auth(),
            )
            response.raise_for_status()
            data = response.json()

            boards = []
            for board in data.get("values", []):
                boards.append({
                    "id": board.get("id"),
                    "name": board.get("name"),
                    "type": board.get("type"),  # scrum, kanban, etc.
                })

            return boards

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to fetch JIRA boards: {e.response.status_code} - {e.response.text}")
            return []
        except Exception as e:
            logger.error(f"Failed to fetch JIRA boards: {e}")
            return []


@dataclass
class JiraConfigData:
    """JIRA configuration data (from DB or env vars)."""
    base_url: Optional[str]
    email: Optional[str]
    api_token: Optional[str]
    project_key: Optional[str]
    issue_type: str
    is_enabled: bool
    min_severity: str
    notify_on_new_findings: bool
    notify_on_regression: bool
    assignee_email: Optional[str] = None


def get_jira_config_from_env() -> Optional[JiraConfigData]:
    """Get JIRA configuration from environment variables."""
    base_url = os.environ.get("JIRA_BASE_URL")
    email = os.environ.get("JIRA_EMAIL")
    api_token = os.environ.get("JIRA_API_TOKEN")
    project_key = os.environ.get("JIRA_PROJECT_KEY")

    # Only return env config if at least the base credentials are set
    if not any([base_url, email, api_token, project_key]):
        return None

    return JiraConfigData(
        base_url=base_url,
        email=email,
        api_token=api_token,
        project_key=project_key,
        issue_type=os.environ.get("JIRA_ISSUE_TYPE", "Bug"),
        is_enabled=os.environ.get("JIRA_ENABLED", "false").lower() == "true",
        min_severity=os.environ.get("JIRA_MIN_SEVERITY", "CRITICAL"),
        notify_on_new_findings=os.environ.get("JIRA_NOTIFY_NEW", "true").lower() == "true",
        notify_on_regression=os.environ.get("JIRA_NOTIFY_REGRESSION", "true").lower() == "true",
        assignee_email=os.environ.get("JIRA_ASSIGNEE_EMAIL"),
    )


async def get_jira_config() -> Optional[JiraConfigData]:
    """
    Get JIRA notification configuration.

    Credentials (base_url, email, api_token, project_key, issue_type):
      - Environment variables ALWAYS take precedence if set
      - Falls back to database credentials only if env vars not configured

    Runtime settings (is_enabled, min_severity, notify_on_*):
      - Database takes precedence if an entry exists
      - Falls back to environment variables otherwise
    """
    from app.models.jira_config import JiraConfig

    # Get environment config first (credentials from env always take precedence)
    env_config = get_jira_config_from_env()

    # Check database for settings
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(JiraConfig).where(JiraConfig.config_key == "jira")
        )
        db_config = result.scalar_one_or_none()

        # Env credentials always take precedence if configured
        if env_config and env_config.base_url:
            if db_config:
                # Env credentials + DB runtime settings
                logger.info(f"Using JIRA credentials from env (override), settings from database: is_enabled={db_config.is_enabled}")
                return JiraConfigData(
                    base_url=env_config.base_url,
                    email=env_config.email,
                    api_token=env_config.api_token,
                    project_key=env_config.project_key,
                    issue_type=env_config.issue_type,
                    is_enabled=db_config.is_enabled,
                    min_severity=db_config.min_severity,
                    notify_on_new_findings=db_config.notify_on_new_findings,
                    notify_on_regression=db_config.notify_on_regression,
                    assignee_email=env_config.assignee_email,
                )
            else:
                # Pure env config
                logger.info(f"Using JIRA config from environment: is_enabled={env_config.is_enabled}, project={env_config.project_key}")
                return env_config

        # Fall back to database credentials if env not configured
        if db_config and db_config.base_url:
            logger.info(f"Using JIRA config from database (no env override): is_enabled={db_config.is_enabled}, project={db_config.project_key}")
            return JiraConfigData(
                base_url=db_config.base_url,
                email=db_config.email,
                api_token=db_config.api_token,
                project_key=db_config.project_key,
                issue_type=db_config.issue_type or "Bug",
                is_enabled=db_config.is_enabled,
                min_severity=db_config.min_severity,
                notify_on_new_findings=db_config.notify_on_new_findings,
                notify_on_regression=db_config.notify_on_regression,
                assignee_email=getattr(db_config, 'assignee_email', None),
            )

    logger.info("No JIRA configuration found in database or environment")
    return None


@dataclass
class JiraTicketResult:
    """Result of a JIRA ticket creation/update attempt."""
    finding_id: str
    issue_key: Optional[str]
    success: bool
    finding_type: str  # "new" or "regression"
    action: str = "created"  # "created", "reopened", or "skipped"


async def send_jira_notifications(
    new_findings: List[dict],
    regression_findings: List[dict],
    rule_descriptions: Dict[str, str],
    rule_remediations: Optional[Dict[str, str]] = None,
) -> tuple[int, List[JiraTicketResult]]:
    """
    Create JIRA tickets for new findings and regressions.

    Each finding creates a standalone ticket with AWS Security Hub custom fields populated.
    Tickets are created in parallel for efficiency.

    Args:
        new_findings: List of new FAIL findings
        regression_findings: List of findings that changed to FAIL
        rule_descriptions: Dict mapping rule_id to description
        rule_remediations: Dict mapping rule_id to remediation text

    Returns:
        Tuple of (tickets_created_count, list of JiraTicketResult)
    """
    config = await get_jira_config()

    if not config or not config.is_enabled:
        logger.info("JIRA notifications not configured or disabled")
        return 0, []

    if not all([config.base_url, config.email, config.api_token, config.project_key]):
        logger.warning("JIRA configuration incomplete - missing required fields")
        return 0, []

    logger.info(f"JIRA notifications enabled. Processing {len(new_findings)} new findings and {len(regression_findings)} regressions")
    logger.info(f"JIRA config: base_url={config.base_url}, project={config.project_key}, min_severity={config.min_severity}")

    rule_remediations = rule_remediations or {}
    results: List[JiraTicketResult] = []
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TICKETS)

    async def process_finding(
        notifier: JiraNotifier,
        finding: dict,
        finding_type: str,
    ) -> JiraTicketResult:
        """Process a single finding and create a ticket with concurrency limit."""
        finding_id = str(finding.get("id", finding.get("finding_id", "")))
        rule_name = finding.get("rule_name", "unknown")
        severity = finding.get("rule_severity", "unknown")

        if not finding_id:
            logger.warning(f"Finding missing ID for {finding_type} finding: {rule_name}")

        if not notifier.should_notify(severity):
            logger.debug(f"Skipping JIRA ticket for {rule_name} - severity {severity} below threshold {config.min_severity}")
            return JiraTicketResult(
                finding_id=finding_id,
                issue_key=None,
                success=False,
                finding_type=finding_type,
                action="skipped",
            )

        async with semaphore:
            try:
                # Get existing ticket key from DB if available (skips JIRA API search)
                existing_ticket_key = finding.get("jira_ticket_key")
                if existing_ticket_key:
                    logger.info(f"Found stored ticket key {existing_ticket_key} for {finding_type} finding: {rule_name}")

                logger.info(f"Processing JIRA ticket for {finding_type} finding: {rule_name} (severity={severity}, finding_id={finding_id})")
                issue_key = await notifier.create_finding_ticket(
                    finding_id=finding_id,
                    finding_type=finding_type,
                    rule_id=finding["rule_id"],
                    rule_name=finding["rule_name"],
                    rule_description=rule_descriptions.get(finding["rule_id"], ""),
                    rule_severity=finding["rule_severity"],
                    resource_id=finding["resource_id"],
                    resource_name=finding["resource_name"],
                    resource_type=finding["resource_type"],
                    account_id=finding["account_id"],
                    region=finding["region"],
                    created_at=_parse_datetime(finding.get("created_at")),
                    first_seen_at=_parse_datetime(finding.get("first_seen_at")),
                    details=finding.get("details"),
                    remediation_text=rule_remediations.get(finding["rule_id"]),
                    existing_ticket_key=existing_ticket_key,
                )

                # Determine action based on finding type and result
                if issue_key:
                    # For regressions with existing tickets, it was reopened; otherwise created
                    action = "reopened" if finding_type == "regression" else "created"
                    logger.info(f"JIRA ticket {issue_key} {action} for finding {finding_id}")
                else:
                    action = "skipped"
                    logger.warning(f"JIRA ticket skipped for finding {finding_id} (duplicate with no action needed)")

                return JiraTicketResult(
                    finding_id=finding_id,
                    issue_key=issue_key,
                    success=issue_key is not None,
                    finding_type=finding_type,
                    action=action,
                )
            except Exception as e:
                logger.error(f"Failed to process JIRA ticket for {finding_type} finding {rule_name}: {e}", exc_info=True)
                return JiraTicketResult(
                    finding_id=finding_id,
                    issue_key=None,
                    success=False,
                    finding_type=finding_type,
                    action="error",
                )

    # Use context manager for connection reuse across all ticket creations
    async with JiraNotifier(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
        issue_type=config.issue_type or "AWS Security Hub V2 Finding",
        min_severity=config.min_severity,
        assignee_email=config.assignee_email,
    ) as notifier:
        # Build list of tasks
        tasks = []

        if config.notify_on_new_findings:
            for finding in new_findings:
                tasks.append(process_finding(notifier, finding, "new"))

        if config.notify_on_regression:
            for finding in regression_findings:
                tasks.append(process_finding(notifier, finding, "regression"))

        # Execute all tasks concurrently (semaphore limits actual concurrency)
        if tasks:
            results = await asyncio.gather(*tasks)

    # Count results by action
    created = sum(1 for r in results if r.action == "created")
    reopened = sum(1 for r in results if r.action == "reopened")
    skipped = sum(1 for r in results if r.action == "skipped")
    errors = sum(1 for r in results if r.action == "error")

    tickets_affected = created + reopened
    logger.info(f"JIRA tickets: {created} created, {reopened} reopened, {skipped} skipped, {errors} errors")
    return tickets_affected, results


def get_jira_ticket_url(base_url: str, issue_key: str) -> str:
    """Get the browse URL for a JIRA ticket."""
    return f"{base_url.rstrip('/')}/browse/{issue_key}"


async def resolve_jira_ticket_for_remediation(
    jira_ticket_key: str,
    resource_name: str,
    remediation_action: str,
    performed_by: str = "system",
) -> bool:
    """
    Resolve a JIRA ticket after successful auto-remediation.

    This is a convenience function that handles configuration loading
    and JiraNotifier instantiation.

    Args:
        jira_ticket_key: JIRA ticket key (e.g., "CORE-123")
        resource_name: Name of the remediated resource
        remediation_action: Description of remediation action taken
        performed_by: User who initiated the remediation

    Returns:
        True if ticket was resolved, False otherwise
    """
    config = await get_jira_config()

    if not config or not config.is_enabled:
        logger.info("JIRA not configured or disabled, skipping ticket resolution")
        return False

    if not all([config.base_url, config.email, config.api_token, config.project_key]):
        logger.warning("JIRA configuration incomplete, skipping ticket resolution")
        return False

    async with JiraNotifier(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
        issue_type=config.issue_type or "Bug",
        min_severity=config.min_severity,
    ) as notifier:
        return await notifier.resolve_ticket_for_remediation(
            issue_key=jira_ticket_key,
            resource_name=resource_name,
            remediation_action=remediation_action,
            performed_by=performed_by,
        )


async def close_jira_ticket_for_rescan_pass(
    jira_ticket_key: str,
    resource_name: str,
    rule_name: str,
) -> bool:
    """
    Close a JIRA ticket when a rescan shows the resource is now compliant.

    Args:
        jira_ticket_key: JIRA ticket key (e.g., "CORE-123")
        resource_name: Name of the resource that now passes
        rule_name: Name of the compliance rule

    Returns:
        True if ticket was closed, False otherwise
    """
    config = await get_jira_config()

    if not config or not config.is_enabled:
        logger.info("JIRA not configured or disabled, skipping ticket close for rescan")
        return False

    if not all([config.base_url, config.email, config.api_token, config.project_key]):
        logger.warning("JIRA configuration incomplete, skipping ticket close for rescan")
        return False

    async with JiraNotifier(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
        issue_type=config.issue_type or "Bug",
        min_severity=config.min_severity,
    ) as notifier:
        return await notifier.close_ticket_for_rescan_pass(
            issue_key=jira_ticket_key,
            resource_name=resource_name,
            rule_name=rule_name,
        )


async def close_jira_ticket_for_exception(
    jira_ticket_key: str,
    resource_name: str,
    justification: str,
    created_by: str = "system",
) -> bool:
    """
    Close a JIRA ticket when an exception is created for the finding.

    Sets AWS Finding Status to "EXCEPTION" to indicate the finding
    was explicitly excepted rather than remediated.

    Args:
        jira_ticket_key: JIRA ticket key (e.g., "CORE-123")
        resource_name: Name of the resource with exception
        justification: Justification for the exception
        created_by: User who created the exception

    Returns:
        True if ticket was closed, False otherwise
    """
    config = await get_jira_config()

    if not config or not config.is_enabled:
        logger.info("JIRA not configured or disabled, skipping ticket close for exception")
        return False

    if not all([config.base_url, config.email, config.api_token, config.project_key]):
        logger.warning("JIRA configuration incomplete, skipping ticket close for exception")
        return False

    async with JiraNotifier(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
        issue_type=config.issue_type or "Bug",
        min_severity=config.min_severity,
    ) as notifier:
        return await notifier.close_ticket_for_exception(
            issue_key=jira_ticket_key,
            resource_name=resource_name,
            justification=justification,
            created_by=created_by,
        )


async def reopen_jira_ticket_for_exception_deleted(
    jira_ticket_key: str,
    resource_name: str,
) -> bool:
    """
    Reopen a JIRA ticket when an exception is deleted for the finding.

    Args:
        jira_ticket_key: JIRA ticket key (e.g., "CORE-123")
        resource_name: Name of the resource

    Returns:
        True if ticket was reopened, False otherwise
    """
    config = await get_jira_config()

    if not config or not config.is_enabled:
        logger.info("JIRA not configured or disabled, skipping ticket reopen for exception deletion")
        return False

    if not all([config.base_url, config.email, config.api_token, config.project_key]):
        logger.warning("JIRA configuration incomplete, skipping ticket reopen for exception deletion")
        return False

    async with JiraNotifier(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
        issue_type=config.issue_type or "Bug",
        min_severity=config.min_severity,
    ) as notifier:
        return await notifier.reopen_ticket_for_exception_deleted(
            issue_key=jira_ticket_key,
            resource_name=resource_name,
        )
