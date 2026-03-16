"""
GitHub Code Scanning API service for fetching Trivy alerts.
"""

import os
import httpx
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CodeScanningAlert:
    """GitHub Code Scanning alert from Trivy."""

    number: int  # Alert number in repo
    rule_id: str  # Trivy rule ID (AVD-AWS-xxxx)
    rule_name: Optional[str]  # e.g., "Misconfiguration"
    severity: str  # critical, high, medium, low
    state: str  # open, dismissed, fixed
    description: str  # Rule description
    help_uri: Optional[str]  # Link to Aqua vulnerability database
    message: str  # Specific finding message
    file_path: str  # e.g., "modules/s3/main.tf"
    start_line: int  # Line number
    end_line: int
    commit_sha: str  # Commit where detected
    html_url: str  # Link to alert in GitHub
    tool_name: Optional[str]  # e.g., "Trivy"
    created_at: datetime
    fixed_at: Optional[datetime]
    dismissed_at: Optional[datetime]
    dismissed_reason: Optional[str]


class GitHubService:
    """Service for interacting with GitHub Code Scanning API."""

    def __init__(self, token: str = None):
        # Use provided token or fall back to env var
        self.token = token or os.getenv("GITHUB_TOKEN")
        if not self.token:
            raise ValueError("GITHUB_TOKEN environment variable is required")

        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def get_code_scanning_alerts(
        self,
        owner: str,
        repo: str,
        ref: Optional[str] = None,  # Branch name
        state: str = "open",  # open, dismissed, fixed, or all
        tool_name: Optional[str] = None,  # Filter by tool (e.g., "trivy", "Trivy")
    ) -> List[CodeScanningAlert]:
        """
        Fetch code scanning alerts from GitHub.

        API: GET /repos/{owner}/{repo}/code-scanning/alerts
        Docs: https://docs.github.com/en/rest/code-scanning/code-scanning
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            params = {
                "per_page": 100,
            }
            if tool_name:
                params["tool_name"] = tool_name
            if state != "all":
                params["state"] = state
            if ref:
                params["ref"] = ref

            alerts = []
            page = 1

            while True:
                params["page"] = page
                response = await client.get(
                    f"{self.base_url}/repos/{owner}/{repo}/code-scanning/alerts",
                    headers=self.headers,
                    params=params,
                )
                response.raise_for_status()

                data = response.json()
                if not data:
                    break

                for alert in data:
                    alerts.append(self._parse_alert(alert))

                # Check if there are more pages
                if len(data) < 100:
                    break
                page += 1

            return alerts

    async def get_alert_instances(
        self, owner: str, repo: str, alert_number: int
    ) -> List[dict]:
        """Get all instances of a specific alert across branches."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def get_repo_info(self, owner: str, repo: str) -> dict:
        """Get repository information."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()

    async def get_latest_commit(self, owner: str, repo: str, branch: str) -> str:
        """Get the latest commit SHA for a branch."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/commits/{branch}",
                headers=self.headers,
            )
            response.raise_for_status()
            return response.json()["sha"]

    def _parse_alert(self, data: dict) -> CodeScanningAlert:
        """Parse GitHub API response into CodeScanningAlert."""
        location = data.get("most_recent_instance", {}).get("location", {})
        rule = data.get("rule", {})
        tool = data.get("tool", {})

        return CodeScanningAlert(
            number=data["number"],
            rule_id=rule.get("id", ""),
            rule_name=rule.get("name"),  # e.g., "Misconfiguration"
            severity=rule.get("security_severity_level") or rule.get("severity") or "medium",
            state=data["state"],
            description=rule.get("description", ""),
            help_uri=rule.get("help_uri"),  # Link to Aqua docs
            message=data.get("most_recent_instance", {}).get("message", {}).get("text", ""),
            file_path=location.get("path", ""),
            start_line=location.get("start_line", 0),
            end_line=location.get("end_line", 0),
            commit_sha=data.get("most_recent_instance", {}).get("commit_sha", ""),
            html_url=data["html_url"],
            tool_name=tool.get("name"),  # e.g., "Trivy"
            created_at=self._parse_datetime(data["created_at"]),
            fixed_at=self._parse_datetime(data.get("fixed_at")),
            dismissed_at=self._parse_datetime(data.get("dismissed_at")),
            dismissed_reason=data.get("dismissed_reason"),
        )

    def _parse_datetime(self, value: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime string, returning timezone-naive UTC datetime."""
        if not value:
            return None
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # Convert to UTC and strip timezone info for PostgreSQL compatibility
        return dt.replace(tzinfo=None)
