"""
IaC configuration service - reads settings from environment variables.
"""

import os
from dataclasses import dataclass


@dataclass
class IaCConfig:
    """IaC repository configuration from environment."""

    github_token: str
    owner: str
    repo: str
    branch: str

    @classmethod
    def from_env(cls) -> "IaCConfig":
        """Load configuration from environment variables."""
        return cls(
            github_token=os.getenv("GITHUB_TOKEN", ""),
            owner=os.getenv("IAC_GITHUB_OWNER", ""),
            repo=os.getenv("IAC_GITHUB_REPO", ""),
            branch=os.getenv("IAC_GITHUB_BRANCH", "main"),
        )

    def is_configured(self) -> bool:
        """Check if IaC scanning is configured."""
        return bool(self.github_token and self.owner and self.repo)

    def get_repo_url(self) -> str:
        """Get the full GitHub repository URL."""
        return f"https://github.com/{self.owner}/{self.repo}"

    def get_file_url(self, file_path: str, line: int | None = None) -> str:
        """Get URL to a specific file in the repository."""
        url = f"https://github.com/{self.owner}/{self.repo}/blob/{self.branch}/{file_path}"
        if line:
            url += f"#L{line}"
        return url
