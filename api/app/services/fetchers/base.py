"""Base classes for resource fetchers."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class FetchedResource:
    """
    Represents a fetched AWS resource with all its attributes.

    This is the standardized format that fetchers return and rules consume.
    """
    resource_id: str  # ARN or unique identifier
    resource_name: str  # Human-readable name
    resource_type: str  # AWS CloudFormation resource type
    region: str
    account_id: str
    raw_data: Dict[str, Any]  # Original AWS API response data
    attributes: Dict[str, Any] = field(default_factory=dict)  # Processed/additional attributes


class ResourceCache:
    """
    Cache for fetched resources to avoid duplicate API calls.

    Keyed by (account_id, region, resource_type) to ensure resources
    are only fetched once per scan context.
    """

    def __init__(self):
        self._cache: Dict[tuple, List[FetchedResource]] = {}

    def get_key(self, account_id: str, region: str, resource_type: str) -> tuple:
        """Generate cache key."""
        return (account_id, region, resource_type)

    def get(self, account_id: str, region: str, resource_type: str) -> Optional[List[FetchedResource]]:
        """Get cached resources if available."""
        key = self.get_key(account_id, region, resource_type)
        return self._cache.get(key)

    def set(self, account_id: str, region: str, resource_type: str, resources: List[FetchedResource]):
        """Cache fetched resources."""
        key = self.get_key(account_id, region, resource_type)
        self._cache[key] = resources

    def has(self, account_id: str, region: str, resource_type: str) -> bool:
        """Check if resources are cached."""
        key = self.get_key(account_id, region, resource_type)
        return key in self._cache

    def clear(self):
        """Clear all cached resources."""
        self._cache.clear()

    def clear_for_region(self, account_id: str, region: str):
        """Clear cached resources for a specific region."""
        keys_to_remove = [
            key for key in self._cache.keys()
            if key[0] == account_id and key[1] == region
        ]
        for key in keys_to_remove:
            del self._cache[key]


class ResourceFetcher(ABC):
    """
    Base class for all resource fetchers.

    Fetchers are responsible for efficiently collecting AWS resources
    with all attributes needed by compliance rules. Each fetcher handles
    one or more related resource types.
    """

    # Resource types this fetcher handles
    resource_types: List[str] = []

    # Whether this fetcher's resources are global (not region-specific)
    is_global: bool = False

    # The single region to use for global resources
    global_region: str = "us-east-1"

    @abstractmethod
    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """
        Fetch all resources of the specified type.

        Args:
            session: boto3 session (possibly assumed role)
            region: AWS region to fetch from
            account_id: AWS account ID
            resource_type: Specific resource type to fetch

        Returns:
            List of FetchedResource objects with all needed attributes
        """
        pass

    async def fetch_with_cache(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
        cache: ResourceCache,
    ) -> List[FetchedResource]:
        """
        Fetch resources using cache to avoid duplicate API calls.

        Args:
            session: boto3 session
            region: AWS region
            account_id: AWS account ID
            resource_type: Resource type to fetch
            cache: ResourceCache instance

        Returns:
            List of FetchedResource objects (from cache or freshly fetched)
        """
        # For global resources, always use the global region
        effective_region = self.global_region if self.is_global else region

        # Skip if not the global region for global resources
        if self.is_global and region != self.global_region:
            return []

        # Check cache first
        cached = cache.get(account_id, effective_region, resource_type)
        if cached is not None:
            return cached

        # Fetch and cache
        resources = await self.fetch(session, effective_region, account_id, resource_type)
        cache.set(account_id, effective_region, resource_type, resources)

        return resources

    def supports_resource_type(self, resource_type: str) -> bool:
        """Check if this fetcher supports the given resource type."""
        return resource_type in self.resource_types
