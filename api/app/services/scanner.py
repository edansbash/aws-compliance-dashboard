"""Scanner service for executing compliance scans with optimized resource fetching."""
import os
from datetime import datetime
from typing import Optional, Dict, List, Callable, Awaitable, Any
from uuid import UUID
import boto3
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload
import logging

from app.database import AsyncSessionLocal
from app.models import Scan, Finding, Rule, AWSAccount, ComplianceException, AuditLog
from app.models.scan import ScanStatus
from app.models.finding import FindingStatus, WorkflowStatus
from app.models.exception import ExceptionScope
from app.services.rules import RULE_REGISTRY
from app.services.cache import invalidate_pattern, CACHE_RULES, CACHE_FINDINGS, CACHE_SUMMARY
from app.services.fetchers.base import ResourceCache, FetchedResource
from app.services.fetchers import get_fetcher_for_resource_type, FETCHER_REGISTRY
from app.services.notifications.slack import SlackNotifier
from app.services.notifications.jira import send_jira_notifications, get_jira_ticket_url
from app.services.integration_config import (
    get_slack_config,
    get_jira_config,
)

logger = logging.getLogger(__name__)


def serialize_for_json(obj: Any) -> Any:
    """
    Recursively convert objects to JSON-serializable types.
    Converts datetime objects to ISO format strings.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [serialize_for_json(item) for item in obj]
    else:
        return obj


async def get_aws_session(account_id: str):
    """Get AWS session, optionally assuming a role for cross-account access."""
    async with AsyncSessionLocal() as db:
        # Find account by AWS account ID
        result = await db.execute(
            select(AWSAccount).where(AWSAccount.account_id == account_id)
        )
        account = result.scalar_one_or_none()

        if account and account.role_arn:
            # Assume role for cross-account access
            sts = boto3.client("sts")
            assume_kwargs = {
                "RoleArn": account.role_arn,
                "RoleSessionName": "compliance-scanner",
            }
            if account.external_id:
                assume_kwargs["ExternalId"] = account.external_id

            response = sts.assume_role(**assume_kwargs)
            credentials = response["Credentials"]

            return boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
            )

    # Use default credentials
    return boto3.Session()


async def is_scan_cancelled(scan_id: str) -> bool:
    """Check if a scan has been cancelled (status changed to FAILED externally)."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan.status).where(Scan.id == scan_id)
        )
        status = result.scalar_one_or_none()
        return status == "FAILED"


async def fetch_resources_for_region(
    session,
    region: str,
    account_id: str,
    resource_types: List[str],
    cache: ResourceCache,
) -> Dict[str, List[FetchedResource]]:
    """
    Fetch all required resources for a region, using cache to avoid duplicates.

    Args:
        session: boto3 session
        region: AWS region to fetch from
        account_id: AWS account ID
        resource_types: List of resource types needed
        cache: ResourceCache instance

    Returns:
        Dict mapping resource_type to list of FetchedResource
    """
    resources_by_type: Dict[str, List[FetchedResource]] = {}

    for resource_type in resource_types:
        fetcher_class = get_fetcher_for_resource_type(resource_type)
        if not fetcher_class:
            logger.warning(f"No fetcher found for resource type: {resource_type}")
            resources_by_type[resource_type] = []
            continue

        fetcher = fetcher_class()

        try:
            resources = await fetcher.fetch_with_cache(
                session, region, account_id, resource_type, cache
            )
            resources_by_type[resource_type] = resources
        except Exception as e:
            logger.error(f"Error fetching {resource_type} in {region}: {e}")
            resources_by_type[resource_type] = []

    return resources_by_type


async def execute_scan(
    scan_id: str,
    progress_callback: Callable[[str, Optional[Dict]], Awaitable[None]] = None
):
    """
    Execute a compliance scan using optimized resource fetching.

    This implementation:
    1. Groups rules by resource type
    2. Fetches each resource type ONCE per region
    3. Evaluates all rules against the pre-fetched resources

    Args:
        scan_id: UUID of the scan to execute
        progress_callback: Optional async callback for progress updates.
                          Called with (message, progress_dict)
    """
    async with AsyncSessionLocal() as db:
        # Get scan
        result = await db.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()

        if not scan:
            return

        # Check if already cancelled before starting
        if scan.status == "FAILED":
            return

        # Update status to running
        scan.status = "RUNNING"
        scan.started_at = datetime.utcnow()
        await db.commit()

        try:
            total_resources = 0
            total_findings = 0

            # Track findings for notifications
            new_findings_for_notification = []
            regression_findings_for_notification = []

            # Sync rules from registry to database BEFORE querying
            await sync_rules_to_db(db)
            logger.info(f"Starting scan {scan_id}")
            if progress_callback:
                await progress_callback("Initializing scan...", None)

            # Get rules to evaluate
            if scan.rule_ids:
                rules_result = await db.execute(
                    select(Rule).where(Rule.id.in_(scan.rule_ids))
                )
                rules = rules_result.scalars().all()
            else:
                rules_result = await db.execute(
                    select(Rule).where(Rule.is_enabled == True)
                )
                rules = rules_result.scalars().all()

            # Collect unique resource types from rules being scanned
            resource_types = list(set(rule.resource_type for rule in rules if rule.resource_type))
            scan.resource_types = sorted(resource_types)
            await db.commit()
            logger.info(f"Scanning {len(rules)} rules across {len(resource_types)} resource types")
            if progress_callback:
                await progress_callback(
                    f"Scanning {len(rules)} rules across {len(resource_types)} resource types",
                    {"rules_count": len(rules), "resource_types_count": len(resource_types)}
                )

            # Group rules by resource type for efficient evaluation
            rules_by_resource_type: Dict[str, List[Rule]] = {}
            for rule in rules:
                if rule.resource_type:
                    if rule.resource_type not in rules_by_resource_type:
                        rules_by_resource_type[rule.resource_type] = []
                    rules_by_resource_type[rule.resource_type].append(rule)

            # Get accounts to scan
            if scan.account_ids:
                accounts_result = await db.execute(
                    select(AWSAccount).where(
                        AWSAccount.id.in_(scan.account_ids),
                        AWSAccount.is_active == True
                    )
                )
            else:
                accounts_result = await db.execute(
                    select(AWSAccount).where(AWSAccount.is_active == True)
                )
            accounts = accounts_result.scalars().all()

            # If no accounts configured, use default credentials
            if not accounts:
                accounts = [None]  # Will use default session

            total_accounts = len(accounts)
            for account_idx, account in enumerate(accounts):
                # Check for cancellation between accounts
                if await is_scan_cancelled(scan_id):
                    logger.info(f"Scan {scan_id} was cancelled, stopping execution")
                    return

                account_id = account.account_id if account else "default"
                account_name = account.name if account else "default"

                if progress_callback:
                    await progress_callback(
                        f"Scanning account {account_name} ({account_idx + 1}/{total_accounts})",
                        {"account": account_name, "account_index": account_idx + 1, "total_accounts": total_accounts}
                    )

                try:
                    session = await get_aws_session(account_id) if account else boto3.Session()

                    # Create a new cache for each account
                    resource_cache = ResourceCache()

                    for region in scan.regions:
                        # Check for cancellation between regions
                        if await is_scan_cancelled(scan_id):
                            logger.info(f"Scan {scan_id} was cancelled, stopping execution")
                            return

                        # Fetch all required resources for this region ONCE
                        logger.info(f"Fetching resources for account={account_id} region={region}")
                        logger.info(f"  Resource types: {', '.join(sorted(resource_types))}")
                        if progress_callback:
                            await progress_callback(
                                f"Fetching resources in {region}",
                                {"region": region, "account": account_name}
                            )
                        resources_by_type = await fetch_resources_for_region(
                            session, region, account_id, resource_types, resource_cache
                        )

                        # Evaluate rules against pre-fetched resources
                        for resource_type, type_rules in rules_by_resource_type.items():
                            resources = resources_by_type.get(resource_type, [])
                            logger.info(f"Resource type {resource_type}: {len(resources)} resources, {len(type_rules)} rules")

                            for rule in type_rules:
                                rule_class = RULE_REGISTRY.get(rule.rule_id)
                                if not rule_class:
                                    logger.warning(f"Rule class not found in registry: {rule.rule_id}")
                                    continue

                                rule_instance = rule_class()

                                try:
                                    # Use optimized evaluate_resources if available
                                    if rule_instance.supports_prefetch:
                                        results = await rule_instance.evaluate_resources(
                                            resources, session, region
                                        )
                                    else:
                                        # Fall back to legacy evaluate method
                                        results = await rule_instance.evaluate(session, region)

                                    logger.info(f"Rule {rule.rule_id}: {len(results)} results from {len(resources)} resources")

                                    # Track resource IDs seen in this scan
                                    seen_resource_ids = set()

                                    for result in results:
                                        total_resources += 1

                                        # Determine finding status
                                        status = result.status

                                        # Check for exceptions
                                        has_exception = await check_exceptions(
                                            db, rule.id, result.resource_id, account_id
                                        )
                                        if has_exception and status == "FAIL":
                                            status = "EXCEPTION"

                                        # Check for existing finding (upsert logic)
                                        existing_result = await db.execute(
                                            select(Finding).where(
                                                and_(
                                                    Finding.rule_id == rule.id,
                                                    Finding.resource_id == result.resource_id,
                                                    Finding.account_id == account_id,
                                                    Finding.region == region,
                                                )
                                            )
                                        )
                                        existing_finding = existing_result.scalar_one_or_none()

                                        if existing_finding:
                                            # Track status change before updating
                                            old_status = existing_finding.status
                                            # Update existing finding
                                            existing_finding.scan_id = scan.id
                                            existing_finding.resource_name = result.resource_name
                                            existing_finding.status = status
                                            existing_finding.details = serialize_for_json(result.details)
                                            existing_finding.last_scanned_at = datetime.utcnow()
                                            # Update workflow status based on status changes
                                            if old_status != "FAIL" and status == "FAIL":
                                                # Regression: was passing/exception, now failing
                                                existing_finding.workflow_status = "OPEN"
                                                existing_finding.workflow_updated_at = datetime.utcnow()
                                            elif status == "EXCEPTION" and existing_finding.workflow_status != "RESOLVED":
                                                # Exception applied: set to RESOLVED
                                                existing_finding.workflow_status = "RESOLVED"
                                                existing_finding.workflow_updated_at = datetime.utcnow()
                                                # Track regression for notification
                                                regression_findings_for_notification.append({
                                                    "id": str(existing_finding.id),
                                                    "rule_id": rule.rule_id,
                                                    "rule_name": rule.name,
                                                    "rule_description": rule.description,
                                                    "rule_severity": rule.severity,
                                                    "resource_id": result.resource_id,
                                                    "resource_name": result.resource_name,
                                                    "resource_type": rule.resource_type,
                                                    "account_id": account_id,
                                                    "region": region,
                                                    "details": result.details,
                                                    "jira_ticket_key": existing_finding.jira_ticket_key,  # For faster JIRA lookup
                                                })
                                            # Handle FAIL -> PASS (fixed) - close JIRA ticket
                                            elif old_status == "FAIL" and status == "PASS":
                                                existing_finding.workflow_status = "RESOLVED"
                                                existing_finding.workflow_updated_at = datetime.utcnow()
                                                # Close JIRA ticket if one exists
                                                if existing_finding.jira_ticket_key:
                                                    try:
                                                        from app.services.notifications.jira import close_jira_ticket_for_rescan_pass
                                                        await close_jira_ticket_for_rescan_pass(
                                                            jira_ticket_key=existing_finding.jira_ticket_key,
                                                            resource_name=existing_finding.resource_name,
                                                            rule_name=rule.name,
                                                        )
                                                        logger.info(f"Closed JIRA ticket {existing_finding.jira_ticket_key} for fixed resource {existing_finding.resource_id}")
                                                    except Exception as jira_error:
                                                        logger.warning(f"Failed to close JIRA ticket for fixed resource: {jira_error}")
                                        else:
                                            # Create new finding
                                            # Set workflow_status based on status:
                                            # - PASS → RESOLVED
                                            # - EXCEPTION → RESOLVED (formally exempted)
                                            # - FAIL → OPEN
                                            if status == "PASS":
                                                workflow_status = "RESOLVED"
                                            elif status == "EXCEPTION":
                                                workflow_status = "RESOLVED"
                                            else:
                                                workflow_status = "OPEN"

                                            finding = Finding(
                                                scan_id=scan.id,
                                                rule_id=rule.id,
                                                resource_id=result.resource_id,
                                                resource_name=result.resource_name,
                                                resource_type=rule.resource_type,
                                                account_id=account_id,
                                                region=region,
                                                status=status,
                                                workflow_status=workflow_status,
                                                details=serialize_for_json(result.details),
                                                last_scanned_at=datetime.utcnow(),
                                            )
                                            db.add(finding)
                                            # Flush to get the finding's ID for notifications
                                            await db.flush()
                                            # Track new FAIL finding for notification
                                            if status == "FAIL":
                                                new_findings_for_notification.append({
                                                    "id": str(finding.id),
                                                    "rule_id": rule.rule_id,
                                                    "rule_name": rule.name,
                                                    "rule_description": rule.description,
                                                    "rule_severity": rule.severity,
                                                    "resource_id": result.resource_id,
                                                    "resource_name": result.resource_name,
                                                    "resource_type": rule.resource_type,
                                                    "account_id": account_id,
                                                    "region": region,
                                                    "details": result.details,
                                                })

                                        if status == "FAIL":
                                            total_findings += 1

                                        # Track that we saw this resource
                                        seen_resource_ids.add(result.resource_id)

                                    # Mark findings for deleted resources as PASS
                                    # Find FAIL findings for this rule/account/region that weren't seen
                                    orphan_conditions = [
                                        Finding.rule_id == rule.id,
                                        Finding.account_id == account_id,
                                        Finding.region == region,
                                        Finding.status == "FAIL",
                                    ]
                                    if seen_resource_ids:
                                        orphan_conditions.append(Finding.resource_id.notin_(seen_resource_ids))
                                    # If no resources seen, all FAIL findings are orphaned

                                    orphaned_result = await db.execute(
                                        select(Finding).where(and_(*orphan_conditions))
                                    )
                                    orphaned_findings = orphaned_result.scalars().all()

                                    for orphaned in orphaned_findings:
                                        logger.info(f"Resource {orphaned.resource_id} no longer exists, marking as PASS")
                                        orphaned.status = "PASS"
                                        orphaned.scan_id = scan.id
                                        orphaned.last_scanned_at = datetime.utcnow()
                                        orphaned.workflow_status = "RESOLVED"
                                        orphaned.workflow_updated_at = datetime.utcnow()

                                        # Close JIRA ticket if one exists
                                        if orphaned.jira_ticket_key:
                                            try:
                                                from app.services.notifications.jira import close_jira_ticket_for_rescan_pass
                                                await close_jira_ticket_for_rescan_pass(
                                                    jira_ticket_key=orphaned.jira_ticket_key,
                                                    resource_name=orphaned.resource_name,
                                                    rule_name=rule.name,
                                                )
                                            except Exception as jira_error:
                                                logger.warning(f"Failed to close JIRA ticket for deleted resource: {jira_error}")

                                except Exception as e:
                                    # Log rule evaluation error but continue
                                    logger.error(f"Error evaluating rule {rule.rule_id}: {e}")

                        await db.commit()

                except Exception as e:
                    # Log account error but continue with other accounts
                    logger.error(f"Error scanning account {account_id}: {e}")

            # Final cancellation check before marking complete
            if await is_scan_cancelled(scan_id):
                logger.info(f"Scan {scan_id} was cancelled, not marking as complete")
                return

            # Update scan status
            scan.status = "COMPLETED"
            scan.completed_at = datetime.utcnow()
            scan.total_resources = total_resources
            scan.total_findings = total_findings

            # Create audit log
            audit_log = AuditLog(
                action="SCAN_COMPLETED",
                performed_by="system",
                details={
                    "scan_id": str(scan.id),
                    "total_resources": total_resources,
                    "total_findings": total_findings,
                    "duration_seconds": (scan.completed_at - scan.started_at).total_seconds() if scan.started_at else None,
                }
            )
            db.add(audit_log)
            await db.commit()

            # Invalidate caches so fresh data is returned
            await invalidate_pattern(f"{CACHE_RULES}:*")
            await invalidate_pattern(f"{CACHE_FINDINGS}:*")
            await invalidate_pattern(f"{CACHE_SUMMARY}:*")

            # Send notifications for new findings and regressions
            scanned_account_ids = [a.account_id for a in accounts if a] or ["default"]
            scanned_regions = scan.regions or []
            await send_finding_notifications(
                scan_id=scan_id,
                new_findings=new_findings_for_notification,
                regression_findings=regression_findings_for_notification,
                total_findings=total_findings,
                account_ids=scanned_account_ids,
                regions=scanned_regions,
            )

        except Exception as e:
            scan.status = "FAILED"
            scan.completed_at = datetime.utcnow()
            scan.error_message = str(e)[:1000]
            await db.commit()

            # Invalidate caches even on failure
            await invalidate_pattern(f"{CACHE_RULES}:*")
            await invalidate_pattern(f"{CACHE_FINDINGS}:*")
            await invalidate_pattern(f"{CACHE_SUMMARY}:*")

            # Re-raise so worker knows the scan failed
            raise


async def check_exceptions(db, rule_id: UUID, resource_id: str, account_id: str) -> bool:
    """Check if a finding matches any active exception."""
    now = datetime.utcnow()

    # Check resource-specific exception
    result = await db.execute(
        select(ComplianceException).where(
            ComplianceException.rule_id == rule_id,
            ComplianceException.resource_id == resource_id,
            ComplianceException.scope == ExceptionScope.RESOURCE,
        )
    )
    exception = result.scalar_one_or_none()
    if exception and (exception.expires_at is None or exception.expires_at > now):
        return True

    # Check account-wide exception
    result = await db.execute(
        select(ComplianceException).where(
            ComplianceException.rule_id == rule_id,
            ComplianceException.account_id == account_id,
            ComplianceException.scope == ExceptionScope.ACCOUNT,
        )
    )
    exception = result.scalar_one_or_none()
    if exception and (exception.expires_at is None or exception.expires_at > now):
        return True

    # Check rule-wide exception
    result = await db.execute(
        select(ComplianceException).where(
            ComplianceException.rule_id == rule_id,
            ComplianceException.scope == ExceptionScope.RULE,
        )
    )
    exception = result.scalar_one_or_none()
    if exception and (exception.expires_at is None or exception.expires_at > now):
        return True

    return False


async def sync_rules_to_db(db):
    """Sync rules from registry to database.

    Creates new rules and updates existing rules with current values
    from the rule class (name, description, resource_type, severity, has_remediation).
    """
    for rule_id, rule_class in RULE_REGISTRY.items():
        result = await db.execute(
            select(Rule).where(Rule.rule_id == rule_id)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Update existing rule with current values from rule class
            # This ensures any changes to resource_type, severity, etc. are reflected
            if existing.resource_type != rule_class.resource_type:
                logger.info(f"Updating rule {rule_id} resource_type: {existing.resource_type} -> {rule_class.resource_type}")
            existing.name = rule_class.name
            existing.description = rule_class.description
            existing.resource_type = rule_class.resource_type
            existing.severity = rule_class.severity.value
            existing.has_remediation = rule_class.has_remediation
        else:
            rule = Rule(
                rule_id=rule_class.rule_id,
                name=rule_class.name,
                description=rule_class.description,
                resource_type=rule_class.resource_type,
                severity=rule_class.severity.value,
                is_enabled=True,
                has_remediation=rule_class.has_remediation,
            )
            db.add(rule)

    await db.commit()

    # Cleanup incorrect findings for root account rules
    # These rules should only have findings with resource_id containing ":root"
    # Any findings with ":user/" were created incorrectly when User resources
    # were passed to AccountSummary rules
    root_rule_ids = ["IAM_ROOT_ACCESS_KEYS", "IAM_ROOT_ACTIVE_CERTIFICATES", "IAM_ROOT_MFA"]
    for root_rule_id in root_rule_ids:
        rule_result = await db.execute(
            select(Rule).where(Rule.rule_id == root_rule_id)
        )
        rule = rule_result.scalar_one_or_none()
        if rule:
            # Delete findings that have ":user/" in resource_id (incorrect)
            delete_result = await db.execute(
                select(Finding).where(
                    and_(
                        Finding.rule_id == rule.id,
                        Finding.resource_id.like("%:user/%")
                    )
                )
            )
            incorrect_findings = delete_result.scalars().all()
            if incorrect_findings:
                logger.info(f"Cleaning up {len(incorrect_findings)} incorrect findings for rule {root_rule_id}")
                for finding in incorrect_findings:
                    await db.delete(finding)

    await db.commit()


async def rescan_single_resource(finding: Finding) -> tuple[str, dict]:
    """
    Rescan a single resource to verify compliance status.

    Returns:
        Tuple of (status, updated_details) where updated_details contains the latest resource attributes
    """
    rule_class = RULE_REGISTRY.get(finding.rule.rule_id)
    if not rule_class:
        return "ERROR", finding.details

    session = await get_aws_session(finding.account_id)
    rule_instance = rule_class()

    try:
        # Use optimized prefetch method if available
        if rule_instance.supports_prefetch:
            # Fetch resources using the appropriate fetcher
            resource_type = finding.rule.resource_type
            fetcher_class = get_fetcher_for_resource_type(resource_type)

            if fetcher_class:
                fetcher = fetcher_class()
                cache = ResourceCache()

                # Fetch resources for this region
                resources = await fetcher.fetch_with_cache(
                    session, finding.region, finding.account_id, resource_type, cache
                )

                # Evaluate using prefetched resources
                results = await rule_instance.evaluate_resources(
                    resources, session, finding.region
                )
            else:
                # No fetcher found, fall back to legacy evaluate
                results = await rule_instance.evaluate(session, finding.region)
        else:
            # Legacy evaluate method
            results = await rule_instance.evaluate(session, finding.region)

        # Find the matching resource and get updated details
        for result in results:
            if result.resource_id == finding.resource_id:
                # Serialize datetime objects to strings before returning
                serialized_details = serialize_for_json(result.details)
                # Return both status and the updated resource attributes (including tags)
                return result.status, serialized_details

        # Resource not found - might have been deleted
        return "PASS", finding.details

    except Exception as e:
        logger.error(f"Error rescanning resource {finding.resource_id}: {e}")
        return "ERROR", finding.details


async def _store_jira_ticket_keys(jira_results: List) -> None:
    """
    Store JIRA ticket keys back to findings in the database.

    This enables faster duplicate detection on subsequent scans by avoiding
    JIRA API searches when we already know the ticket key.
    """
    # Filter to results with new ticket keys (action=created)
    new_tickets = [r for r in jira_results if r.action == "created" and r.issue_key]

    if not new_tickets:
        return

    logger.info(f"Storing {len(new_tickets)} JIRA ticket keys to findings")

    async with AsyncSessionLocal() as db:
        for result in new_tickets:
            try:
                # Update finding with ticket key
                finding_result = await db.execute(
                    select(Finding).where(Finding.id == result.finding_id)
                )
                finding = finding_result.scalar_one_or_none()
                if finding:
                    finding.jira_ticket_key = result.issue_key
                    logger.debug(f"Stored ticket key {result.issue_key} for finding {result.finding_id}")
            except Exception as e:
                logger.error(f"Failed to store ticket key for finding {result.finding_id}: {e}")

        await db.commit()


async def send_finding_notifications(
    scan_id: str,
    new_findings: List[dict],
    regression_findings: List[dict],
    total_findings: int,
    account_ids: List[str] = None,
    regions: List[str] = None,
):
    """
    Send Slack notifications for new findings and regressions.

    Args:
        scan_id: ID of the completed scan
        new_findings: List of new FAIL findings
        regression_findings: List of findings that changed to FAIL
        total_findings: Total number of failed findings
        account_ids: List of AWS account IDs that were scanned
        regions: List of AWS regions that were scanned
    """
    # Create JIRA tickets FIRST (so we can include links in Slack notifications)
    jira_tickets_created = 0
    jira_ticket_urls = []
    jira_ticket_map = {}  # finding_id -> ticket_url

    # Get JIRA config (includes is_enabled from DB and settings from env > DB)
    jira_config = await get_jira_config()

    if not jira_config.is_enabled:
        logger.debug("JIRA integration disabled via UI toggle")
    elif not jira_config.is_configured:
        logger.debug("JIRA integration not configured (missing env vars)")
    else:
        try:
            # Build rule descriptions dict from findings
            rule_descriptions = {}
            for finding in new_findings + regression_findings:
                rule_id = finding.get("rule_id")
                if rule_id and rule_id not in rule_descriptions:
                    rule_descriptions[rule_id] = finding.get("rule_description", "")

            jira_tickets_created, jira_results = await send_jira_notifications(
                new_findings=new_findings,
                regression_findings=regression_findings,
                rule_descriptions=rule_descriptions,
            )
            if jira_tickets_created > 0:
                logger.info(f"Created {jira_tickets_created} JIRA tickets for scan {scan_id}")
                # Build ticket URL map for Slack notifications
                for r in jira_results:
                    if r.success and r.issue_key:
                        url = get_jira_ticket_url(jira_config.base_url, r.issue_key)
                        jira_ticket_urls.append(url)
                        jira_ticket_map[r.finding_id] = url

                # Store ticket keys back to findings in database
                await _store_jira_ticket_keys(jira_results)
        except Exception as e:
            logger.error(f"Failed to create JIRA tickets: {e}", exc_info=True)

    # Get Slack config (includes is_enabled from DB and settings from env > DB)
    slack_config = await get_slack_config()

    if not slack_config.is_enabled:
        logger.debug("Slack integration disabled via UI toggle")
        return

    if not slack_config.is_configured:
        logger.debug("Slack not configured (missing SLACK_WEBHOOK_URL env var)")
        return

    notifier = SlackNotifier(
        webhook_url=slack_config.webhook_url,
        min_severity=slack_config.min_severity
    )

    # Send individual notifications for critical/high severity findings
    notifications_sent = 0

    # Notify on new findings
    if slack_config.notify_on_new_findings:
        for finding in new_findings:
            if notifier.should_notify(finding["rule_severity"]):
                try:
                    finding_id = str(finding.get("id", finding.get("finding_id", "")))
                    await notifier.send_finding_notification(
                        finding_type="new",
                        rule_name=finding["rule_name"],
                        rule_severity=finding["rule_severity"],
                        resource_id=finding["resource_id"],
                        resource_name=finding["resource_name"],
                        resource_type=finding["resource_type"],
                        account_id=finding["account_id"],
                        region=finding["region"],
                        details=finding.get("details"),
                        jira_ticket_url=jira_ticket_map.get(finding_id),
                    )
                    notifications_sent += 1
                except Exception as e:
                    logger.error(f"Failed to send notification for new finding: {e}")

    # Notify on regressions
    if slack_config.notify_on_regression:
        for finding in regression_findings:
            if notifier.should_notify(finding["rule_severity"]):
                try:
                    finding_id = str(finding.get("id", finding.get("finding_id", "")))
                    await notifier.send_finding_notification(
                        finding_type="regression",
                        rule_name=finding["rule_name"],
                        rule_severity=finding["rule_severity"],
                        resource_id=finding["resource_id"],
                        resource_name=finding["resource_name"],
                        resource_type=finding["resource_type"],
                        account_id=finding["account_id"],
                        region=finding["region"],
                        details=finding.get("details"),
                        jira_ticket_url=jira_ticket_map.get(finding_id),
                    )
                    notifications_sent += 1
                except Exception as e:
                    logger.error(f"Failed to send notification for regression: {e}")

    # Send summary notification only if the user has enabled it
    notify_on_complete = slack_config.notify_on_scan_complete
    logger.info(f"Scan summary check: notify_on_complete={notify_on_complete}, notifications_sent={notifications_sent}")

    if notify_on_complete:
        # Calculate findings by severity
        findings_by_severity = {}
        for finding in new_findings + regression_findings:
            sev = finding["rule_severity"]
            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

        try:
            logger.info(f"Sending scan summary to Slack for scan {scan_id}")
            result = await notifier.send_scan_summary(
                scan_id=scan_id,
                total_findings=total_findings,
                new_findings=len(new_findings),
                regressions=len(regression_findings),
                findings_by_severity=findings_by_severity,
                account_ids=account_ids,
                regions=regions,
                jira_tickets_created=jira_tickets_created,
                jira_ticket_urls=jira_ticket_urls,
            )
            logger.info(f"Scan summary sent result: {result}")
        except Exception as e:
            logger.error(f"Failed to send scan summary notification: {e}", exc_info=True)

    logger.info(f"Sent {notifications_sent} Slack notifications for scan {scan_id}")
