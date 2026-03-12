"""S3 compliance rules using pre-fetched resource data."""

import json
from typing import List, Dict, Any, TYPE_CHECKING
from botocore.exceptions import ClientError

from app.services.rules.base import ComplianceRule, RuleResult, Severity

if TYPE_CHECKING:
    from app.services.fetchers.base import FetchedResource


# ============================================================================
# S3 Versioning Rule
# ============================================================================


class S3VersioningRule(ComplianceRule):
    """Ensures S3 buckets have versioning enabled."""

    rule_id = "S3_VERSIONING"
    name = "S3 Bucket Versioning Enabled"
    description = "Ensures S3 buckets have versioning enabled for data protection and recovery"
    resource_type = "AWS::S3::Bucket"
    severity = Severity.MEDIUM
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate S3 buckets for versioning using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            # Skip resources that failed to fetch
            if attrs.get("fetch_failed"):
                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=resource.resource_name,
                    status="ERROR",
                    details={"error": attrs.get("error", "Failed to fetch resource")}
                ))
                continue

            versioning_status = attrs.get("versioning_status", "Disabled")
            is_compliant = versioning_status == "Enabled"

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "versioning_status": versioning_status,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="PASS" if is_compliant else "FAIL",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method - kept for backward compatibility."""
        results = []

        try:
            s3 = session.client("s3", region_name=region)
            response = s3.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]

                try:
                    location_response = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get("LocationConstraint") or "us-east-1"

                    if bucket_region != region:
                        continue

                    versioning_response = s3.get_bucket_versioning(Bucket=bucket_name)
                    versioning_status = versioning_response.get("Status", "Disabled")
                    is_compliant = versioning_status == "Enabled"

                    results.append(RuleResult(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        status="PASS" if is_compliant else "FAIL",
                        details={
                            "versioning_status": versioning_status,
                            "bucket_region": bucket_region,
                        }
                    ))

                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "Unknown")
                    results.append(RuleResult(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        status="ERROR",
                        details={"error": f"{error_code}: {str(e)}"}
                    ))

        except ClientError:
            pass

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Enable versioning on the S3 bucket."""
        bucket_name = resource_id.split(":::")[-1]

        s3 = session.client("s3", region_name=region)
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"}
        )

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable versioning on S3 bucket"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "versioning_status": "Enabled"
        }


# ============================================================================
# S3 MFA Delete Rule
# ============================================================================


class S3MFADeleteRule(ComplianceRule):
    """Ensures S3 buckets have MFA Delete enabled."""

    rule_id = "S3_MFA_DELETE"
    name = "S3 Bucket MFA Delete Enabled"
    description = "Ensures S3 buckets have MFA Delete enabled to prevent accidental or malicious deletion of versioned objects"
    resource_type = "AWS::S3::Bucket"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate S3 buckets for MFA Delete using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            if attrs.get("fetch_failed"):
                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=resource.resource_name,
                    status="ERROR",
                    details={"error": attrs.get("error", "Failed to fetch resource")}
                ))
                continue

            mfa_delete_status = attrs.get("mfa_delete_status", "Disabled")
            versioning_status = attrs.get("versioning_status", "Disabled")
            is_compliant = mfa_delete_status == "Enabled"

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "mfa_delete_status": mfa_delete_status,
                "versioning_status": versioning_status,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="PASS" if is_compliant else "FAIL",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []

        try:
            s3 = session.client("s3", region_name=region)
            response = s3.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]

                try:
                    location_response = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get("LocationConstraint") or "us-east-1"

                    if bucket_region != region:
                        continue

                    versioning_response = s3.get_bucket_versioning(Bucket=bucket_name)
                    versioning_status = versioning_response.get("Status", "Disabled")
                    mfa_delete_status = versioning_response.get("MFADelete", "Disabled")
                    is_compliant = mfa_delete_status == "Enabled"

                    results.append(RuleResult(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        status="PASS" if is_compliant else "FAIL",
                        details={
                            "mfa_delete_status": mfa_delete_status,
                            "versioning_status": versioning_status,
                            "bucket_region": bucket_region,
                        }
                    ))

                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "Unknown")
                    results.append(RuleResult(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        status="ERROR",
                        details={"error": f"{error_code}: {str(e)}"}
                    ))

        except ClientError:
            pass

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable MFA Delete on S3 bucket (requires root account credentials and versioning enabled)"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "mfa_delete_status": "Enabled"
        }


# ============================================================================
# S3 Encryption Rules
# ============================================================================


class S3EncryptionRule(ComplianceRule):
    """Ensures S3 buckets have server-side encryption enabled."""

    rule_id = "S3_ENCRYPTION"
    name = "S3 Bucket Encryption Enabled"
    description = "Ensures S3 buckets have server-side encryption enabled at rest"
    resource_type = "AWS::S3::Bucket"
    severity = Severity.HIGH
    has_remediation = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate S3 buckets for encryption using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            if attrs.get("fetch_failed"):
                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=resource.resource_name,
                    status="ERROR",
                    details={"error": attrs.get("error", "Failed to fetch resource")}
                ))
                continue

            encryption_enabled = attrs.get("encryption_enabled", False)
            if encryption_enabled == "ERROR":
                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=resource.resource_name,
                    status="ERROR",
                    details={"error": attrs.get("encryption_error", "Failed to check encryption")}
                ))
                continue

            is_compliant = encryption_enabled is True

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "encryption_enabled": encryption_enabled,
                "encryption_type": attrs.get("encryption_type"),
                "kms_key_id": attrs.get("kms_key_id"),
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="PASS" if is_compliant else "FAIL",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []

        try:
            s3 = session.client("s3", region_name=region)
            response = s3.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]

                try:
                    location_response = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get("LocationConstraint") or "us-east-1"

                    if bucket_region != region:
                        continue

                    try:
                        encryption_response = s3.get_bucket_encryption(Bucket=bucket_name)
                        rules = encryption_response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

                        is_encrypted = len(rules) > 0
                        encryption_type = None
                        kms_key = None

                        if rules:
                            apply_sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                            encryption_type = apply_sse.get("SSEAlgorithm")
                            kms_key = apply_sse.get("KMSMasterKeyID")

                        results.append(RuleResult(
                            resource_id=f"arn:aws:s3:::{bucket_name}",
                            resource_name=bucket_name,
                            status="PASS" if is_encrypted else "FAIL",
                            details={
                                "encryption_enabled": is_encrypted,
                                "encryption_type": encryption_type,
                                "kms_key_id": kms_key,
                                "bucket_region": bucket_region,
                            }
                        ))

                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code", "Unknown")
                        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                            results.append(RuleResult(
                                resource_id=f"arn:aws:s3:::{bucket_name}",
                                resource_name=bucket_name,
                                status="FAIL",
                                details={
                                    "encryption_enabled": False,
                                    "encryption_type": None,
                                    "kms_key_id": None,
                                    "bucket_region": bucket_region,
                                }
                            ))
                        else:
                            results.append(RuleResult(
                                resource_id=f"arn:aws:s3:::{bucket_name}",
                                resource_name=bucket_name,
                                status="ERROR",
                                details={"error": f"{error_code}: {str(e)}"}
                            ))

                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "Unknown")
                    results.append(RuleResult(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        status="ERROR",
                        details={"error": f"{error_code}: {str(e)}"}
                    ))

        except ClientError:
            pass

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Enable default encryption on the S3 bucket using AES-256."""
        bucket_name = resource_id.split(":::")[-1]

        s3 = session.client("s3", region_name=region)
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        )

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable AES-256 server-side encryption on S3 bucket"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "encryption_enabled": True,
            "encryption_type": "AES256"
        }


class S3AllowsCleartextRule(ComplianceRule):
    """Ensures S3 buckets enforce SSL/TLS for data transfer (deny cleartext HTTP)."""

    rule_id = "S3_DENY_CLEARTEXT"
    name = "S3 Bucket Denies Cleartext Access"
    description = "Ensures S3 buckets have a bucket policy that denies non-HTTPS requests"
    resource_type = "AWS::S3::Bucket"
    severity = Severity.HIGH
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate S3 buckets for HTTPS-only access using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            if attrs.get("fetch_failed"):
                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=resource.resource_name,
                    status="ERROR",
                    details={"error": attrs.get("error", "Failed to fetch resource")}
                ))
                continue

            policy = attrs.get("policy")
            policy_exists = attrs.get("policy_exists", False)

            denies_cleartext = False
            if policy:
                denies_cleartext = self._check_denies_cleartext(policy)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)  # Copy all attributes
            details.update({
                "denies_cleartext": denies_cleartext,
                "policy_exists": policy_exists,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="PASS" if denies_cleartext else "FAIL",
                details=details
            ))

        return results

    def _check_denies_cleartext(self, policy: dict) -> bool:
        """Check if policy denies non-SSL requests."""
        for statement in policy.get("Statement", []):
            effect = statement.get("Effect", "")
            condition = statement.get("Condition", {})

            bool_condition = condition.get("Bool", {})
            secure_transport = bool_condition.get("aws:SecureTransport")

            if effect == "Deny" and secure_transport == "false":
                return True

        return False

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []

        try:
            s3 = session.client("s3", region_name=region)
            response = s3.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]

                try:
                    location_response = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get("LocationConstraint") or "us-east-1"

                    if bucket_region != region:
                        continue

                    denies_cleartext = False
                    policy_exists = False

                    try:
                        policy_response = s3.get_bucket_policy(Bucket=bucket_name)
                        policy = json.loads(policy_response.get("Policy", "{}"))
                        policy_exists = True

                        denies_cleartext = self._check_denies_cleartext(policy)

                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code", "Unknown")
                        if error_code == "NoSuchBucketPolicy":
                            policy_exists = False
                        else:
                            raise

                    results.append(RuleResult(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        status="PASS" if denies_cleartext else "FAIL",
                        details={
                            "denies_cleartext": denies_cleartext,
                            "policy_exists": policy_exists,
                            "bucket_region": bucket_region,
                        }
                    ))

                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "Unknown")
                    results.append(RuleResult(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        status="ERROR",
                        details={"error": f"{error_code}: {str(e)}"}
                    ))

        except ClientError:
            pass

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Add a bucket policy that denies non-HTTPS requests."""
        bucket_name = resource_id.split(":::")[-1]

        s3 = session.client("s3", region_name=region)

        existing_statements = []
        try:
            policy_response = s3.get_bucket_policy(Bucket=bucket_name)
            existing_policy = json.loads(policy_response.get("Policy", "{}"))
            existing_statements = existing_policy.get("Statement", [])
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
                raise

        deny_http_statement = {
            "Sid": "DenyNonHTTPS",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                f"arn:aws:s3:::{bucket_name}",
                f"arn:aws:s3:::{bucket_name}/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }

        existing_statements = [s for s in existing_statements if s.get("Sid") != "DenyNonHTTPS"]
        existing_statements.append(deny_http_statement)

        new_policy = {
            "Version": "2012-10-17",
            "Statement": existing_statements
        }

        s3.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(new_policy)
        )

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Add bucket policy to deny non-HTTPS (cleartext) requests"

    @classmethod
    def get_expected_state(cls, current_details: Dict[str, Any]) -> Dict[str, Any]:
        return {
            **current_details,
            "denies_cleartext": True,
            "policy_exists": True
        }


# ============================================================================
# S3 Policy Rules (World Access Checks)
# ============================================================================


def check_world_access_policy(policy: dict, action_patterns: List[str]) -> bool:
    """
    Check if a bucket policy allows world (public) access for specific actions.

    Args:
        policy: Parsed bucket policy dict
        action_patterns: List of action patterns to check (e.g., ["s3:*"], ["s3:Put*"])

    Returns:
        True if world access is allowed for any of the action patterns
    """
    for statement in policy.get("Statement", []):
        effect = statement.get("Effect", "")
        if effect != "Allow":
            continue

        principal = statement.get("Principal", {})
        is_world_principal = (
            principal == "*" or
            principal == {"AWS": "*"} or
            (isinstance(principal, dict) and principal.get("AWS") == "*")
        )

        if not is_world_principal:
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            action_lower = action.lower()
            for pattern in action_patterns:
                pattern_lower = pattern.lower()
                if action_lower == pattern_lower:
                    return True
                if action_lower == "s3:*" or action_lower == "*":
                    return True
                if pattern_lower.endswith("*"):
                    prefix = pattern_lower[:-1]
                    if action_lower.startswith(prefix):
                        return True
                if action_lower.endswith("*"):
                    action_prefix = action_lower[:-1]
                    if pattern_lower.startswith(action_prefix):
                        return True

    return False


class S3BucketPolicyBaseRule(ComplianceRule):
    """Base class for S3 bucket policy world access checks."""

    resource_type = "AWS::S3::Bucket"
    severity = Severity.CRITICAL
    has_remediation = False
    supports_prefetch = True

    action_patterns: List[str] = []
    action_description: str = ""

    async def evaluate_resources(
        self,
        resources: List["FetchedResource"],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate S3 buckets for world access policies using pre-fetched data."""
        results = []

        for resource in resources:
            attrs = resource.attributes

            if attrs.get("fetch_failed"):
                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=resource.resource_name,
                    status="ERROR",
                    details={"error": attrs.get("error", "Failed to fetch resource")}
                ))
                continue

            policy = attrs.get("policy")
            policy_exists = attrs.get("policy_exists", False)

            allows_world_access = False
            if policy:
                allows_world_access = check_world_access_policy(policy, self.action_patterns)

            # Preserve all resource attributes (including tags) and add compliance-specific fields
            details = dict(attrs)
            details.update({
                "allows_world_access": allows_world_access,
                "policy_exists": policy_exists,
                "action_checked": self.action_description,
            })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                status="FAIL" if allows_world_access else "PASS",
                details=details
            ))

        return results

    async def evaluate(self, session, region: str) -> List[RuleResult]:
        """Legacy evaluate method."""
        results = []

        try:
            s3 = session.client("s3", region_name=region)
            response = s3.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]

                try:
                    location_response = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get("LocationConstraint") or "us-east-1"

                    if bucket_region != region:
                        continue

                    allows_world_access = False
                    policy_exists = False

                    try:
                        policy_response = s3.get_bucket_policy(Bucket=bucket_name)
                        policy = json.loads(policy_response.get("Policy", "{}"))
                        policy_exists = True

                        allows_world_access = check_world_access_policy(
                            policy, self.action_patterns
                        )

                    except ClientError as e:
                        error_code = e.response.get("Error", {}).get("Code", "Unknown")
                        if error_code == "NoSuchBucketPolicy":
                            policy_exists = False
                        else:
                            raise

                    results.append(RuleResult(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        status="FAIL" if allows_world_access else "PASS",
                        details={
                            "allows_world_access": allows_world_access,
                            "policy_exists": policy_exists,
                            "bucket_region": bucket_region,
                            "action_checked": self.action_description,
                        }
                    ))

                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "Unknown")
                    results.append(RuleResult(
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        resource_name=bucket_name,
                        status="ERROR",
                        details={"error": f"{error_code}: {str(e)}"}
                    ))

        except ClientError:
            pass

        return results


class S3WorldStarPolicyRule(S3BucketPolicyBaseRule):
    """Ensures S3 buckets do not have world (*) access for all actions."""

    rule_id = "S3_WORLD_STAR_POLICY"
    name = "S3 Bucket World Star Policy"
    description = "Ensures S3 buckets do not allow public access for all actions (s3:*)"
    action_patterns = ["s3:*", "*"]
    action_description = "All actions (s3:*)"


class S3WorldPutPolicyRule(S3BucketPolicyBaseRule):
    """Ensures S3 buckets do not have world access for Put actions."""

    rule_id = "S3_WORLD_PUT_POLICY"
    name = "S3 Bucket World Put Policy"
    description = "Ensures S3 buckets do not allow public access for Put actions"
    action_patterns = ["s3:Put*", "s3:PutObject", "s3:PutObjectAcl", "s3:PutObjectTagging"]
    action_description = "Put actions"


class S3WorldListPolicyRule(S3BucketPolicyBaseRule):
    """Ensures S3 buckets do not have world access for List actions."""

    rule_id = "S3_WORLD_LIST_POLICY"
    name = "S3 Bucket World List Policy"
    description = "Ensures S3 buckets do not allow public access for List actions"
    action_patterns = ["s3:List*", "s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"]
    action_description = "List actions"


class S3WorldGetPolicyRule(S3BucketPolicyBaseRule):
    """Ensures S3 buckets do not have world access for Get actions."""

    rule_id = "S3_WORLD_GET_POLICY"
    name = "S3 Bucket World Get Policy"
    description = "Ensures S3 buckets do not allow public access for Get actions"
    action_patterns = ["s3:Get*", "s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectTagging", "s3:GetBucketAcl"]
    action_description = "Get actions"


class S3WorldDeletePolicyRule(S3BucketPolicyBaseRule):
    """Ensures S3 buckets do not have world access for Delete actions."""

    rule_id = "S3_WORLD_DELETE_POLICY"
    name = "S3 Bucket World Delete Policy"
    description = "Ensures S3 buckets do not allow public access for Delete actions"
    action_patterns = ["s3:Delete*", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket"]
    action_description = "Delete actions"
