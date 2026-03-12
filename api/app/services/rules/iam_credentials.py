"""IAM user credential compliance rules."""
from typing import List
from datetime import datetime, timezone

from app.services.rules.base import ComplianceRule, RuleResult, Severity
from app.services.fetchers.base import FetchedResource


class IAMUserInactiveKeyRotationRule(ComplianceRule):
    """Ensures inactive IAM user access keys are rotated within 90 days."""

    rule_id = "IAM_INACTIVE_KEY_ROTATION"
    name = "IAM User Inactive Key Rotation"
    description = "Ensures IAM user access keys that are inactive are rotated within 90 days"
    resource_type = "AWS::IAM::User"
    severity = Severity.MEDIUM
    has_remediation = False
    supports_prefetch = True

    MAX_KEY_AGE_DAYS = 90

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched IAM users for inactive key rotation compliance."""
        results = []

        # IAM is global, only evaluate for us-east-1 resources
        for resource in resources:
            attrs = resource.attributes
            user_name = attrs.get("user_name", resource.resource_name)
            access_keys = attrs.get("access_keys", [])

            # Check inactive keys
            inactive_old_keys = []
            all_keys = []
            now = datetime.now(timezone.utc)

            for key in access_keys:
                key_id = key.get("access_key_id")
                key_status = key.get("status")
                create_date = key.get("create_date")

                # Calculate key age
                key_age_days = None
                if create_date:
                    if isinstance(create_date, str):
                        create_date = datetime.fromisoformat(create_date.replace('Z', '+00:00'))
                    key_age_days = (now - create_date).days

                key_info = {
                    "key_id": key_id,
                    "status": key_status,
                    "create_date": create_date.isoformat() if hasattr(create_date, 'isoformat') else create_date,
                    "age_days": key_age_days,
                }
                all_keys.append(key_info)

                # Check if inactive and older than threshold
                if key_status == "Inactive" and key_age_days and key_age_days > self.MAX_KEY_AGE_DAYS:
                    inactive_old_keys.append(key_info)

            # Only evaluate users who have inactive keys
            if any(k["status"] == "Inactive" for k in all_keys):
                is_compliant = len(inactive_old_keys) == 0

                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=user_name,
                    status="PASS" if is_compliant else "FAIL",
                    details={
                        "user_name": user_name,
                        "access_keys": all_keys,
                        "non_compliant_keys": inactive_old_keys,
                        "max_key_age_days": self.MAX_KEY_AGE_DAYS,
                        "message": f"User has {len(inactive_old_keys)} inactive key(s) older than {self.MAX_KEY_AGE_DAYS} days" if not is_compliant else "All inactive keys are within rotation period"
                    }
                ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Delete or rotate inactive access keys that are older than 90 days"


class IAMUserActiveKeyRotationRule(ComplianceRule):
    """Ensures active IAM user access keys are rotated within 90 days."""

    rule_id = "IAM_ACTIVE_KEY_ROTATION"
    name = "IAM User Active Key Rotation"
    description = "Ensures IAM user access keys that are active are rotated within 90 days"
    resource_type = "AWS::IAM::User"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    MAX_KEY_AGE_DAYS = 90

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched IAM users for active key rotation compliance."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            user_name = attrs.get("user_name", resource.resource_name)
            access_keys = attrs.get("access_keys", [])

            # Check active keys
            active_old_keys = []
            all_keys = []
            now = datetime.now(timezone.utc)

            for key in access_keys:
                key_id = key.get("access_key_id")
                key_status = key.get("status")
                create_date = key.get("create_date")

                # Calculate key age
                key_age_days = None
                if create_date:
                    if isinstance(create_date, str):
                        create_date = datetime.fromisoformat(create_date.replace('Z', '+00:00'))
                    key_age_days = (now - create_date).days

                key_info = {
                    "key_id": key_id,
                    "status": key_status,
                    "create_date": create_date.isoformat() if hasattr(create_date, 'isoformat') else create_date,
                    "age_days": key_age_days,
                }
                all_keys.append(key_info)

                # Check if active and older than threshold
                if key_status == "Active" and key_age_days and key_age_days > self.MAX_KEY_AGE_DAYS:
                    active_old_keys.append(key_info)

            # Only evaluate users who have active keys
            if any(k["status"] == "Active" for k in all_keys):
                is_compliant = len(active_old_keys) == 0

                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=user_name,
                    status="PASS" if is_compliant else "FAIL",
                    details={
                        "user_name": user_name,
                        "access_keys": all_keys,
                        "non_compliant_keys": active_old_keys,
                        "max_key_age_days": self.MAX_KEY_AGE_DAYS,
                        "message": f"User has {len(active_old_keys)} active key(s) older than {self.MAX_KEY_AGE_DAYS} days" if not is_compliant else "All active keys are within rotation period"
                    }
                ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Rotate active access keys that are older than 90 days"


class IAMUserMultipleAccessKeysRule(ComplianceRule):
    """Ensures IAM users do not have multiple access keys."""

    rule_id = "IAM_USER_MULTIPLE_ACCESS_KEYS"
    name = "IAM User Multiple Access Keys"
    description = "Ensures IAM users do not have more than one access key (indicates poor key management)"
    resource_type = "AWS::IAM::User"
    severity = Severity.MEDIUM
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched IAM users for multiple access keys."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            user_name = attrs.get("user_name", resource.resource_name)
            access_keys = attrs.get("access_keys", [])
            now = datetime.now(timezone.utc)

            all_keys = []
            for key in access_keys:
                create_date = key.get("create_date")
                key_age_days = None
                if create_date:
                    if isinstance(create_date, str):
                        create_date = datetime.fromisoformat(create_date.replace('Z', '+00:00'))
                    key_age_days = (now - create_date).days

                key_info = {
                    "key_id": key.get("access_key_id"),
                    "status": key.get("status"),
                    "create_date": create_date.isoformat() if hasattr(create_date, 'isoformat') else create_date,
                    "age_days": key_age_days,
                }
                all_keys.append(key_info)

            # Only evaluate users who have access keys
            if len(all_keys) > 0:
                is_compliant = len(all_keys) <= 1

                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=user_name,
                    status="PASS" if is_compliant else "FAIL",
                    details={
                        "user_name": user_name,
                        "access_key_count": len(all_keys),
                        "access_keys": all_keys,
                        "message": f"User has {len(all_keys)} access keys (should have at most 1)" if not is_compliant else "User has 1 or fewer access keys"
                    }
                ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Delete unused access keys and ensure each user has at most one active access key"


class IAMUnusedCredentialsRule(ComplianceRule):
    """Ensures IAM user credentials that have not been used in 90 days are disabled."""

    rule_id = "IAM_UNUSED_CREDENTIALS"
    name = "IAM Unused Credentials"
    description = "Ensures IAM user credentials (password or access keys) unused for 90+ days are identified"
    resource_type = "AWS::IAM::User"
    severity = Severity.MEDIUM
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    MAX_UNUSED_DAYS = 90

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched IAM users for unused credentials."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            user_name = attrs.get("user_name", resource.resource_name)
            now = datetime.now(timezone.utc)

            unused_credentials = []
            all_credentials = []

            # Check password last used
            password_last_used = attrs.get("password_last_used")
            if password_last_used:
                if isinstance(password_last_used, str):
                    password_last_used = datetime.fromisoformat(password_last_used.replace('Z', '+00:00'))
                days_since_used = (now - password_last_used).days
                cred_info = {
                    "type": "password",
                    "last_used": password_last_used.isoformat() if hasattr(password_last_used, 'isoformat') else password_last_used,
                    "days_since_used": days_since_used,
                }
                all_credentials.append(cred_info)
                if days_since_used > self.MAX_UNUSED_DAYS:
                    unused_credentials.append(cred_info)

            # Check access keys from pre-fetched data
            access_keys = attrs.get("access_keys", [])
            for key in access_keys:
                if key.get("status") != "Active":
                    continue

                key_id = key.get("access_key_id")
                last_used_date = key.get("last_used_date")
                create_date = key.get("create_date")

                if last_used_date:
                    if isinstance(last_used_date, str):
                        last_used_date = datetime.fromisoformat(last_used_date.replace('Z', '+00:00'))
                    days_since_used = (now - last_used_date).days
                else:
                    # Key has never been used - use creation date
                    if isinstance(create_date, str):
                        create_date = datetime.fromisoformat(create_date.replace('Z', '+00:00'))
                    days_since_used = (now - create_date).days if create_date else 0

                cred_info = {
                    "type": "access_key",
                    "key_id": key_id,
                    "last_used": last_used_date.isoformat() if hasattr(last_used_date, 'isoformat') else last_used_date,
                    "days_since_used": days_since_used,
                    "never_used": last_used_date is None,
                }
                all_credentials.append(cred_info)

                if days_since_used > self.MAX_UNUSED_DAYS:
                    unused_credentials.append(cred_info)

            # Only report if user has credentials
            if all_credentials:
                is_compliant = len(unused_credentials) == 0

                results.append(RuleResult(
                    resource_id=resource.resource_id,
                    resource_name=user_name,
                    status="PASS" if is_compliant else "FAIL",
                    details={
                        "user_name": user_name,
                        "all_credentials": all_credentials,
                        "unused_credentials": unused_credentials,
                        "max_unused_days": self.MAX_UNUSED_DAYS,
                        "tags": attrs.get("tags", {}),
                        "message": f"User has {len(unused_credentials)} credential(s) unused for over {self.MAX_UNUSED_DAYS} days" if not is_compliant else "All credentials have been used recently"
                    }
                ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Delete the IAM user with unused credentials."""
        user_name = resource_id.split("/")[-1]
        iam = session.client("iam", region_name=region)

        # Delete access keys
        access_keys = iam.list_access_keys(UserName=user_name)
        for key in access_keys.get("AccessKeyMetadata", []):
            iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])

        # Delete MFA devices
        mfa_devices = iam.list_mfa_devices(UserName=user_name)
        for device in mfa_devices.get("MFADevices", []):
            iam.deactivate_mfa_device(UserName=user_name, SerialNumber=device["SerialNumber"])
            # Delete virtual MFA device if it exists
            if "arn:aws:iam::" in device["SerialNumber"] and ":mfa/" in device["SerialNumber"]:
                try:
                    iam.delete_virtual_mfa_device(SerialNumber=device["SerialNumber"])
                except Exception:
                    pass  # May fail if hardware MFA or already deleted

        # Delete login profile (console password)
        try:
            iam.delete_login_profile(UserName=user_name)
        except iam.exceptions.NoSuchEntityException:
            pass  # User may not have console access

        # Detach managed policies
        attached_policies = iam.list_attached_user_policies(UserName=user_name)
        for policy in attached_policies.get("AttachedPolicies", []):
            iam.detach_user_policy(UserName=user_name, PolicyArn=policy["PolicyArn"])

        # Delete inline policies
        inline_policies = iam.list_user_policies(UserName=user_name)
        for policy_name in inline_policies.get("PolicyNames", []):
            iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)

        # Remove from groups
        groups = iam.list_groups_for_user(UserName=user_name)
        for group in groups.get("Groups", []):
            iam.remove_user_from_group(UserName=user_name, GroupName=group["GroupName"])

        # Delete signing certificates
        signing_certs = iam.list_signing_certificates(UserName=user_name)
        for cert in signing_certs.get("Certificates", []):
            iam.delete_signing_certificate(UserName=user_name, CertificateId=cert["CertificateId"])

        # Delete SSH public keys
        ssh_keys = iam.list_ssh_public_keys(UserName=user_name)
        for key in ssh_keys.get("SSHPublicKeys", []):
            iam.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key["SSHPublicKeyId"])

        # Delete service-specific credentials
        service_creds = iam.list_service_specific_credentials(UserName=user_name)
        for cred in service_creds.get("ServiceSpecificCredentials", []):
            iam.delete_service_specific_credential(
                UserName=user_name,
                ServiceSpecificCredentialId=cred["ServiceSpecificCredentialId"]
            )

        # Finally, delete the user
        iam.delete_user(UserName=user_name)

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Delete the IAM user with unused credentials"

    @classmethod
    def get_expected_state(cls, current_details: dict) -> dict:
        return {
            "user_deleted": True,
            "message": "IAM user will be deleted",
        }


class IAMUserMFARule(ComplianceRule):
    """Ensures IAM users have MFA enabled."""

    rule_id = "IAM_USER_MFA"
    name = "IAM User MFA Enabled"
    description = "Ensures IAM users with console access have multi-factor authentication (MFA) enabled"
    resource_type = "AWS::IAM::User"
    severity = Severity.HIGH
    has_remediation = False
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched IAM users for MFA configuration."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            user_name = attrs.get("user_name", resource.resource_name)

            has_console_access = attrs.get("has_console_access", False)

            # Only check MFA for users with console access
            if not has_console_access:
                continue

            mfa_devices = attrs.get("mfa_devices", [])
            has_mfa = len(mfa_devices) > 0

            mfa_device_info = []
            for device in mfa_devices:
                mfa_device_info.append({
                    "serial_number": device.get("serial_number"),
                    "enable_date": device.get("enable_date"),
                })

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=user_name,
                status="PASS" if has_mfa else "FAIL",
                details={
                    "user_name": user_name,
                    "has_console_access": has_console_access,
                    "mfa_enabled": has_mfa,
                    "mfa_device_count": len(mfa_devices),
                    "mfa_devices": mfa_device_info,
                    "message": "User has console access but no MFA device configured" if not has_mfa else f"User has {len(mfa_devices)} MFA device(s) configured"
                }
            ))

        return results

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Enable MFA for the IAM user using a hardware or virtual MFA device"


class IAMGroupNoUsersRule(ComplianceRule):
    """Identifies IAM groups that have no users."""

    rule_id = "IAM_GROUP_NO_USERS"
    name = "IAM Group with No Users"
    description = "Identifies IAM groups that have no users assigned, which may indicate unused or orphaned groups"
    resource_type = "AWS::IAM::Group"
    severity = Severity.LOW
    has_remediation = True
    remediation_tested = True
    supports_prefetch = True

    async def evaluate_resources(
        self,
        resources: List[FetchedResource],
        session,
        region: str,
    ) -> List[RuleResult]:
        """Evaluate pre-fetched IAM groups for user membership."""
        results = []

        for resource in resources:
            attrs = resource.attributes
            group_name = attrs.get("group_name", resource.resource_name)

            user_count = attrs.get("user_count", 0)
            user_names = attrs.get("users", [])
            create_date = attrs.get("create_date")

            is_empty = user_count == 0

            results.append(RuleResult(
                resource_id=resource.resource_id,
                resource_name=group_name,
                status="FAIL" if is_empty else "PASS",
                details={
                    "group_name": group_name,
                    "user_count": user_count,
                    "users": user_names,
                    "create_date": create_date,
                    "message": "Group has no users and may be a candidate for removal" if is_empty else f"Group has {user_count} user(s)"
                }
            ))

        return results

    async def remediate(self, session, resource_id: str, region: str, finding_details: dict = None) -> bool:
        """Delete the empty IAM group."""
        group_name = resource_id.split("/")[-1]

        iam = session.client("iam", region_name=region)

        # First, detach all managed policies
        attached_policies = iam.list_attached_group_policies(GroupName=group_name)
        for policy in attached_policies.get("AttachedPolicies", []):
            iam.detach_group_policy(GroupName=group_name, PolicyArn=policy["PolicyArn"])

        # Delete all inline policies
        inline_policies = iam.list_group_policies(GroupName=group_name)
        for policy_name in inline_policies.get("PolicyNames", []):
            iam.delete_group_policy(GroupName=group_name, PolicyName=policy_name)

        # Delete the group
        iam.delete_group(GroupName=group_name)

        return True

    @classmethod
    def get_remediation_description(cls) -> str:
        return "Delete the empty IAM group after confirming it is no longer needed"
