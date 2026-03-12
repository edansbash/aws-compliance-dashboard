"""IAM resource fetcher - fetches IAM users, roles, groups, and policies."""

from typing import List
from datetime import datetime, timezone
from botocore.exceptions import ClientError

from app.services.fetchers.base import ResourceFetcher, FetchedResource


class IAMResourceFetcher(ResourceFetcher):
    """
    Fetches IAM resources including users, roles, groups, and policies.

    This fetcher collects:
    - IAM users with access keys, MFA devices, and credentials
    - IAM roles with trust policies
    - IAM groups with user memberships
    - IAM managed policies with policy documents
    - Account summary for root account checks
    """

    resource_types = [
        "AWS::IAM::User",
        "AWS::IAM::Role",
        "AWS::IAM::Group",
        "AWS::IAM::Policy",
        "AWS::IAM::ManagedPolicy",  # Alias for Policy
        "AWS::IAM::AccountSummary",
    ]

    # IAM is global, only run in us-east-1
    is_global = True
    global_region = "us-east-1"

    async def fetch(
        self,
        session,
        region: str,
        account_id: str,
        resource_type: str,
    ) -> List[FetchedResource]:
        """Fetch IAM resources based on resource type."""
        if resource_type == "AWS::IAM::User":
            return await self._fetch_users(session, region, account_id)
        elif resource_type == "AWS::IAM::Role":
            return await self._fetch_roles(session, region, account_id)
        elif resource_type == "AWS::IAM::Group":
            return await self._fetch_groups(session, region, account_id)
        elif resource_type == "AWS::IAM::Policy":
            return await self._fetch_policies(session, region, account_id)
        elif resource_type == "AWS::IAM::ManagedPolicy":
            return await self._fetch_policies(session, region, account_id)
        elif resource_type == "AWS::IAM::AccountSummary":
            return await self._fetch_account_summary(session, region, account_id)
        return []

    async def _fetch_users(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all IAM users with access keys, MFA, and credentials."""
        resources = []

        try:
            iam = session.client("iam", region_name=region)
            paginator = iam.get_paginator("list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    user_arn = user["Arn"]
                    now = datetime.now(timezone.utc)

                    # Get access keys
                    access_keys = []
                    try:
                        keys_response = iam.list_access_keys(UserName=user_name)
                        for key in keys_response.get("AccessKeyMetadata", []):
                            key_age_days = (now - key["CreateDate"]).days

                            # Get last used info
                            last_used_date = None
                            days_since_used = None
                            never_used = True
                            try:
                                last_used_response = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                                last_used_info = last_used_response.get("AccessKeyLastUsed", {})
                                last_used_date = last_used_info.get("LastUsedDate")
                                if last_used_date:
                                    days_since_used = (now - last_used_date).days
                                    never_used = False
                                else:
                                    days_since_used = key_age_days
                            except ClientError:
                                pass

                            access_keys.append({
                                "key_id": key["AccessKeyId"],
                                "status": key["Status"],
                                "create_date": key["CreateDate"].isoformat(),
                                "age_days": key_age_days,
                                "last_used": last_used_date.isoformat() if last_used_date else None,
                                "days_since_used": days_since_used,
                                "never_used": never_used,
                            })
                    except ClientError:
                        pass

                    # Check console access
                    has_console_access = False
                    try:
                        iam.get_login_profile(UserName=user_name)
                        has_console_access = True
                    except ClientError as e:
                        if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
                            pass

                    # Get MFA devices
                    mfa_devices = []
                    try:
                        mfa_response = iam.list_mfa_devices(UserName=user_name)
                        for device in mfa_response.get("MFADevices", []):
                            mfa_devices.append({
                                "serial_number": device.get("SerialNumber"),
                                "enable_date": device.get("EnableDate").isoformat() if device.get("EnableDate") else None,
                            })
                    except ClientError:
                        pass

                    # Get inline policies
                    inline_policies = []
                    try:
                        inline_response = iam.list_user_policies(UserName=user_name)
                        for policy_name in inline_response.get("PolicyNames", []):
                            try:
                                policy_doc_response = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                                inline_policies.append({
                                    "policy_name": policy_name,
                                    "policy_document": policy_doc_response.get("PolicyDocument"),
                                })
                            except ClientError:
                                inline_policies.append({"policy_name": policy_name, "policy_document": None})
                    except ClientError:
                        pass

                    # Get attached managed policies
                    attached_policies = []
                    try:
                        attached_response = iam.list_attached_user_policies(UserName=user_name)
                        attached_policies = attached_response.get("AttachedPolicies", [])
                    except ClientError:
                        pass

                    # Get user tags
                    tags = {}
                    try:
                        tags_response = iam.list_user_tags(UserName=user_name)
                        for tag in tags_response.get("Tags", []):
                            tags[tag["Key"]] = tag["Value"]
                    except ClientError:
                        pass

                    # Password last used
                    password_last_used = user.get("PasswordLastUsed")
                    password_days_since_used = None
                    if password_last_used:
                        password_days_since_used = (now - password_last_used).days

                    attributes = {
                        "user_name": user_name,
                        "user_id": user.get("UserId"),
                        "create_date": user.get("CreateDate").isoformat() if user.get("CreateDate") else None,
                        "password_last_used": password_last_used.isoformat() if password_last_used else None,
                        "password_days_since_used": password_days_since_used,
                        "has_console_access": has_console_access,
                        "access_keys": access_keys,
                        "access_key_count": len(access_keys),
                        "mfa_devices": mfa_devices,
                        "mfa_enabled": len(mfa_devices) > 0,
                        "inline_policies": inline_policies,
                        "inline_policy_count": len(inline_policies),
                        "attached_policies": attached_policies,
                        "attached_policy_count": len(attached_policies),
                        "tags": tags,
                    }

                    resource = FetchedResource(
                        resource_id=user_arn,
                        resource_name=user_name,
                        resource_type="AWS::IAM::User",
                        region=region,
                        account_id=account_id,
                        raw_data=user,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_roles(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all IAM roles with trust policies and inline policies."""
        resources = []

        try:
            iam = session.client("iam", region_name=region)
            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]

                    # Get inline policies
                    inline_policies = []
                    try:
                        inline_response = iam.list_role_policies(RoleName=role_name)
                        for policy_name in inline_response.get("PolicyNames", []):
                            try:
                                policy_doc_response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                                inline_policies.append({
                                    "policy_name": policy_name,
                                    "policy_document": policy_doc_response.get("PolicyDocument"),
                                })
                            except ClientError:
                                inline_policies.append({"policy_name": policy_name, "policy_document": None})
                    except ClientError:
                        pass

                    # Get attached managed policies
                    attached_policies = []
                    try:
                        attached_response = iam.list_attached_role_policies(RoleName=role_name)
                        attached_policies = attached_response.get("AttachedPolicies", [])
                    except ClientError:
                        pass

                    attributes = {
                        "role_name": role_name,
                        "role_id": role.get("RoleId"),
                        "create_date": role.get("CreateDate").isoformat() if role.get("CreateDate") else None,
                        "assume_role_policy_document": role.get("AssumeRolePolicyDocument"),
                        "description": role.get("Description"),
                        "max_session_duration": role.get("MaxSessionDuration"),
                        "path": role.get("Path"),
                        "inline_policies": inline_policies,
                        "inline_policy_count": len(inline_policies),
                        "attached_policies": attached_policies,
                        "attached_policy_count": len(attached_policies),
                    }

                    resource = FetchedResource(
                        resource_id=role_arn,
                        resource_name=role_name,
                        resource_type="AWS::IAM::Role",
                        region=region,
                        account_id=account_id,
                        raw_data=role,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_groups(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all IAM groups with user memberships."""
        resources = []

        try:
            iam = session.client("iam", region_name=region)
            paginator = iam.get_paginator("list_groups")

            for page in paginator.paginate():
                for group in page.get("Groups", []):
                    group_name = group["GroupName"]
                    group_arn = group["Arn"]

                    # Get users in group
                    users = []
                    try:
                        group_response = iam.get_group(GroupName=group_name)
                        users = [u["UserName"] for u in group_response.get("Users", [])]
                    except ClientError:
                        pass

                    # Get inline policies
                    inline_policies = []
                    try:
                        inline_response = iam.list_group_policies(GroupName=group_name)
                        for policy_name in inline_response.get("PolicyNames", []):
                            try:
                                policy_doc_response = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                                inline_policies.append({
                                    "policy_name": policy_name,
                                    "policy_document": policy_doc_response.get("PolicyDocument"),
                                })
                            except ClientError:
                                inline_policies.append({"policy_name": policy_name, "policy_document": None})
                    except ClientError:
                        pass

                    # Get attached managed policies
                    attached_policies = []
                    try:
                        attached_response = iam.list_attached_group_policies(GroupName=group_name)
                        attached_policies = attached_response.get("AttachedPolicies", [])
                    except ClientError:
                        pass

                    attributes = {
                        "group_name": group_name,
                        "group_id": group.get("GroupId"),
                        "create_date": group.get("CreateDate").isoformat() if group.get("CreateDate") else None,
                        "path": group.get("Path"),
                        "users": users,
                        "user_count": len(users),
                        "inline_policies": inline_policies,
                        "inline_policy_count": len(inline_policies),
                        "attached_policies": attached_policies,
                        "attached_policy_count": len(attached_policies),
                    }

                    resource = FetchedResource(
                        resource_id=group_arn,
                        resource_name=group_name,
                        resource_type="AWS::IAM::Group",
                        region=region,
                        account_id=account_id,
                        raw_data=group,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_policies(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch all customer-managed IAM policies with policy documents."""
        resources = []

        try:
            iam = session.client("iam", region_name=region)
            paginator = iam.get_paginator("list_policies")

            # Only get customer-managed policies
            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_name = policy["PolicyName"]
                    policy_arn = policy["Arn"]

                    # Get the default policy version document
                    policy_document = None
                    try:
                        version_response = iam.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=policy["DefaultVersionId"]
                        )
                        policy_document = version_response.get("PolicyVersion", {}).get("Document")
                    except ClientError:
                        pass

                    attributes = {
                        "policy_name": policy_name,
                        "policy_id": policy.get("PolicyId"),
                        "default_version_id": policy.get("DefaultVersionId"),
                        "attachment_count": policy.get("AttachmentCount", 0),
                        "permissions_boundary_usage_count": policy.get("PermissionsBoundaryUsageCount", 0),
                        "is_attachable": policy.get("IsAttachable", True),
                        "create_date": policy.get("CreateDate").isoformat() if policy.get("CreateDate") else None,
                        "update_date": policy.get("UpdateDate").isoformat() if policy.get("UpdateDate") else None,
                        "policy_document": policy_document,
                    }

                    resource = FetchedResource(
                        resource_id=policy_arn,
                        resource_name=policy_name,
                        resource_type="AWS::IAM::Policy",
                        region=region,
                        account_id=account_id,
                        raw_data=policy,
                        attributes=attributes,
                    )
                    resources.append(resource)

        except ClientError:
            pass

        return resources

    async def _fetch_account_summary(
        self,
        session,
        region: str,
        account_id: str,
    ) -> List[FetchedResource]:
        """Fetch IAM account summary for root account checks."""
        resources = []

        try:
            iam = session.client("iam", region_name=region)

            # Get account summary
            summary_response = iam.get_account_summary()
            summary_map = summary_response.get("SummaryMap", {})

            # AccountMFAEnabled from summary is the authoritative source for root MFA
            # (1 = enabled, 0 = disabled)
            root_mfa_enabled = summary_map.get("AccountMFAEnabled", 0) == 1

            # Get credential report for additional root account details (access keys, certs)
            root_access_keys = []
            root_has_active_certs = False
            root_password_enabled = True  # Assume enabled unless we can confirm otherwise
            credential_report_available = False
            try:
                # Generate and get credential report
                iam.generate_credential_report()
                import time
                time.sleep(2)  # Wait for report generation
                report_response = iam.get_credential_report()
                report_content = report_response.get("Content", b"").decode("utf-8")
                credential_report_available = True

                # Parse CSV report
                import csv
                from io import StringIO
                reader = csv.DictReader(StringIO(report_content))
                for row in reader:
                    if row.get("user") == "<root_account>":
                        # Check if root password/credentials are enabled
                        # If disabled, this indicates AWS Organizations centralized root management
                        root_password_enabled = row.get("password_enabled", "").lower() == "true"
                        if row.get("access_key_1_active", "").lower() == "true":
                            root_access_keys.append({
                                "key_number": 1,
                                "active": True,
                                "last_used": row.get("access_key_1_last_used_date"),
                            })
                        if row.get("access_key_2_active", "").lower() == "true":
                            root_access_keys.append({
                                "key_number": 2,
                                "active": True,
                                "last_used": row.get("access_key_2_last_used_date"),
                            })
                        if row.get("cert_1_active", "").lower() == "true":
                            root_has_active_certs = True
                        if row.get("cert_2_active", "").lower() == "true":
                            root_has_active_certs = True
                        break
            except ClientError:
                pass

            # Detect if root credentials are centrally managed (AWS Organizations)
            # If password is disabled AND no access keys, root is likely managed centrally
            root_credentials_disabled = (
                credential_report_available and
                not root_password_enabled and
                len(root_access_keys) == 0
            )

            attributes = {
                "account_mfa_enabled": root_mfa_enabled,
                "root_mfa_enabled": root_mfa_enabled,
                "credential_report_available": credential_report_available,
                "root_password_enabled": root_password_enabled,
                "root_credentials_disabled": root_credentials_disabled,
                "root_access_keys": root_access_keys,
                "root_has_access_keys": len(root_access_keys) > 0,
                "root_has_active_certs": root_has_active_certs,
                "users": summary_map.get("Users", 0),
                "groups": summary_map.get("Groups", 0),
                "roles": summary_map.get("Roles", 0),
                "policies": summary_map.get("Policies", 0),
                "access_keys_per_user_quota": summary_map.get("AccessKeysPerUserQuota", 0),
                "summary_map": summary_map,
            }

            resource = FetchedResource(
                resource_id=f"arn:aws:iam::{account_id}:root",
                resource_name="AWS Account Root",
                resource_type="AWS::IAM::AccountSummary",
                region=region,
                account_id=account_id,
                raw_data=summary_map,
                attributes=attributes,
            )
            resources.append(resource)

        except ClientError:
            pass

        return resources
