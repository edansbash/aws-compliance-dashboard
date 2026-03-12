from app.services.rules.base import ComplianceRule, RuleResult

# EC2, EBS, and AMI Rules
from app.services.rules.ec2_rules import (
    EC2PublicIPRule,
    EBSSnapshotEncryptionRule,
    EBSVolumeEncryptionRule,
    EBSSnapshotPublicRule,
    AMIPublicRule,
)

# S3 Rules
from app.services.rules.s3_rules import (
    S3VersioningRule,
    S3MFADeleteRule,
    S3EncryptionRule,
    S3AllowsCleartextRule,
    S3WorldStarPolicyRule,
    S3WorldPutPolicyRule,
    S3WorldListPolicyRule,
    S3WorldGetPolicyRule,
    S3WorldDeletePolicyRule,
)
# Security Group Rules
from app.services.rules.security_group_rules import (
    SecurityGroupSSHOpenRule,
    SecurityGroupRDPOpenRule,
    SecurityGroupFTPOpenRule,
    SecurityGroupTelnetOpenRule,
    SecurityGroupPostgresOpenRule,
    SecurityGroupAllTCPOpenRule,
    SecurityGroupAllUDPOpenRule,
    SecurityGroupAllPortsOpenRule,
    SecurityGroupICMPOpenRule,
    SecurityGroupSMTPOpenRule,
    SecurityGroupNFSOpenRule,
    SecurityGroupOracleOpenRule,
    SecurityGroupMsSQLOpenRule,
    SecurityGroupMongoDBOpenRule,
    SecurityGroupDNSOpenRule,
    SecurityGroupMySQLOpenRule,
    SecurityGroupPortRangeRule,
    SecurityGroupAllPortsToSelfRule,
    SecurityGroupAWSIPRangeRule,
    DefaultSecurityGroupInUseRule,
    UnusedSecurityGroupRule,
)

# IAM Account-level Rules
from app.services.rules.iam_account import (
    IAMRootAccessKeysRule,
    IAMRootActiveCertificatesRule,
    IAMRootMFARule,
)

# IAM Credential Rules
from app.services.rules.iam_credentials import (
    IAMUserInactiveKeyRotationRule,
    IAMUserActiveKeyRotationRule,
    IAMUserMultipleAccessKeysRule,
    IAMUnusedCredentialsRule,
    IAMUserMFARule,
    IAMGroupNoUsersRule,
)

# IAM Managed Policy Rules
from app.services.rules.iam_managed_policies import (
    IAMManagedPolicyFullPrivilegesRule,
    IAMManagedPolicyAllowsAssumeRoleRule,
    IAMManagedPolicyAllowsPassRoleRule,
    IAMManagedPolicyNotActionRule,
)

# IAM Trust Policy Rules
from app.services.rules.iam_trust_policies import (
    IAMAssumeRolePolicyAllowsAllRule,
    IAMAssumeRoleLacksExternalIdMFARule,
)

# VPC Rules
from app.services.rules.vpc_rules import (
    VPCSubnetFlowLogEnabledRule,
    NetworkACLAllowsAllEgressRule,
    NetworkACLAllowsAllIngressRule,
    VPCNetworkACLNotUsedRule,
    VPCDefaultSecurityGroupAllowsInboundRule,
)

# RDS Rules
from app.services.rules.rds_rules import (
    RDSSecurityGroupAllowsAllRule,
    RDSStorageEncryptionRule,
    RDSInstanceSingleAZRule,
    RDSBackupRetentionPeriodRule,
    RDSInstancePubliclyAccessibleRule,
    RDSBackupEnabledRule,
    RDSAutoMinorVersionUpgradeRule,
    RDSSnapshotPublicRule,
)

# ELBv2 Rules
from app.services.rules.elbv2_rules import (
    ELBv2DeletionProtectionRule,
    ELBv2ListenerAllowsCleartextRule,
    ELBv2NoAccessLogsRule,
    ELBv2OlderSSLPolicyRule,
    ELBv2DropInvalidHeaderFieldsRule,
)

# Redshift Rules
from app.services.rules.redshift_rules import (
    RedshiftClusterEncryptionRule,
    RedshiftClusterPubliclyAccessibleRule,
    RedshiftParameterGroupLoggingRule,
    RedshiftParameterGroupSSLRule,
    RedshiftSecurityGroupAllowsInternetRule,
    RedshiftVersionUpgradeDisabledRule,
)

# SNS Policy Rules
from app.services.rules.sns_rules import (
    SNSWorldAddPermissionRule,
    SNSWorldRemovePermissionRule,
    SNSWorldSetTopicAttributesRule,
    SNSWorldSubscribeRule,
    SNSWorldDeleteTopicRule,
    SNSWorldPublishRule,
    SNSWorldGetTopicAttributesRule,
    SNSWorldListSubscriptionsByTopicRule,
)

# SQS Rules
from app.services.rules.sqs_rules import (
    SQSWorldGetQueueUrlPolicyRule,
    SQSWorldGetQueueAttributesPolicyRule,
    SQSWorldChangeMessageVisibilityPolicyRule,
    SQSWorldDeleteMessagePolicyRule,
    SQSWorldPurgeQueuePolicyRule,
    SQSWorldReceiveMessagePolicyRule,
    SQSWorldSendMessagePolicyRule,
    SQSQueueEncryptionDisabledRule,
)

# SES Rules
from app.services.rules.ses_rules import (
    SESIdentityWorldSendEmailRule,
    SESDKIMNotEnabledRule,
    SESDKIMNotVerifiedRule,
)

# KMS Rules
from app.services.rules.kms_rules import (
    KMSKeyRotationDisabledRule,
)

# ACM Rules
from app.services.rules.acm_rules import (
    ACMCertificateExpirationRule,
)

# CloudTrail Rules
from app.services.rules.cloudtrail_rules import (
    CloudTrailNotMultiRegionRule,
    CloudTrailNoCloudWatchLogsRule,
    CloudTrailNotEncryptedRule,
    CloudTrailLogFileValidationDisabledRule,
)

# IAM Inline Policy Rules (User, Role, Group)
from app.services.rules.iam_inline_policies import (
    # User inline policies
    IAMUserInlinePolicyExistsRule,
    IAMUserInlinePolicyAssumeRoleRule,
    IAMUserInlinePolicyPassRoleRule,
    IAMUserInlinePolicyNotActionRule,
    # Role inline policies
    IAMRoleInlinePolicyExistsRule,
    IAMRoleInlinePolicyAssumeRoleRule,
    IAMRoleInlinePolicyPassRoleRule,
    IAMRoleInlinePolicyNotActionRule,
    # Group inline policies
    IAMGroupInlinePolicyExistsRule,
    IAMGroupInlinePolicyAssumeRoleRule,
    IAMGroupInlinePolicyPassRoleRule,
    IAMGroupInlinePolicyNotActionRule,
)

# Rule registry - maps rule_id to rule class
RULE_REGISTRY = {
    # S3 Rules
    S3VersioningRule.rule_id: S3VersioningRule,
    S3EncryptionRule.rule_id: S3EncryptionRule,
    S3AllowsCleartextRule.rule_id: S3AllowsCleartextRule,
    S3WorldStarPolicyRule.rule_id: S3WorldStarPolicyRule,
    S3WorldPutPolicyRule.rule_id: S3WorldPutPolicyRule,
    S3WorldListPolicyRule.rule_id: S3WorldListPolicyRule,
    S3WorldGetPolicyRule.rule_id: S3WorldGetPolicyRule,
    S3WorldDeletePolicyRule.rule_id: S3WorldDeletePolicyRule,
    S3MFADeleteRule.rule_id: S3MFADeleteRule,
    # EC2, EBS, AMI Rules
    EC2PublicIPRule.rule_id: EC2PublicIPRule,
    EBSSnapshotEncryptionRule.rule_id: EBSSnapshotEncryptionRule,
    EBSVolumeEncryptionRule.rule_id: EBSVolumeEncryptionRule,
    EBSSnapshotPublicRule.rule_id: EBSSnapshotPublicRule,
    AMIPublicRule.rule_id: AMIPublicRule,
    # Security Group Rules
    SecurityGroupSSHOpenRule.rule_id: SecurityGroupSSHOpenRule,
    SecurityGroupRDPOpenRule.rule_id: SecurityGroupRDPOpenRule,
    SecurityGroupFTPOpenRule.rule_id: SecurityGroupFTPOpenRule,
    SecurityGroupTelnetOpenRule.rule_id: SecurityGroupTelnetOpenRule,
    SecurityGroupPostgresOpenRule.rule_id: SecurityGroupPostgresOpenRule,
    SecurityGroupAllTCPOpenRule.rule_id: SecurityGroupAllTCPOpenRule,
    SecurityGroupAllUDPOpenRule.rule_id: SecurityGroupAllUDPOpenRule,
    SecurityGroupAllPortsOpenRule.rule_id: SecurityGroupAllPortsOpenRule,
    SecurityGroupICMPOpenRule.rule_id: SecurityGroupICMPOpenRule,
    SecurityGroupSMTPOpenRule.rule_id: SecurityGroupSMTPOpenRule,
    SecurityGroupNFSOpenRule.rule_id: SecurityGroupNFSOpenRule,
    SecurityGroupOracleOpenRule.rule_id: SecurityGroupOracleOpenRule,
    SecurityGroupMsSQLOpenRule.rule_id: SecurityGroupMsSQLOpenRule,
    SecurityGroupMongoDBOpenRule.rule_id: SecurityGroupMongoDBOpenRule,
    SecurityGroupDNSOpenRule.rule_id: SecurityGroupDNSOpenRule,
    SecurityGroupMySQLOpenRule.rule_id: SecurityGroupMySQLOpenRule,
    SecurityGroupPortRangeRule.rule_id: SecurityGroupPortRangeRule,
    SecurityGroupAllPortsToSelfRule.rule_id: SecurityGroupAllPortsToSelfRule,
    SecurityGroupAWSIPRangeRule.rule_id: SecurityGroupAWSIPRangeRule,
    DefaultSecurityGroupInUseRule.rule_id: DefaultSecurityGroupInUseRule,
    UnusedSecurityGroupRule.rule_id: UnusedSecurityGroupRule,
    # IAM Account Rules
    IAMRootAccessKeysRule.rule_id: IAMRootAccessKeysRule,
    IAMRootActiveCertificatesRule.rule_id: IAMRootActiveCertificatesRule,
    IAMRootMFARule.rule_id: IAMRootMFARule,
    # IAM Credential Rules
    IAMUserInactiveKeyRotationRule.rule_id: IAMUserInactiveKeyRotationRule,
    IAMUserActiveKeyRotationRule.rule_id: IAMUserActiveKeyRotationRule,
    IAMUserMultipleAccessKeysRule.rule_id: IAMUserMultipleAccessKeysRule,
    IAMUnusedCredentialsRule.rule_id: IAMUnusedCredentialsRule,
    IAMUserMFARule.rule_id: IAMUserMFARule,
    IAMGroupNoUsersRule.rule_id: IAMGroupNoUsersRule,
    # IAM Managed Policy Rules
    IAMManagedPolicyFullPrivilegesRule.rule_id: IAMManagedPolicyFullPrivilegesRule,
    IAMManagedPolicyAllowsAssumeRoleRule.rule_id: IAMManagedPolicyAllowsAssumeRoleRule,
    IAMManagedPolicyAllowsPassRoleRule.rule_id: IAMManagedPolicyAllowsPassRoleRule,
    IAMManagedPolicyNotActionRule.rule_id: IAMManagedPolicyNotActionRule,
    # IAM Trust Policy Rules
    IAMAssumeRolePolicyAllowsAllRule.rule_id: IAMAssumeRolePolicyAllowsAllRule,
    IAMAssumeRoleLacksExternalIdMFARule.rule_id: IAMAssumeRoleLacksExternalIdMFARule,
    # IAM User Inline Policy Rules
    IAMUserInlinePolicyExistsRule.rule_id: IAMUserInlinePolicyExistsRule,
    IAMUserInlinePolicyAssumeRoleRule.rule_id: IAMUserInlinePolicyAssumeRoleRule,
    IAMUserInlinePolicyPassRoleRule.rule_id: IAMUserInlinePolicyPassRoleRule,
    IAMUserInlinePolicyNotActionRule.rule_id: IAMUserInlinePolicyNotActionRule,
    # IAM Role Inline Policy Rules
    IAMRoleInlinePolicyExistsRule.rule_id: IAMRoleInlinePolicyExistsRule,
    IAMRoleInlinePolicyAssumeRoleRule.rule_id: IAMRoleInlinePolicyAssumeRoleRule,
    IAMRoleInlinePolicyPassRoleRule.rule_id: IAMRoleInlinePolicyPassRoleRule,
    IAMRoleInlinePolicyNotActionRule.rule_id: IAMRoleInlinePolicyNotActionRule,
    # IAM Group Inline Policy Rules
    IAMGroupInlinePolicyExistsRule.rule_id: IAMGroupInlinePolicyExistsRule,
    IAMGroupInlinePolicyAssumeRoleRule.rule_id: IAMGroupInlinePolicyAssumeRoleRule,
    IAMGroupInlinePolicyPassRoleRule.rule_id: IAMGroupInlinePolicyPassRoleRule,
    IAMGroupInlinePolicyNotActionRule.rule_id: IAMGroupInlinePolicyNotActionRule,
    # VPC Rules
    VPCSubnetFlowLogEnabledRule.rule_id: VPCSubnetFlowLogEnabledRule,
    NetworkACLAllowsAllEgressRule.rule_id: NetworkACLAllowsAllEgressRule,
    NetworkACLAllowsAllIngressRule.rule_id: NetworkACLAllowsAllIngressRule,
    VPCNetworkACLNotUsedRule.rule_id: VPCNetworkACLNotUsedRule,
    VPCDefaultSecurityGroupAllowsInboundRule.rule_id: VPCDefaultSecurityGroupAllowsInboundRule,
    # RDS Rules
    RDSSecurityGroupAllowsAllRule.rule_id: RDSSecurityGroupAllowsAllRule,
    RDSStorageEncryptionRule.rule_id: RDSStorageEncryptionRule,
    RDSInstanceSingleAZRule.rule_id: RDSInstanceSingleAZRule,
    RDSBackupRetentionPeriodRule.rule_id: RDSBackupRetentionPeriodRule,
    RDSInstancePubliclyAccessibleRule.rule_id: RDSInstancePubliclyAccessibleRule,
    RDSBackupEnabledRule.rule_id: RDSBackupEnabledRule,
    RDSAutoMinorVersionUpgradeRule.rule_id: RDSAutoMinorVersionUpgradeRule,
    RDSSnapshotPublicRule.rule_id: RDSSnapshotPublicRule,
    # ELBv2 Rules
    ELBv2DeletionProtectionRule.rule_id: ELBv2DeletionProtectionRule,
    ELBv2ListenerAllowsCleartextRule.rule_id: ELBv2ListenerAllowsCleartextRule,
    ELBv2NoAccessLogsRule.rule_id: ELBv2NoAccessLogsRule,
    ELBv2OlderSSLPolicyRule.rule_id: ELBv2OlderSSLPolicyRule,
    ELBv2DropInvalidHeaderFieldsRule.rule_id: ELBv2DropInvalidHeaderFieldsRule,
    # Redshift Rules
    RedshiftClusterEncryptionRule.rule_id: RedshiftClusterEncryptionRule,
    RedshiftClusterPubliclyAccessibleRule.rule_id: RedshiftClusterPubliclyAccessibleRule,
    RedshiftParameterGroupLoggingRule.rule_id: RedshiftParameterGroupLoggingRule,
    RedshiftParameterGroupSSLRule.rule_id: RedshiftParameterGroupSSLRule,
    RedshiftSecurityGroupAllowsInternetRule.rule_id: RedshiftSecurityGroupAllowsInternetRule,
    RedshiftVersionUpgradeDisabledRule.rule_id: RedshiftVersionUpgradeDisabledRule,
    # SNS Policy Rules
    SNSWorldAddPermissionRule.rule_id: SNSWorldAddPermissionRule,
    SNSWorldRemovePermissionRule.rule_id: SNSWorldRemovePermissionRule,
    SNSWorldSetTopicAttributesRule.rule_id: SNSWorldSetTopicAttributesRule,
    SNSWorldSubscribeRule.rule_id: SNSWorldSubscribeRule,
    SNSWorldDeleteTopicRule.rule_id: SNSWorldDeleteTopicRule,
    SNSWorldPublishRule.rule_id: SNSWorldPublishRule,
    SNSWorldGetTopicAttributesRule.rule_id: SNSWorldGetTopicAttributesRule,
    SNSWorldListSubscriptionsByTopicRule.rule_id: SNSWorldListSubscriptionsByTopicRule,
    # SQS Rules
    SQSWorldGetQueueUrlPolicyRule.rule_id: SQSWorldGetQueueUrlPolicyRule,
    SQSWorldGetQueueAttributesPolicyRule.rule_id: SQSWorldGetQueueAttributesPolicyRule,
    SQSWorldChangeMessageVisibilityPolicyRule.rule_id: SQSWorldChangeMessageVisibilityPolicyRule,
    SQSWorldDeleteMessagePolicyRule.rule_id: SQSWorldDeleteMessagePolicyRule,
    SQSWorldPurgeQueuePolicyRule.rule_id: SQSWorldPurgeQueuePolicyRule,
    SQSWorldReceiveMessagePolicyRule.rule_id: SQSWorldReceiveMessagePolicyRule,
    SQSWorldSendMessagePolicyRule.rule_id: SQSWorldSendMessagePolicyRule,
    SQSQueueEncryptionDisabledRule.rule_id: SQSQueueEncryptionDisabledRule,
    # SES Rules
    SESIdentityWorldSendEmailRule.rule_id: SESIdentityWorldSendEmailRule,
    SESDKIMNotEnabledRule.rule_id: SESDKIMNotEnabledRule,
    SESDKIMNotVerifiedRule.rule_id: SESDKIMNotVerifiedRule,
    # KMS Rules
    KMSKeyRotationDisabledRule.rule_id: KMSKeyRotationDisabledRule,
    # ACM Rules
    ACMCertificateExpirationRule.rule_id: ACMCertificateExpirationRule,
    # CloudTrail Rules
    CloudTrailNotMultiRegionRule.rule_id: CloudTrailNotMultiRegionRule,
    CloudTrailNoCloudWatchLogsRule.rule_id: CloudTrailNoCloudWatchLogsRule,
    CloudTrailNotEncryptedRule.rule_id: CloudTrailNotEncryptedRule,
    CloudTrailLogFileValidationDisabledRule.rule_id: CloudTrailLogFileValidationDisabledRule,
}

__all__ = [
    "ComplianceRule",
    "RuleResult",
    "RULE_REGISTRY",
    # S3
    "S3VersioningRule",
    "S3EncryptionRule",
    "S3AllowsCleartextRule",
    "S3WorldStarPolicyRule",
    "S3WorldPutPolicyRule",
    "S3WorldListPolicyRule",
    "S3WorldGetPolicyRule",
    "S3WorldDeletePolicyRule",
    "S3MFADeleteRule",
    # EC2, EBS, AMI
    "EC2PublicIPRule",
    "EBSSnapshotEncryptionRule",
    "EBSVolumeEncryptionRule",
    "EBSSnapshotPublicRule",
    "AMIPublicRule",
    # Security Groups
    "SecurityGroupSSHOpenRule",
    "SecurityGroupRDPOpenRule",
    "SecurityGroupFTPOpenRule",
    "SecurityGroupTelnetOpenRule",
    "SecurityGroupPostgresOpenRule",
    "SecurityGroupAllTCPOpenRule",
    "SecurityGroupAllUDPOpenRule",
    "SecurityGroupAllPortsOpenRule",
    "SecurityGroupICMPOpenRule",
    "SecurityGroupSMTPOpenRule",
    "SecurityGroupNFSOpenRule",
    "SecurityGroupOracleOpenRule",
    "SecurityGroupMsSQLOpenRule",
    "SecurityGroupMongoDBOpenRule",
    "SecurityGroupDNSOpenRule",
    "SecurityGroupMySQLOpenRule",
    "SecurityGroupPortRangeRule",
    "SecurityGroupAllPortsToSelfRule",
    "SecurityGroupAWSIPRangeRule",
    "DefaultSecurityGroupInUseRule",
    "UnusedSecurityGroupRule",
    # IAM Account
    "IAMRootAccessKeysRule",
    "IAMRootActiveCertificatesRule",
    "IAMRootMFARule",
    # IAM Credentials
    "IAMUserInactiveKeyRotationRule",
    "IAMUserActiveKeyRotationRule",
    "IAMUserMultipleAccessKeysRule",
    "IAMUnusedCredentialsRule",
    "IAMUserMFARule",
    "IAMGroupNoUsersRule",
    # IAM Managed Policies
    "IAMManagedPolicyFullPrivilegesRule",
    "IAMManagedPolicyAllowsAssumeRoleRule",
    "IAMManagedPolicyAllowsPassRoleRule",
    "IAMManagedPolicyNotActionRule",
    # IAM Trust Policies
    "IAMAssumeRolePolicyAllowsAllRule",
    "IAMAssumeRoleLacksExternalIdMFARule",
    # IAM User Inline Policies
    "IAMUserInlinePolicyExistsRule",
    "IAMUserInlinePolicyAssumeRoleRule",
    "IAMUserInlinePolicyPassRoleRule",
    "IAMUserInlinePolicyNotActionRule",
    # IAM Role Inline Policies
    "IAMRoleInlinePolicyExistsRule",
    "IAMRoleInlinePolicyAssumeRoleRule",
    "IAMRoleInlinePolicyPassRoleRule",
    "IAMRoleInlinePolicyNotActionRule",
    # IAM Group Inline Policies
    "IAMGroupInlinePolicyExistsRule",
    "IAMGroupInlinePolicyAssumeRoleRule",
    "IAMGroupInlinePolicyPassRoleRule",
    "IAMGroupInlinePolicyNotActionRule",
    # VPC
    "VPCSubnetFlowLogEnabledRule",
    "NetworkACLAllowsAllEgressRule",
    "NetworkACLAllowsAllIngressRule",
    "VPCNetworkACLNotUsedRule",
    "VPCDefaultSecurityGroupAllowsInboundRule",
    # RDS
    "RDSSecurityGroupAllowsAllRule",
    "RDSStorageEncryptionRule",
    "RDSInstanceSingleAZRule",
    "RDSBackupRetentionPeriodRule",
    "RDSInstancePubliclyAccessibleRule",
    "RDSBackupEnabledRule",
    "RDSAutoMinorVersionUpgradeRule",
    "RDSSnapshotPublicRule",
    # ELBv2
    "ELBv2DeletionProtectionRule",
    "ELBv2ListenerAllowsCleartextRule",
    "ELBv2NoAccessLogsRule",
    "ELBv2OlderSSLPolicyRule",
    "ELBv2DropInvalidHeaderFieldsRule",
    # Redshift
    "RedshiftClusterEncryptionRule",
    "RedshiftClusterPubliclyAccessibleRule",
    "RedshiftParameterGroupLoggingRule",
    "RedshiftParameterGroupSSLRule",
    "RedshiftSecurityGroupAllowsInternetRule",
    "RedshiftVersionUpgradeDisabledRule",
    # SNS Policy
    "SNSWorldAddPermissionRule",
    "SNSWorldRemovePermissionRule",
    "SNSWorldSetTopicAttributesRule",
    "SNSWorldSubscribeRule",
    "SNSWorldDeleteTopicRule",
    "SNSWorldPublishRule",
    "SNSWorldGetTopicAttributesRule",
    "SNSWorldListSubscriptionsByTopicRule",
    # SQS
    "SQSWorldGetQueueUrlPolicyRule",
    "SQSWorldGetQueueAttributesPolicyRule",
    "SQSWorldChangeMessageVisibilityPolicyRule",
    "SQSWorldDeleteMessagePolicyRule",
    "SQSWorldPurgeQueuePolicyRule",
    "SQSWorldReceiveMessagePolicyRule",
    "SQSWorldSendMessagePolicyRule",
    "SQSQueueEncryptionDisabledRule",
    # SES
    "SESIdentityWorldSendEmailRule",
    "SESDKIMNotEnabledRule",
    "SESDKIMNotVerifiedRule",
    # KMS
    "KMSKeyRotationDisabledRule",
    # ACM
    "ACMCertificateExpirationRule",
    # CloudTrail
    "CloudTrailNotMultiRegionRule",
    "CloudTrailNoCloudWatchLogsRule",
    "CloudTrailNotEncryptedRule",
    "CloudTrailLogFileValidationDisabledRule",
]
