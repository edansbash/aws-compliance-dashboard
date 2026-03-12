"""Resource fetchers for efficient AWS resource collection."""

from app.services.fetchers.base import ResourceFetcher, ResourceCache
from app.services.fetchers.s3_fetcher import S3ResourceFetcher
from app.services.fetchers.security_group_fetcher import SecurityGroupResourceFetcher
from app.services.fetchers.ec2_fetcher import EC2ResourceFetcher
from app.services.fetchers.rds_fetcher import RDSResourceFetcher
from app.services.fetchers.iam_fetcher import IAMResourceFetcher
from app.services.fetchers.vpc_fetcher import VPCResourceFetcher
from app.services.fetchers.elbv2_fetcher import ELBv2ResourceFetcher
from app.services.fetchers.redshift_fetcher import RedshiftResourceFetcher
from app.services.fetchers.sns_fetcher import SNSResourceFetcher
from app.services.fetchers.sqs_fetcher import SQSResourceFetcher
from app.services.fetchers.ses_fetcher import SESResourceFetcher
from app.services.fetchers.kms_fetcher import KMSResourceFetcher
from app.services.fetchers.acm_fetcher import ACMResourceFetcher
from app.services.fetchers.cloudtrail_fetcher import CloudTrailResourceFetcher

# Registry mapping resource types to their fetchers
FETCHER_REGISTRY = {
    # S3
    "AWS::S3::Bucket": S3ResourceFetcher,
    # EC2, EBS, AMI
    "AWS::EC2::Instance": EC2ResourceFetcher,
    "AWS::EC2::Volume": EC2ResourceFetcher,
    "AWS::EC2::Snapshot": EC2ResourceFetcher,
    "AWS::EC2::Image": EC2ResourceFetcher,
    "AWS::EC2::SecurityGroup": SecurityGroupResourceFetcher,
    # IAM
    "AWS::IAM::User": IAMResourceFetcher,
    "AWS::IAM::Role": IAMResourceFetcher,
    "AWS::IAM::Group": IAMResourceFetcher,
    "AWS::IAM::Policy": IAMResourceFetcher,
    "AWS::IAM::ManagedPolicy": IAMResourceFetcher,  # Alias for Policy
    "AWS::IAM::AccountSummary": IAMResourceFetcher,
    # VPC
    "AWS::EC2::VPC": VPCResourceFetcher,
    "AWS::EC2::Subnet": VPCResourceFetcher,
    "AWS::EC2::NetworkAcl": VPCResourceFetcher,
    "AWS::EC2::FlowLog": VPCResourceFetcher,
    # RDS
    "AWS::RDS::DBInstance": RDSResourceFetcher,
    "AWS::RDS::DBSnapshot": RDSResourceFetcher,
    "AWS::RDS::DBClusterSnapshot": RDSResourceFetcher,
    # ELBv2
    "AWS::ElasticLoadBalancingV2::LoadBalancer": ELBv2ResourceFetcher,
    "AWS::ElasticLoadBalancingV2::Listener": ELBv2ResourceFetcher,
    # Redshift
    "AWS::Redshift::Cluster": RedshiftResourceFetcher,
    # SNS
    "AWS::SNS::Topic": SNSResourceFetcher,
    # SQS
    "AWS::SQS::Queue": SQSResourceFetcher,
    # SES
    "AWS::SES::Identity": SESResourceFetcher,
    # KMS
    "AWS::KMS::Key": KMSResourceFetcher,
    # ACM
    "AWS::ACM::Certificate": ACMResourceFetcher,
    # CloudTrail
    "AWS::CloudTrail::Trail": CloudTrailResourceFetcher,
}


def get_fetcher_for_resource_type(resource_type: str) -> type[ResourceFetcher] | None:
    """Get the appropriate fetcher class for a resource type."""
    return FETCHER_REGISTRY.get(resource_type)


__all__ = [
    "ResourceFetcher",
    "ResourceCache",
    "FETCHER_REGISTRY",
    "get_fetcher_for_resource_type",
    "S3ResourceFetcher",
    "SecurityGroupResourceFetcher",
    "EC2ResourceFetcher",
    "RDSResourceFetcher",
    "IAMResourceFetcher",
    "VPCResourceFetcher",
    "ELBv2ResourceFetcher",
    "RedshiftResourceFetcher",
    "SNSResourceFetcher",
    "SQSResourceFetcher",
    "SESResourceFetcher",
    "KMSResourceFetcher",
    "ACMResourceFetcher",
    "CloudTrailResourceFetcher",
]
