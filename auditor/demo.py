"""Demo mode: build a deliberately misconfigured account inside moto and scan it.

Lets anyone (recruiters included) see the tool work without touching a real AWS account.
"""
from __future__ import annotations

import json
import os
import sys


def seed_vulnerable_account(session) -> None:
    region = "us-east-1"
    s3 = session.client("s3", region_name=region)
    iam = session.client("iam")
    ec2 = session.client("ec2", region_name=region)

    # --- S3: one public bucket, one locked-down bucket ---
    s3.create_bucket(Bucket="acme-marketing-assets")
    s3.put_bucket_policy(Bucket="acme-marketing-assets", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::acme-marketing-assets/*"}],
    }))
    s3.create_bucket(Bucket="acme-hr-exports")
    s3.put_bucket_acl(Bucket="acme-hr-exports", ACL="public-read")

    s3.create_bucket(Bucket="acme-secure-logs")
    s3.put_public_access_block(Bucket="acme-secure-logs", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_encryption(Bucket="acme-secure-logs", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    s3.put_bucket_versioning(Bucket="acme-secure-logs", VersioningConfiguration={"Status": "Enabled"})

    # --- IAM: weak password policy, console user w/o MFA, direct admin, wildcard policy ---
    iam.update_account_password_policy(MinimumPasswordLength=8)
    iam.create_user(UserName="jsmith")
    iam.create_login_profile(UserName="jsmith", Password="Passw0rd!Demo")
    iam.attach_user_policy(UserName="jsmith", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_user(UserName="ci-deploy")
    iam.create_access_key(UserName="ci-deploy")
    iam.put_user_policy(UserName="ci-deploy", PolicyName="deploy-everything", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    arn = iam.create_policy(PolicyName="LegacyPowerUser", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]}))["Policy"]["Arn"]
    iam.create_role(RoleName="legacy-app", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                                                 "Action": "sts:AssumeRole"}]}))
    iam.attach_role_policy(RoleName="legacy-app", PolicyArn=arn)

    # --- EC2: open SSH/RDP/all-traffic SGs, IMDSv1 instance, unencrypted volume, public snapshot ---
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg = ec2.create_security_group(GroupName="bastion-sg", Description="demo", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
    ])
    wide = ec2.create_security_group(GroupName="temp-debug-sg", Description="demo", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=wide, IpPermissions=[
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    web = ec2.create_security_group(GroupName="web-sg", Description="demo", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro", SecurityGroupIds=[sg],
                      MetadataOptions={"HttpTokens": "optional"})
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t3.micro", SecurityGroupIds=[web],
                      MetadataOptions={"HttpTokens": "required"})
    vol = ec2.create_volume(AvailabilityZone=f"{region}a", Size=50, Encrypted=False)["VolumeId"]
    snap = ec2.create_snapshot(VolumeId=vol, Description="db backup")["SnapshotId"]
    ec2.modify_snapshot_attribute(SnapshotId=snap, Attribute="createVolumePermission",
                                  OperationType="add", GroupNames=["all"])


def run_demo(scan_fn) -> int:
    try:
        from moto import mock_aws
    except ImportError:
        print("Demo mode needs moto:  pip install -r requirements-dev.txt", file=sys.stderr)
        return 1
    import boto3

    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": "us-east-1",
                 "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}.items():
        os.environ[k] = v
    os.environ.pop("AWS_PROFILE", None)

    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        print("DEMO MODE: scanning a simulated, intentionally misconfigured AWS account (moto).\n", file=sys.stderr)
        seed_vulnerable_account(session)
        return scan_fn(session)
