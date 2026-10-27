import json

from auditor.checks import s3
from tests.conftest import ids

LOCKED = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def test_public_bucket_policy_is_critical(session, ctx):
    c = session.client("s3")
    c.create_bucket(Bucket="leaky")
    c.put_bucket_policy(Bucket="leaky", Policy=json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::leaky/*"}]}))
    s3.run(ctx)
    assert "S3-03" in ids(ctx, "leaky")


def test_policy_with_condition_is_not_public(session, ctx):
    c = session.client("s3")
    c.create_bucket(Bucket="scoped")
    c.put_bucket_policy(Bucket="scoped", Policy=json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::scoped/*",
         "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}]}))
    s3.run(ctx)
    assert "S3-03" not in ids(ctx, "scoped")


def test_public_acl_flagged(session, ctx):
    c = session.client("s3")
    c.create_bucket(Bucket="acl-bucket")
    c.put_bucket_acl(Bucket="acl-bucket", ACL="public-read")
    s3.run(ctx)
    assert "S3-04" in ids(ctx, "acl-bucket")


def test_hardened_bucket_only_missing_logging(session, ctx):
    c = session.client("s3")
    c.create_bucket(Bucket="good")
    c.put_public_access_block(Bucket="good", PublicAccessBlockConfiguration=LOCKED)
    c.put_bucket_encryption(Bucket="good", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    c.put_bucket_versioning(Bucket="good", VersioningConfiguration={"Status": "Enabled"})
    s3.run(ctx)
    assert ids(ctx, "good") == {"S3-07"}


def test_account_block_public_access(session, ctx):
    s3.run(ctx)
    assert "S3-01" in ids(ctx, "account/")
    account = session.client("sts").get_caller_identity()["Account"]
    session.client("s3control").put_public_access_block(AccountId=account, PublicAccessBlockConfiguration=LOCKED)
    ctx.findings.clear()
    s3.run(ctx)
    assert "S3-01" not in ids(ctx)
