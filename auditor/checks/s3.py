"""S3 checks: public access, encryption, versioning, logging."""
from __future__ import annotations

from botocore.exceptions import ClientError

from auditor.models import CheckContext, Severity
from auditor.policy import is_public_principal, statements

SERVICE = "s3"
PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "everyone on the internet",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "any AWS account",
}
BPA_KEYS = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]


def _error_code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "")


def check_account_block_public_access(ctx: CheckContext) -> None:
    with ctx.guard("sts:GetCallerIdentity"):
        account_id = ctx.client("sts").get_caller_identity()["Account"]
        s3control = ctx.client("s3control", "us-east-1")
        try:
            cfg = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
            missing = [k for k in BPA_KEYS if not cfg.get(k)]
        except ClientError as e:
            if _error_code(e) != "NoSuchPublicAccessBlockConfiguration":
                raise
            missing = BPA_KEYS
        if missing:
            ctx.add(
                check_id="S3-01", service=SERVICE, severity=Severity.MEDIUM,
                resource=f"account/{account_id}", region="global",
                title="Account-level S3 Block Public Access is not fully enabled",
                detail=f"Disabled settings: {', '.join(missing)}",
                remediation="Enable all four Block Public Access settings at the account level "
                            "(S3 console > Block Public Access settings for this account).",
            )


def _bucket_region(s3, name: str) -> str:
    loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
    if loc in (None, ""):
        return "us-east-1"
    return "eu-west-1" if loc == "EU" else loc


def check_bucket(ctx: CheckContext, name: str, region: str) -> None:
    s3 = ctx.client("s3", region)
    arn = f"arn:aws:s3:::{name}"

    # 1. Bucket-level Block Public Access
    with ctx.guard(f"s3:GetBucketPublicAccessBlock {name}"):
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            missing = [k for k in BPA_KEYS if not cfg.get(k)]
        except ClientError as e:
            if _error_code(e) != "NoSuchPublicAccessBlockConfiguration":
                raise
            missing = BPA_KEYS
        if missing:
            ctx.add(
                check_id="S3-02", service=SERVICE, severity=Severity.MEDIUM, resource=arn, region=region,
                title="Bucket Block Public Access is not fully enabled",
                detail=f"Disabled settings: {', '.join(missing)}",
                remediation="Turn on all four Block Public Access settings for this bucket unless it "
                            "intentionally serves public content (prefer CloudFront + OAC for that).",
            )

    # 2. Bucket policy granting access to everyone
    with ctx.guard(f"s3:GetBucketPolicy {name}"):
        try:
            policy = s3.get_bucket_policy(Bucket=name)["Policy"]
        except ClientError as e:
            if _error_code(e) != "NoSuchBucketPolicy":
                raise
            policy = None
        if policy:
            public = [s for s in statements(policy) if is_public_principal(s)]
            if public:
                actions = sorted({a for s in public for a in ([s["Action"]] if isinstance(s.get("Action"), str) else s.get("Action", []))})
                ctx.add(
                    check_id="S3-03", service=SERVICE, severity=Severity.CRITICAL, resource=arn, region=region,
                    title="Bucket policy allows public access",
                    detail=f"Statement(s) grant Principal '*' with no Condition. Actions: {', '.join(actions)}",
                    remediation="Remove the Principal '*' statement or scope it with a Condition "
                                "(e.g. aws:SourceVpce, aws:PrincipalOrgID).",
                )

    # 3. ACL grants to AllUsers / AuthenticatedUsers
    with ctx.guard(f"s3:GetBucketAcl {name}"):
        for grant in s3.get_bucket_acl(Bucket=name).get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI")
            if uri in PUBLIC_GROUPS:
                perm = grant.get("Permission")
                sev = Severity.CRITICAL if perm in ("WRITE", "WRITE_ACP", "FULL_CONTROL") else Severity.HIGH
                ctx.add(
                    check_id="S3-04", service=SERVICE, severity=sev, resource=arn, region=region,
                    title="Bucket ACL grants access to a public group",
                    detail=f"{perm} granted to {PUBLIC_GROUPS[uri]}",
                    remediation="Set Object Ownership to 'Bucket owner enforced' to disable ACLs, "
                                "or remove the public grant.",
                )

    # 4. Default encryption
    with ctx.guard(f"s3:GetBucketEncryption {name}"):
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if _error_code(e) != "ServerSideEncryptionConfigurationNotFoundError":
                raise
            ctx.add(
                check_id="S3-05", service=SERVICE, severity=Severity.MEDIUM, resource=arn, region=region,
                title="No default encryption configured",
                detail="Bucket has no server-side encryption configuration.",
                remediation="Enable default encryption (SSE-S3 at minimum, SSE-KMS for sensitive data).",
            )

    # 5. Versioning
    with ctx.guard(f"s3:GetBucketVersioning {name}"):
        if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
            ctx.add(
                check_id="S3-06", service=SERVICE, severity=Severity.LOW, resource=arn, region=region,
                title="Versioning is not enabled",
                detail="Deleted or overwritten objects (e.g. by ransomware) cannot be recovered.",
                remediation="Enable versioning; pair it with lifecycle rules to control cost.",
            )

    # 6. Server access logging
    with ctx.guard(f"s3:GetBucketLogging {name}"):
        if "LoggingEnabled" not in s3.get_bucket_logging(Bucket=name):
            ctx.add(
                check_id="S3-07", service=SERVICE, severity=Severity.LOW, resource=arn, region=region,
                title="Server access logging is disabled",
                detail="No request-level access logs for incident investigation.",
                remediation="Enable server access logging (or CloudTrail S3 data events) to a separate log bucket.",
            )


def run(ctx: CheckContext) -> None:
    check_account_block_public_access(ctx)
    s3 = ctx.client("s3", "us-east-1")
    buckets = []
    with ctx.guard("s3:ListAllMyBuckets"):
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    for name in buckets:
        region = "us-east-1"
        with ctx.guard(f"s3:GetBucketLocation {name}"):
            region = _bucket_region(s3, name)
        check_bucket(ctx, name, region)
