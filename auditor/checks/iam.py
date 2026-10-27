"""IAM checks: root account, password policy, MFA, access keys, admin privileges."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from auditor.models import CheckContext, Severity
from auditor.policy import is_full_admin, statements

SERVICE = "iam"
KEY_MAX_AGE_DAYS = 90
KEY_UNUSED_DAYS = 90
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _days_since(ts: datetime) -> int:
    return (datetime.now(timezone.utc) - ts).days


def _is_no_such_entity(e: ClientError) -> bool:
    return e.response.get("Error", {}).get("Code") == "NoSuchEntity"


def check_root(ctx: CheckContext, iam) -> None:
    with ctx.guard("iam:GetAccountSummary"):
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) != 1:
            ctx.add(
                check_id="IAM-01", service=SERVICE, severity=Severity.CRITICAL, resource="root", region="global",
                title="Root account does not have MFA enabled",
                detail="The root user can do anything in the account, including closing it.",
                remediation="Enable MFA (hardware key or virtual) on the root user and lock the credentials away.",
            )
        if summary.get("AccountAccessKeysPresent", 0) == 1:
            ctx.add(
                check_id="IAM-02", service=SERVICE, severity=Severity.CRITICAL, resource="root", region="global",
                title="Root account has access keys",
                detail="Programmatic root credentials are a high-value target and cannot be scoped down.",
                remediation="Delete the root access keys; use IAM roles or Identity Center users instead.",
            )


def check_password_policy(ctx: CheckContext, iam) -> None:
    with ctx.guard("iam:GetAccountPasswordPolicy"):
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if not _is_no_such_entity(e):
                raise
            ctx.add(
                check_id="IAM-03", service=SERVICE, severity=Severity.MEDIUM, resource="account", region="global",
                title="No account password policy is set",
                detail="IAM users fall back to AWS defaults (8+ chars, no complexity or reuse rules).",
                remediation="Set a password policy: 14+ characters, reuse prevention of 24.",
            )
            return
        problems = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            problems.append(f"minimum length {policy.get('MinimumPasswordLength')} (< 14)")
        if policy.get("PasswordReusePrevention", 0) < 24:
            problems.append("password reuse prevention < 24")
        if problems:
            ctx.add(
                check_id="IAM-04", service=SERVICE, severity=Severity.LOW, resource="account", region="global",
                title="Password policy is weaker than recommended",
                detail="; ".join(problems),
                remediation="Raise minimum length to 14 and reuse prevention to 24.",
            )


def check_users(ctx: CheckContext, iam) -> None:
    users = []
    with ctx.guard("iam:ListUsers"):
        for page in iam.get_paginator("list_users").paginate():
            users.extend(page["Users"])

    for user in users:
        name, arn = user["UserName"], user["Arn"]

        # Console access without MFA
        with ctx.guard(f"iam:GetLoginProfile {name}"):
            try:
                iam.get_login_profile(UserName=name)
                has_console = True
            except ClientError as e:
                if not _is_no_such_entity(e):
                    raise
                has_console = False
            if has_console and not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                ctx.add(
                    check_id="IAM-05", service=SERVICE, severity=Severity.HIGH, resource=arn, region="global",
                    title="Console user without MFA",
                    detail=f"'{name}' can sign in to the console with only a password.",
                    remediation="Require MFA for this user (or move human users to IAM Identity Center).",
                )

        # Access key age and usage
        with ctx.guard(f"iam:ListAccessKeys {name}"):
            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                if key["Status"] != "Active":
                    continue
                key_id, age = key["AccessKeyId"], _days_since(key["CreateDate"])
                if age > KEY_MAX_AGE_DAYS:
                    ctx.add(
                        check_id="IAM-06", service=SERVICE, severity=Severity.MEDIUM, resource=f"{arn} ({key_id})",
                        region="global", title=f"Access key older than {KEY_MAX_AGE_DAYS} days",
                        detail=f"Key {key_id} for '{name}' is {age} days old.",
                        remediation="Rotate the key: create a new one, update consumers, deactivate then delete the old one.",
                    )
                last_used = iam.get_access_key_last_used(AccessKeyId=key_id)["AccessKeyLastUsed"].get("LastUsedDate")
                idle = _days_since(last_used) if last_used else age
                if idle > KEY_UNUSED_DAYS:
                    ctx.add(
                        check_id="IAM-07", service=SERVICE, severity=Severity.MEDIUM, resource=f"{arn} ({key_id})",
                        region="global", title=f"Active access key unused for {KEY_UNUSED_DAYS}+ days",
                        detail=f"Key {key_id} for '{name}' " + (f"last used {idle} days ago." if last_used else "has never been used."),
                        remediation="Deactivate and delete unused keys; stale credentials are pure attack surface.",
                    )

        # AdministratorAccess attached directly to a user
        with ctx.guard(f"iam:ListAttachedUserPolicies {name}"):
            attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
            if any(p["PolicyArn"] == ADMIN_POLICY_ARN for p in attached):
                ctx.add(
                    check_id="IAM-08", service=SERVICE, severity=Severity.HIGH, resource=arn, region="global",
                    title="AdministratorAccess attached directly to a user",
                    detail=f"'{name}' has full admin rights via a direct policy attachment.",
                    remediation="Grant permissions through groups/roles, apply least privilege, and use role assumption for admin tasks.",
                )

        # Inline policies granting *:*
        with ctx.guard(f"iam:ListUserPolicies {name}"):
            for policy_name in iam.list_user_policies(UserName=name)["PolicyNames"]:
                doc = iam.get_user_policy(UserName=name, PolicyName=policy_name)["PolicyDocument"]
                if any(is_full_admin(s) for s in statements(doc)):
                    ctx.add(
                        check_id="IAM-09", service=SERVICE, severity=Severity.HIGH, resource=arn, region="global",
                        title="Inline policy grants full admin (*:*)",
                        detail=f"Inline policy '{policy_name}' on '{name}' allows Action '*' on Resource '*'.",
                        remediation="Replace with a scoped managed policy; inline policies are hard to audit.",
                    )


def check_customer_policies(ctx: CheckContext, iam) -> None:
    with ctx.guard("iam:ListPolicies"):
        for page in iam.get_paginator("list_policies").paginate(Scope="Local", OnlyAttached=True):
            for pol in page["Policies"]:
                with ctx.guard(f"iam:GetPolicyVersion {pol['PolicyName']}"):
                    doc = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"])["PolicyVersion"]["Document"]
                    if any(is_full_admin(s) for s in statements(doc)):
                        ctx.add(
                            check_id="IAM-10", service=SERVICE, severity=Severity.HIGH, resource=pol["Arn"], region="global",
                            title="Customer-managed policy grants full admin (*:*)",
                            detail=f"'{pol['PolicyName']}' is attached to {pol.get('AttachmentCount', '?')} principal(s).",
                            remediation="Scope the policy to the actions and resources actually needed.",
                        )


def run(ctx: CheckContext) -> None:
    iam = ctx.client("iam")
    check_root(ctx, iam)
    check_password_policy(ctx, iam)
    check_users(ctx, iam)
    check_customer_policies(ctx, iam)
