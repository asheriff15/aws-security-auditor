import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from auditor.checks import iam
from tests.conftest import ids

ADMIN_DOC = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
READ_DOC = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]})


def test_root_without_mfa_and_missing_password_policy(ctx):
    iam.run(ctx)
    assert {"IAM-01", "IAM-03"} <= ids(ctx)


def test_weak_password_policy(session, ctx):
    session.client("iam").update_account_password_policy(MinimumPasswordLength=8)
    iam.run(ctx)
    assert "IAM-04" in ids(ctx) and "IAM-03" not in ids(ctx)


def test_console_user_without_mfa(session, ctx):
    c = session.client("iam")
    c.create_user(UserName="alice")
    c.create_login_profile(UserName="alice", Password="Sup3r-Secret!!")
    c.create_user(UserName="svc")  # no console access -> not flagged
    iam.run(ctx)
    assert "IAM-05" in ids(ctx, "user/alice")
    assert "IAM-05" not in ids(ctx, "user/svc")


def test_direct_admin_and_inline_wildcard(session, ctx):
    c = session.client("iam")
    c.create_user(UserName="bob")
    c.attach_user_policy(UserName="bob", PolicyArn=iam.ADMIN_POLICY_ARN)
    c.create_user(UserName="carol")
    c.put_user_policy(UserName="carol", PolicyName="all", PolicyDocument=ADMIN_DOC)
    c.create_user(UserName="dave")
    c.put_user_policy(UserName="dave", PolicyName="read", PolicyDocument=READ_DOC)
    iam.run(ctx)
    assert "IAM-08" in ids(ctx, "user/bob")
    assert "IAM-09" in ids(ctx, "user/carol")
    assert "IAM-09" not in ids(ctx, "user/dave")


def test_customer_managed_admin_policy_only_when_attached(session, ctx):
    c = session.client("iam")
    attached = c.create_policy(PolicyName="Attached", PolicyDocument=ADMIN_DOC)["Policy"]["Arn"]
    c.create_policy(PolicyName="Unattached", PolicyDocument=ADMIN_DOC)
    c.create_user(UserName="erin")
    c.attach_user_policy(UserName="erin", PolicyArn=attached)
    iam.run(ctx)
    flagged = {f.resource for f in ctx.findings if f.check_id == "IAM-10"}
    assert flagged == {attached}


def test_old_unused_access_key(session, ctx):
    c = session.client("iam")
    c.create_user(UserName="old")
    c.create_access_key(UserName="old")
    future = datetime.now(timezone.utc) + timedelta(days=120)
    with patch("auditor.checks.iam.datetime") as dt:
        dt.now.return_value = future
        iam.run(ctx)
    assert {"IAM-06", "IAM-07"} <= ids(ctx, "user/old")


def test_fresh_access_key_not_flagged(session, ctx):
    c = session.client("iam")
    c.create_user(UserName="new")
    c.create_access_key(UserName="new")
    iam.run(ctx)
    assert not ({"IAM-06", "IAM-07"} & ids(ctx, "user/new"))
