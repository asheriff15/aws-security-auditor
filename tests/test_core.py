import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from auditor import cli
from auditor.checks import s3
from auditor.models import CheckContext
from auditor.policy import is_full_admin, is_public_principal


def test_policy_helpers():
    assert is_full_admin({"Effect": "Allow", "Action": ["*"], "Resource": "*"})
    assert not is_full_admin({"Effect": "Deny", "Action": "*", "Resource": "*"})
    assert not is_full_admin({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})
    assert is_public_principal({"Effect": "Allow", "Principal": "*"})
    assert is_public_principal({"Effect": "Allow", "Principal": {"AWS": ["*"]}})
    assert not is_public_principal({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}})


def test_access_denied_is_recorded_not_raised():
    """A missing permission should skip that check, not crash the whole scan."""
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListBuckets")
    client = MagicMock()
    client.list_buckets.side_effect = denied
    client.get_caller_identity.side_effect = denied
    session = MagicMock()
    session.client.return_value = client
    ctx = CheckContext(session=session, regions=["us-east-1"])
    s3.run(ctx)
    assert ctx.findings == []
    assert any("AccessDenied" in e for e in ctx.errors)


def test_cli_fail_on_and_reports(session, tmp_path, capsys):
    session.client("s3").create_bucket(Bucket="plain-bucket")
    args = cli.parse_args(["--services", "s3", "--output-dir", str(tmp_path), "--fail-on", "MEDIUM"])
    assert cli.scan(session, args) == 2
    report = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert report["summary"]["MEDIUM"] >= 1
    assert next(tmp_path.glob("*.html")).read_text().startswith("<!doctype html>")

    args = cli.parse_args(["--services", "s3", "--no-files", "--fail-on", "CRITICAL"])
    assert cli.scan(session, args) == 0


def test_unknown_service_rejected(session):
    assert cli.scan(session, cli.parse_args(["--services", "rds"])) == 1
