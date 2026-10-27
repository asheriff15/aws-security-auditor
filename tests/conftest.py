import os

import boto3
import pytest
from moto import mock_aws

from auditor.models import CheckContext

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION,
                 "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def session():
    with mock_aws():
        yield boto3.Session(region_name=REGION)


@pytest.fixture
def ctx(session):
    return CheckContext(session=session, regions=[REGION])


def ids(ctx, resource_contains=""):
    """Check IDs raised, optionally filtered to one resource."""
    return {f.check_id for f in ctx.findings if resource_contains in f.resource}
