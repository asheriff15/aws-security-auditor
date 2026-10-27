"""Core data types: severities, findings, and the shared check context."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from enum import IntEnum

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    check_id: str
    service: str
    severity: Severity
    resource: str
    region: str
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class CheckContext:
    """Passed to every check module. Holds the session, collected findings, and errors."""

    session: boto3.session.Session
    regions: list[str]
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    _clients: dict = field(default_factory=dict)

    def client(self, service: str, region: str | None = None):
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=region, config=RETRY_CONFIG)
        return self._clients[key]

    def add(self, **kwargs) -> None:
        self.findings.append(Finding(**kwargs))

    @contextmanager
    def guard(self, what: str):
        """Run an API call; on AccessDenied (or any AWS error) record it and keep scanning."""
        try:
            yield
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            self.errors.append(f"{what}: {code}")
