"""Command-line entry point."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from auditor import __version__, report
from auditor.checks import REGISTRY
from auditor.models import CheckContext, Severity


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="aws-audit",
        description="Read-only AWS misconfiguration scanner for S3, IAM and EC2.",
    )
    p.add_argument("--profile", help="AWS CLI profile to use (default: standard credential chain)")
    p.add_argument("--region", action="append", dest="regions", metavar="REGION",
                   help="Region to scan for EC2 (repeatable). Default: the profile's region.")
    p.add_argument("--all-regions", action="store_true", help="Scan every enabled region for EC2")
    p.add_argument("--services", default="s3,iam,ec2", help="Comma-separated subset of: s3,iam,ec2")
    p.add_argument("--output-dir", default="reports", help="Where JSON/HTML reports are written")
    p.add_argument("--no-files", action="store_true", help="Console output only, skip JSON/HTML")
    p.add_argument("--min-severity", default="INFO", choices=[s.name for s in Severity],
                   help="Hide findings below this severity")
    p.add_argument("--fail-on", choices=[s.name for s in Severity],
                   help="Exit with code 2 if any finding is at or above this severity (for CI)")
    p.add_argument("--demo", action="store_true",
                   help="Scan a simulated, deliberately misconfigured account (needs moto; no AWS creds required)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def resolve_regions(session, args) -> list[str]:
    if args.all_regions:
        ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
        return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])
    return args.regions or [session.region_name or "us-east-1"]


def scan(session, args) -> int:
    services = [s.strip().lower() for s in args.services.split(",") if s.strip()]
    unknown = [s for s in services if s not in REGISTRY]
    if unknown:
        print(f"Unknown service(s): {', '.join(unknown)}. Choose from {', '.join(REGISTRY)}.", file=sys.stderr)
        return 1

    try:
        account = session.client("sts").get_caller_identity()["Account"]
    except NoCredentialsError:
        print("No AWS credentials found. Run `aws configure` / `aws sso login`, pass --profile, or try --demo.", file=sys.stderr)
        return 1
    except (ClientError, BotoCoreError) as e:
        print(f"Could not authenticate to AWS: {e}", file=sys.stderr)
        return 1

    ctx = CheckContext(session=session, regions=resolve_regions(session, args))
    for svc in services:
        print(f"Scanning {svc.upper()}...", file=sys.stderr)
        REGISTRY[svc](ctx)

    min_sev = Severity[args.min_severity]
    findings = [f for f in ctx.findings if f.severity >= min_sev]
    meta = {"account": account, "regions": ctx.regions, "services": services, "scanned_at": report.timestamp()}

    report.print_console(findings, ctx.errors, meta)
    if not args.no_files:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        stem = f"audit-{account}-{meta['scanned_at'].replace(':', '')}"
        j = report.write_json(findings, ctx.errors, meta, out / f"{stem}.json")
        h = report.write_html(findings, ctx.errors, meta, out / f"{stem}.html")
        print(f"\nReports written:\n  {j}\n  {h}")

    if args.fail_on and any(f.severity >= Severity[args.fail_on] for f in findings):
        return 2
    return 0


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.demo:
        from auditor.demo import run_demo
        return run_demo(lambda session: scan(session, args))
    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    return scan(session, args)


if __name__ == "__main__":
    sys.exit(main())
