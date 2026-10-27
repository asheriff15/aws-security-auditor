"""EC2 checks: security groups, IMDSv2, EBS encryption, public snapshots."""
from __future__ import annotations

from auditor.models import CheckContext, Severity

SERVICE = "ec2"
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

# port -> (label, severity) for services that should never face the internet
SENSITIVE_PORTS = {
    22: ("SSH", Severity.HIGH),
    3389: ("RDP", Severity.HIGH),
    3306: ("MySQL", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    1433: ("SQL Server", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
    23: ("Telnet", Severity.HIGH),
}


def _open_sources(perm: dict) -> list[str]:
    v4 = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") in OPEN_CIDRS]
    v6 = [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in OPEN_CIDRS]
    return v4 + v6


def check_security_groups(ctx: CheckContext, ec2, region: str) -> None:
    with ctx.guard(f"ec2:DescribeSecurityGroups {region}"):
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                sg_label = f"{sg['GroupId']} ({sg.get('GroupName', '')})"
                for perm in sg.get("IpPermissions", []):
                    sources = _open_sources(perm)
                    if not sources:
                        continue
                    if perm.get("IpProtocol") == "-1":
                        ctx.add(
                            check_id="EC2-01", service=SERVICE, severity=Severity.CRITICAL, resource=sg_label, region=region,
                            title="Security group allows ALL traffic from the internet",
                            detail=f"All protocols/ports open to {', '.join(sources)}",
                            remediation="Remove the rule; allow only the specific ports and source ranges required.",
                        )
                        continue
                    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                    for port, (label, sev) in SENSITIVE_PORTS.items():
                        if lo <= port <= hi:
                            ctx.add(
                                check_id="EC2-02", service=SERVICE, severity=sev, resource=sg_label, region=region,
                                title=f"{label} (port {port}) open to the internet",
                                detail=f"Rule {perm.get('IpProtocol')} {lo}-{hi} from {', '.join(sources)}",
                                remediation="Restrict the source to known IPs, or use SSM Session Manager / a VPN "
                                            "instead of exposing management and database ports.",
                            )


def check_instances(ctx: CheckContext, ec2, region: str) -> None:
    with ctx.guard(f"ec2:DescribeInstances {region}"):
        for page in ec2.get_paginator("describe_instances").paginate():
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    if inst.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                        continue
                    iid = inst["InstanceId"]
                    if inst.get("MetadataOptions", {}).get("HttpTokens") != "required":
                        ctx.add(
                            check_id="EC2-03", service=SERVICE, severity=Severity.MEDIUM, resource=iid, region=region,
                            title="Instance allows IMDSv1",
                            detail="IMDSv1 is vulnerable to SSRF-based credential theft (the Capital One breach vector).",
                            remediation="Set HttpTokens=required (enforce IMDSv2) on the instance and in launch templates.",
                        )
                    if inst.get("PublicIpAddress"):
                        ctx.add(
                            check_id="EC2-04", service=SERVICE, severity=Severity.INFO, resource=iid, region=region,
                            title="Instance has a public IP address",
                            detail=f"Public IP {inst['PublicIpAddress']} — confirm this host is meant to be internet-facing.",
                            remediation="Place non-public workloads in private subnets behind a load balancer or NAT.",
                        )


def check_ebs(ctx: CheckContext, ec2, region: str) -> None:
    with ctx.guard(f"ec2:GetEbsEncryptionByDefault {region}"):
        if not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
            ctx.add(
                check_id="EC2-05", service=SERVICE, severity=Severity.MEDIUM, resource=f"region/{region}", region=region,
                title="EBS encryption by default is disabled",
                detail="New volumes in this region will not be encrypted unless requested explicitly.",
                remediation="Enable 'Always encrypt new EBS volumes' in EC2 settings for every region you use.",
            )
    with ctx.guard(f"ec2:DescribeVolumes {region}"):
        for page in ec2.get_paginator("describe_volumes").paginate():
            for vol in page["Volumes"]:
                if not vol.get("Encrypted"):
                    attached = ", ".join(a["InstanceId"] for a in vol.get("Attachments", [])) or "unattached"
                    ctx.add(
                        check_id="EC2-06", service=SERVICE, severity=Severity.MEDIUM, resource=vol["VolumeId"], region=region,
                        title="EBS volume is not encrypted",
                        detail=f"{vol.get('Size')} GiB volume ({attached}).",
                        remediation="Snapshot it, copy the snapshot with encryption, and restore to a new encrypted volume.",
                    )
    with ctx.guard(f"ec2:DescribeSnapshots {region}"):
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            for snap in page["Snapshots"]:
                sid = snap["SnapshotId"]
                with ctx.guard(f"ec2:DescribeSnapshotAttribute {sid}"):
                    perms = ec2.describe_snapshot_attribute(SnapshotId=sid, Attribute="createVolumePermission")
                    if any(p.get("Group") == "all" for p in perms.get("CreateVolumePermissions", [])):
                        ctx.add(
                            check_id="EC2-07", service=SERVICE, severity=Severity.CRITICAL, resource=sid, region=region,
                            title="EBS snapshot is publicly shared",
                            detail="Any AWS account can create a volume from this snapshot and read its data.",
                            remediation="Remove the 'all' createVolumePermission and enable 'Block public access for EBS snapshots'.",
                        )


def run(ctx: CheckContext) -> None:
    for region in ctx.regions:
        ec2 = ctx.client("ec2", region)
        check_security_groups(ctx, ec2, region)
        check_instances(ctx, ec2, region)
        check_ebs(ctx, ec2, region)
