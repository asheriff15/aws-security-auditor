from auditor.checks import ec2
from tests.conftest import REGION, ids


def _vpc(c):
    return c.describe_vpcs()["Vpcs"][0]["VpcId"]


def _sg(c, name, perms):
    gid = c.create_security_group(GroupName=name, Description="t", VpcId=_vpc(c))["GroupId"]
    c.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
    return gid


def test_open_ssh_and_rdp(session, ctx):
    c = session.client("ec2")
    _sg(c, "ssh", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    _sg(c, "rdp6", [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
    ec2.run(ctx)
    titles = {f.title for f in ctx.findings if f.check_id == "EC2-02"}
    assert any("SSH" in t for t in titles) and any("RDP" in t for t in titles)


def test_port_range_covering_ssh(session, ctx):
    c = session.client("ec2")
    _sg(c, "range", [{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 1024, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.run(ctx)
    assert "EC2-02" in ids(ctx, "(range)")


def test_all_traffic_is_critical(session, ctx):
    c = session.client("ec2")
    _sg(c, "all", [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.run(ctx)
    assert "EC2-01" in ids(ctx, "(all)")


def test_https_and_private_ssh_not_flagged(session, ctx):
    c = session.client("ec2")
    _sg(c, "web", [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    _sg(c, "vpn", [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    ec2.run(ctx)
    assert not ids(ctx, "(web)") and not ids(ctx, "(vpn)")


def test_imdsv1_flagged_only_when_optional(session, ctx):
    c = session.client("ec2")
    ami = c.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    v1 = c.run_instances(ImageId=ami, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "optional"})["Instances"][0]["InstanceId"]
    v2 = c.run_instances(ImageId=ami, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "required"})["Instances"][0]["InstanceId"]
    ec2.run(ctx)
    assert "EC2-03" in ids(ctx, v1)
    assert "EC2-03" not in ids(ctx, v2)


def test_ebs_encryption(session, ctx):
    c = session.client("ec2")
    bad = c.create_volume(AvailabilityZone=f"{REGION}a", Size=10, Encrypted=False)["VolumeId"]
    good = c.create_volume(AvailabilityZone=f"{REGION}a", Size=10, Encrypted=True)["VolumeId"]
    ec2.run(ctx)
    assert "EC2-06" in ids(ctx, bad) and "EC2-06" not in ids(ctx, good)
    assert "EC2-05" in ids(ctx, "region/")

    c.enable_ebs_encryption_by_default()
    ctx.findings.clear()
    ec2.run(ctx)
    assert "EC2-05" not in ids(ctx)


def test_public_snapshot(session, ctx):
    c = session.client("ec2")
    vol = c.create_volume(AvailabilityZone=f"{REGION}a", Size=10, Encrypted=True)["VolumeId"]
    public = c.create_snapshot(VolumeId=vol)["SnapshotId"]
    private = c.create_snapshot(VolumeId=vol)["SnapshotId"]
    c.modify_snapshot_attribute(SnapshotId=public, Attribute="createVolumePermission",
                                OperationType="add", GroupNames=["all"])
    ec2.run(ctx)
    assert "EC2-07" in ids(ctx, public) and "EC2-07" not in ids(ctx, private)
