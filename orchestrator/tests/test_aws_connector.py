"""AWS SOURCE connector against moto (an in-process fake AWS). No real AWS calls.

Skipped cleanly when the optional ``aws`` extra (boto3) or moto is missing.
"""
from __future__ import annotations

import json

import pytest

from app.integrations.connectors import load_all
from app.integrations.connectors import aws as aws_mod

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

load_all()

REGION = "us-east-1"
SECRETS = {"access_key_id": "testing", "secret_access_key": "testing",
           "external_id": "ext-123"}


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def test_world_open_ranges_and_admin_ports():
    sg = {"IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        {"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
    ]}
    ranges = aws_mod.world_open_ranges(sg)
    assert ("tcp", 22, 22) in ranges and ("all", 0, 65535) in ranges
    assert 5432 in aws_mod.admin_ports_hit(ranges, (22, 5432))   # via the ::/0 all-traffic rule
    assert aws_mod.admin_ports_hit([("tcp", 443, 443)], (22,)) == []


def test_s3_grants_and_bucket_matching():
    doc = {"Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::crown/*"},
        {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
    ]}
    grants = aws_mod.s3_grants(doc)
    assert grants == [(["s3:GetObject"], ["arn:aws:s3:::crown/*"])]
    assert aws_mod.bucket_matches("crown", grants[0][1])
    assert not aws_mod.bucket_matches("other", grants[0][1])
    assert aws_mod.bucket_matches("x", ["arn:aws-us-gov:s3:::*"])
    assert aws_mod.s3_grants({"Statement": {"Effect": "Allow", "NotAction": "iam:*",
                                            "Resource": "*"}}) == [(["*"], ["*"])]


# --------------------------------------------------------------------------- #
# Full pull against moto
# --------------------------------------------------------------------------- #

def _build_world():
    ec2 = boto3.client("ec2", region_name=REGION)
    iam = boto3.client("iam", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    elbv2 = boto3.client("elbv2", region_name=REGION)
    rds = boto3.client("rds", region_name=REGION)
    r53 = boto3.client("route53", region_name=REGION)

    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    subnets = [s["SubnetId"] for s in ec2.describe_subnets()["Subnets"]][:2]
    web = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    ])
    db = ec2.create_security_group(GroupName="db", Description="db", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=db, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
         "UserIdGroupPairs": [{"GroupId": web}]},
    ])

    assume = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
        "Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="app-role", AssumeRolePolicyDocument=json.dumps(assume))
    iam.put_role_policy(RoleName="app-role", PolicyName="read-crown", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                                                "Resource": "arn:aws:s3:::crown-bucket/*"}]}))
    iam.create_instance_profile(InstanceProfileName="app-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="app-profile", RoleName="app-role")
    # the role Paddock assumes
    iam.create_role(RoleName="paddock-readonly", AssumeRolePolicyDocument=json.dumps(assume))

    inst = ec2.run_instances(
        ImageId="ami-12c6146b", MinCount=1, MaxCount=1, InstanceType="t3.micro",
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnets[0], "Groups": [web],
                            "AssociatePublicIpAddress": True}],
        IamInstanceProfile={"Name": "app-profile"},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "app-1"}]}],
    )["Instances"][0]
    iid = inst["InstanceId"]
    desc = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    public_ip = desc.get("PublicIpAddress")

    lb = elbv2.create_load_balancer(Name="app-alb", Subnets=subnets, SecurityGroups=[web],
                                    Scheme="internet-facing", Type="application")["LoadBalancers"][0]
    tg = elbv2.create_target_group(Name="app-tg", Protocol="HTTP", Port=80, VpcId=vpc,
                                   TargetType="instance")["TargetGroups"][0]
    elbv2.register_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": iid, "Port": 80}])
    elbv2.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                          DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])

    rds.create_db_instance(DBInstanceIdentifier="payments-db", DBInstanceClass="db.t3.micro",
                           Engine="postgres", MasterUsername="admin", MasterUserPassword="x" * 12,
                           AllocatedStorage=20, PubliclyAccessible=True, VpcSecurityGroupIds=[db])

    s3.create_bucket(Bucket="crown-bucket")
    s3.create_bucket(Bucket="public-bucket")
    s3.put_bucket_acl(Bucket="public-bucket", ACL="public-read")

    zone = r53.create_hosted_zone(Name="acme-test.com", CallerReference="1")["HostedZone"]["Id"]
    changes = [{"Action": "CREATE", "ResourceRecordSet": {
        "Name": "app.acme-test.com", "Type": "A",
        "AliasTarget": {"HostedZoneId": lb.get("CanonicalHostedZoneId", "Z35SXDOTRQ7X7K"),
                        "DNSName": "dualstack." + lb["DNSName"], "EvaluateTargetHealth": False}}}]
    if public_ip:
        changes.append({"Action": "CREATE", "ResourceRecordSet": {
            "Name": "ssh.acme-test.com", "Type": "A", "TTL": 60,
            "ResourceRecords": [{"Value": public_ip}]}})
    r53.change_resource_record_sets(HostedZoneId=zone, ChangeBatch={"Changes": changes})
    return {"iid": iid, "public_ip": public_ip, "lb_arn": lb["LoadBalancerArn"]}


async def test_aws_pull_builds_internet_to_bucket_path(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with moto.mock_aws():
        world = _build_world()
        conn = aws_mod.AwsConnector(
            {"regions": [REGION], "role_arn": "arn:aws:iam::123456789012:role/paddock-readonly"},
            SECRETS, http=None)
        health = await conn.test()
        assert health.ok, health.detail
        batch = await conn.pull()

    acct = "123456789012"
    inst_arn = f"arn:aws:ec2:{REGION}:{acct}:instance/{world['iid']}"
    role_arn = f"arn:aws:iam::{acct}:role/app-role"
    crown_arn = "arn:aws:s3:::crown-bucket"
    assets = {(a["kind"], a["value"]): a for a in batch.assets}
    edges = {(e["src_canonical"], e["kind"], e["dst_canonical"]) for e in batch.edges}

    assert ("cloud_account", f"aws:{acct}") in assets
    inst = assets[("cloud_resource", inst_arn)]["metadata"]
    assert inst["iam_instance_profile"].endswith("instance-profile/app-profile")
    assert assets[("cloud_resource", world["lb_arn"])]["metadata"]["public"] is True
    assert assets[("cloud_resource", crown_arn)]["metadata"]["sensitive"] is True

    # internet -> record -> LB -> instance -> role -> bucket
    assert ("app.acme-test.com", "routes_to", world["lb_arn"]) in edges
    assert (world["lb_arn"], "routes_to", inst_arn) in edges
    assert (inst_arn, "has_role", role_arn) in edges
    assert (role_arn, "can_access", crown_arn) in edges
    assert (role_arn, "can_access", "arn:aws:s3:::public-bucket") not in edges
    assert assets[("subdomain", "app.acme-test.com")]["metadata"]["public"] is True
    # instance -> rds, because the db SG admits the web SG
    rds_arn = next(v for (k, v) in assets if k == "cloud_resource" and ":rds:" in v)
    assert (inst_arn, "can_reach", rds_arn) in edges
    # no hub edges to the account or security groups
    assert not any(e["dst_kind"] == "cloud_account" for e in batch.edges)
    assert not any("security-group" in e["dst_canonical"] for e in batch.edges)

    rules = {(f["rule_id"], f["asset_value"]) for f in batch.findings}
    assert ("aws.rds.publicly_accessible", rds_arn) in rules
    assert ("aws.s3.bucket_public", "arn:aws:s3:::public-bucket") in rules
    assert not any(r == "aws.s3.bucket_public" and v == crown_arn for r, v in rules)
    assert any(r == "aws.ec2.sg_admin_port_open_to_world" for r, _ in rules)
    if world["public_ip"]:
        assert inst["public"] is True
        assert ("aws.ec2.admin_port_open_to_internet", inst_arn) in rules
        assert (world["public_ip"], "attached_to", inst_arn) in edges
        assert ("ssh.acme-test.com", "resolves_to", world["public_ip"]) in edges
    assert all(f["rule_source"] == "policy" for f in batch.findings)
    blob = json.dumps([batch.assets, batch.edges, batch.findings], default=str)
    assert "ext-123" not in blob and "testing" not in blob


async def test_aws_bad_credentials_fail_safely(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)

    class Boom:
        def __init__(self, **kw):
            pass

        def client(self, *a, **k):
            from botocore.exceptions import ClientError

            class C:
                def get_caller_identity(self):
                    raise ClientError({"Error": {"Code": "InvalidClientTokenId",
                                                 "Message": "key AKIASECRET is bad"}},
                                      "GetCallerIdentity")
            return C()

    conn = aws_mod.AwsConnector({"regions": [REGION]},
                                {"access_key_id": "AKIASECRET", "secret_access_key": "zzzz"}, None)
    conn.session_factory = Boom
    res = await conn.test()
    assert not res.ok and "InvalidClientTokenId" in res.detail and "AKIASECRET" not in res.detail


# --------------------------------------------------------------------------- #
# normalize_ingress / persisted ingress_rules (reach-graph input, docs/ASSURANCE_P1.md 4.1)
# --------------------------------------------------------------------------------------- #

def _src(rule, typ):
    return [(s["value"]) for s in rule["sources"] if s["type"] == typ]


def test_normalize_ingress_covers_every_source_kind():
    sg = {"IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "10.1.2.9/16", "Description": "kept out of the output"},
                      {"CidrIp": "0.0.0.0/0"}],
         "Ipv6Ranges": [{"CidrIpv6": "2001:DB8::/32"}],
         "UserIdGroupPairs": [{"GroupId": "sg-aaa", "UserId": "999999999999",
                               "VpcPeeringConnectionId": "pcx-1"}, {"GroupId": "sg-bbb"}],
         "PrefixListIds": [{"PrefixListId": "pl-123"}]},
    ]}
    rules = aws_mod.normalize_ingress(sg)
    assert len(rules) == 1
    r = rules[0]
    assert (r["proto"], r["from"], r["to"]) == ("tcp", 443, 443)
    assert _src(r, "cidr") == ["0.0.0.0/0", "10.1.0.0/16"]        # canonical, sorted
    assert _src(r, "cidr6") == ["2001:db8::/32"]
    assert _src(r, "sg") == ["sg-aaa", "sg-bbb"]
    assert _src(r, "prefix_list") == ["pl-123"]
    foreign = next(s for s in r["sources"] if s["value"] == "sg-aaa")
    assert foreign["account"] == "999999999999" and foreign["peered"] is True
    assert "kept out" not in json.dumps(rules)


@pytest.mark.parametrize("raw,proto,lo,hi", [
    ("-1", "any", 0, 65535), ("all", "any", 0, 65535), ("6", "tcp", 22, 22),
    ("TCP", "tcp", 22, 22), ("17", "udp", 22, 22), ("1", "icmp", 0, 0), ("58", "icmp", 0, 0),
])
def test_normalize_ingress_protocols(raw, proto, lo, hi):
    perm = {"IpProtocol": raw, "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
    (r,) = aws_mod.normalize_ingress({"IpPermissions": [perm]})
    assert (r["proto"], r["from"], r["to"]) == (proto, lo, hi)


def test_normalize_ingress_widens_what_it_cannot_read():
    perms = [
        {"IpProtocol": "47", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},                 # GRE
        {"IpProtocol": "tcp", "FromPort": "x", "ToPort": None, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        {"IpProtocol": "tcp", "FromPort": 9000, "ToPort": 8000, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        {"IpProtocol": "tcp", "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "not-a-cidr"}]},
        {"IpProtocol": "tcp", "FromPort": 81, "ToPort": 81, "UserIdGroupPairs": [{"UserId": "1"}]},
        {"IpProtocol": "tcp", "FromPort": 82, "ToPort": 82, "Ipv6Ranges": [{}]},
        "garbage",
        {"IpProtocol": "tcp", "FromPort": 83, "ToPort": 83},                          # no sources
    ]
    rules = {(r["proto"], r["from"], r["to"]): r for r in aws_mod.normalize_ingress(
        {"IpPermissions": perms})}
    assert rules[("any", 0, 65535)]["proto_raw"] == "47"                      # unknown proto -> any
    assert ("tcp", 0, 65535) in rules                                         # bad/-1 ports -> all
    assert ("tcp", 8000, 9000) in rules                                       # inverted -> ordered
    for key in (("tcp", 80, 80), ("tcp", 81, 81)):
        (s,) = rules[key]["sources"]
        assert s == {"type": "cidr", "value": "0.0.0.0/0", "unparsed": True}  # world, flagged
    assert rules[("tcp", 82, 82)]["sources"] == [
        {"type": "cidr6", "value": "::/0", "unparsed": True}]
    assert not any(k[1] == 83 for k in rules)                                 # nothing to admit
    assert aws_mod.normalize_ingress({"IpPermissions": None}) == []
    assert aws_mod.normalize_ingress({}) == []


def test_normalize_ingress_is_sorted_and_capped():
    perms = [{"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
             for p in (443, 22, 80)]
    assert [r["from"] for r in aws_mod.normalize_ingress({"IpPermissions": perms})] == [22, 80, 443]
    many = {"IpPermissions": [{"IpProtocol": "tcp", "FromPort": i % 60000, "ToPort": i % 60000,
                               "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
                              for i in range(aws_mod.MAX_INGRESS_RULES + 5)]}
    assert len(aws_mod.normalize_ingress(many)) == aws_mod.MAX_INGRESS_RULES
    assert aws_mod.ingress_truncated(many) is True
    wide = {"IpPermissions": [{"IpProtocol": "-1", "IpRanges": [
        {"CidrIp": f"10.{i // 256}.{i % 256}.0/24"} for i in range(aws_mod.MAX_RULE_SOURCES + 1)]}]}
    assert len(aws_mod.normalize_ingress(wide)[0]["sources"]) == aws_mod.MAX_RULE_SOURCES
    assert aws_mod.ingress_truncated(wide) is True
    assert aws_mod.ingress_truncated(
        {"IpPermissions": perms}) is False


async def test_sg_assets_persist_ingress_rules_without_changing_existing_keys(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with moto.mock_aws():
        _build_world()
        conn = aws_mod.AwsConnector(
            {"regions": [REGION], "role_arn": "arn:aws:iam::123456789012:role/paddock-readonly"},
            SECRETS, http=None)
        batch = await conn.pull()
    sgs = {a["metadata"]["name"]: a["metadata"] for a in batch.assets
           if a["kind"] == "cloud_resource" and a["metadata"].get("resource_type") == "security_group"}
    assert {"web", "db", "default"} <= set(sgs)
    web, db = sgs["web"], sgs["db"]
    # the pre-existing keys are untouched
    for key in ("provider", "service", "account_id", "region", "group_id", "name", "vpc_id",
                "world_ingress", "attached_instances"):
        assert key in web
    assert web["world_ingress"] == ["tcp/22", "tcp/443"]
    assert web["ingress_truncated"] is False
    assert {(r["proto"], r["from"], r["to"], s["type"], s["value"]) for r in web["ingress_rules"]
            for s in r["sources"]} == {("tcp", 22, 22, "cidr", "0.0.0.0/0"),
                                       ("tcp", 443, 443, "cidr", "0.0.0.0/0")}
    (dbrule,) = db["ingress_rules"]
    assert (dbrule["proto"], dbrule["from"], dbrule["to"]) == ("tcp", 5432, 5432)
    assert dbrule["sources"] == [{"type": "sg", "value": web["group_id"], "account": "123456789012"}]
    # rules synced but empty is "[]", not absent (moto's default group allows only itself)
    assert isinstance(sgs["default"]["ingress_rules"], list)


def test_sg_without_an_ip_permissions_list_is_flagged_not_treated_as_empty():
    st = aws_mod._State(account="1", partition="aws", admin_ports=(), crown_tags=[],
                        data_stores_sensitive=True)
    st.sgs = {"sg-1": {"GroupId": "sg-1", "_region": REGION},                    # no IpPermissions
              "sg-2": {"GroupId": "sg-2", "_region": REGION, "IpPermissions": []}}
    aws_mod.AwsConnector._security_group_findings(aws_mod.AwsConnector({}, {}, None), st, REGION)
    md = {a["metadata"]["group_id"]: a["metadata"] for a in st.batch.assets}
    assert "ingress_rules" not in md["sg-1"] and md["sg-1"]["ingress_truncated"] is True
    assert md["sg-2"]["ingress_rules"] == [] and md["sg-2"]["ingress_truncated"] is False
