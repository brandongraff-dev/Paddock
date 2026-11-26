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


# --------------------------------------------------------------------------- #
# builders-7: the ENI inventory (docs/ASSURANCE_P2_1.md section 5.3, D32)
# --------------------------------------------------------------------------- #

import datetime as dt                           # noqa: E402
import random                                   # noqa: E402
import re                                       # noqa: E402
from pathlib import Path                        # noqa: E402
from types import SimpleNamespace               # noqa: E402

ACCT = "123456789012"


def _inst(iid, region=REGION):
    return aws_mod._Instance(f"arn:aws:ec2:{region}:{ACCT}:instance/{iid}", region, iid, [], [], [], None, {})


def _eni(eid, groups, *, status="in-use", itype="interface", desc="", iid=None, managed=False,
         owner=ACCT, public=None, **extra):
    e = {"NetworkInterfaceId": eid, "Status": status, "InterfaceType": itype, "Description": desc,
         "RequesterManaged": managed, "Groups": [{"GroupId": g, "GroupName": g} for g in groups]}
    if iid or status == "in-use":
        e["Attachment"] = {"InstanceId": iid, "InstanceOwnerId": owner, "Status": "attached"} if iid else \
            {"InstanceOwnerId": owner, "Status": "attached"}
        if not iid:
            e["Attachment"].pop("InstanceId")
    if public:
        e["Association"] = {"PublicIp": public}
    e.update(extra)
    return e


def _classify(eni, *, instances=("i-1",), lbs=("app/front", "classic/old")):
    return aws_mod.classify_eni(eni, region=REGION, account=ACCT,
                                instances={i: _inst(i) for i in instances}, lb_names=set(lbs))


def test_an_attached_instance_interface_is_modelled_only_when_the_instance_is_ours_and_in_this_region():
    assert _classify(_eni("eni-1", ["sg-a"], iid="i-1")) == ("instance", "i-1")
    assert _classify(_eni("eni-1", ["sg-a"], iid="i-ghost"))[0] == "other"                  # not described: unmodelled
    assert _classify(_eni("eni-1", ["sg-a"], iid="i-1", owner="222222222222"))[0] == "other"   # another account's
    assert _classify(_eni("eni-1", ["sg-a"], iid="i-1", status="available"))[0] == "detached"
    inst = {"i-1": _inst("i-1", "eu-west-1")}
    assert aws_mod.classify_eni(_eni("eni-1", ["sg-a"], iid="i-1"), region=REGION, account=ACCT,
                                instances=inst, lb_names=set())[0] == "other"                # other region's instance
    for itype in ("trunk", "branch", "lambda", "vpc_endpoint"):
        assert _classify(_eni("eni-1", ["sg-a"], iid="i-1", itype=itype))[0] != "instance"   # pod / service ENIs


def test_a_load_balancer_interface_is_modelled_only_when_requester_managed_and_the_typed_name_was_described():
    assert _classify(_eni("e", ["g"], desc="ELB app/front/50dc6c495c0c9188", managed=True)) == ("lb", "app/front")
    assert _classify(_eni("e", ["g"], desc="ELB old", managed=True)) == ("lb", "classic/old")
    assert _classify(_eni("e", ["g"], desc="ELB app/other/1", managed=True))[0] == "other"       # not described here
    assert _classify(_eni("e", ["g"], desc="ELB net/front/1", managed=True))[0] == "other"       # same name, other type
    assert _classify(_eni("e", ["g"], desc="ELB front", managed=True))[0] == "other"             # untyped = classic/front
    # a user can name any ENI "ELB app/front/..": only requester-managed ones are the load balancer's
    assert _classify(_eni("e", ["g"], desc="ELB app/front/50dc6c495c0c9188", managed=False))[0] == "other"
    assert _classify(_eni("e", ["g"], desc="ELB app/front/1", managed=True, status="available"))[0] == "detached"
    assert _classify(_eni("e", ["g"], desc="ELB app/front/1/x", managed=True))[0] == "other"
    assert _classify(_eni("e", ["g"], desc="ELB app//1", managed=True))[0] == "other"


@pytest.mark.parametrize("kw,kind", [
    ({"itype": "lambda"}, "lambda"),
    ({"desc": "AWS Lambda VPC ENI-fn-1234"}, "lambda"),
    ({"desc": "arn:aws:ecs:us-east-1:123456789012:attachment/abc"}, "ecs"),
    ({"desc": "arn:aws-us-gov:ecs:us-gov-west-1:123456789012:attachment/abc"}, "ecs"),
    ({"desc": "RDSNetworkInterface"}, "rds"),
    ({"itype": "vpc_endpoint"}, "vpce"),
    ({"itype": "gateway_load_balancer_endpoint"}, "vpce"),
    ({"itype": "nat_gateway"}, "nat_gateway"),
    ({"status": "available"}, "detached"),
    ({"itype": "api_gateway_managed"}, "other"),
    ({"desc": "something we never heard of"}, "other"),
])
def test_everything_that_is_not_an_instance_or_a_described_lb_is_unmodelled_with_a_kind(kw, kind):
    got, who = _classify(_eni("eni-9", ["sg-a"], **kw))
    assert got == kind and who is None


def test_summarize_counts_each_group_an_interface_is_in_and_ignores_unknown_groups():
    enis = [_eni("eni-a", ["sg-a", "sg-b"], iid="i-1"),
            _eni("eni-b", ["sg-a"], itype="lambda"),
            _eni("eni-c", ["sg-b", "sg-zzz"], desc="arn:aws:ecs:r:a:x", public="54.1.1.1"),
            _eni("eni-d", ["sg-a"], desc="ELB app/front/1", managed=True)]
    out = aws_mod.summarize_enis(enis, region=REGION, account=ACCT, instances={"i-1": _inst("i-1")},
                                 lb_names={"app/front"}, sg_ids={"sg-a", "sg-b", "sg-empty"})
    assert set(out) == {"sg-a", "sg-b", "sg-empty"}
    assert out["sg-a"] == {"instances": ["i-1"], "lbs": ["app/front"], "truncated": False,
                           "unmodeled": {"count": 1, "kinds": {"lambda": 1},
                                         "sample": [{"id": "eni-b", "kind": "lambda", "public": False}]}}
    assert out["sg-b"]["instances"] == ["i-1"] and out["sg-b"]["unmodeled"] == {
        "count": 1, "kinds": {"ecs": 1}, "sample": [{"id": "eni-c", "kind": "ecs", "public": True}]}
    assert out["sg-empty"] == {"instances": [], "lbs": [], "truncated": False,
                               "unmodeled": {"count": 0, "kinds": {}, "sample": []}}
    json.dumps(out)


def test_summarize_is_deterministic_and_caps_with_a_truncated_flag():
    enis = [_eni(f"eni-{i:04d}", ["sg-a"], iid=f"i-{i:04d}") for i in range(600)]
    enis += [_eni(f"eni-l{i:04d}", ["sg-a"], desc=f"ELB app/lb{i}/1", managed=True) for i in range(200)]
    enis += [_eni(f"eni-x{i:04d}", ["sg-a"], itype="lambda") for i in range(37)]
    inst = {f"i-{i:04d}": _inst(f"i-{i:04d}") for i in range(600)}
    lbs = {f"app/lb{i}" for i in range(200)}
    first = aws_mod.summarize_enis(enis, region=REGION, account=ACCT, instances=inst, lb_names=lbs, sg_ids={"sg-a"})
    m = first["sg-a"]
    assert len(m["instances"]) == 512 and m["instances"] == sorted(m["instances"])
    assert len(m["lbs"]) == 128 and m["lbs"] == sorted(m["lbs"])
    assert m["truncated"] is True
    assert m["unmodeled"]["count"] == 37 and m["unmodeled"]["kinds"] == {"lambda": 37}
    assert [s["id"] for s in m["unmodeled"]["sample"]] == [f"eni-x{i:04d}" for i in range(10)]
    for seed in range(4):
        shuffled = enis[:]
        random.Random(seed).shuffle(shuffled)
        assert aws_mod.summarize_enis(shuffled, region=REGION, account=ACCT, instances=inst, lb_names=lbs,
                                      sg_ids={"sg-a"}) == first
    under = aws_mod.summarize_enis(enis[:512], region=REGION, account=ACCT, instances=inst, lb_names=lbs,
                                   sg_ids={"sg-a"})
    assert under["sg-a"]["truncated"] is False and len(under["sg-a"]["instances"]) == 512


def test_summarize_survives_garbage_interfaces_by_counting_them_unmodelled():
    out = aws_mod.summarize_enis([None, "x", {}, {"Groups": "sg-a"}, {"Groups": [None, {"GroupId": 5}]},
                                  {"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-a"}], "Status": 7}],
                                 region=REGION, account=ACCT, instances={}, lb_names=set(), sg_ids={"sg-a"})
    assert out["sg-a"]["unmodeled"]["count"] == 1 and out["sg-a"]["instances"] == []


def _pull_sync(conn):
    import asyncio
    return asyncio.run(conn.pull())


def _sgs(batch):
    return {a["metadata"]["name"]: a["metadata"] for a in batch.assets
            if a["kind"] == "cloud_resource" and a["metadata"].get("resource_type") == "security_group"}


def _insts(batch):
    return [a["metadata"] for a in batch.assets
            if a["kind"] == "cloud_resource" and a["metadata"].get("resource_type") == "instance"]


def _faulty(*, eni=None, instances=None, sgs=None):
    """A boto3 Session whose chosen operations answer ``(code, [pages-before-the-error])`` like a denied or
    interrupted AWS call. ``before-call`` handlers short-circuit the HTTP exchange, so everything else is moto."""
    import boto3 as _boto3

    faults = {"DescribeNetworkInterfaces": eni, "DescribeInstances": instances, "DescribeSecurityGroups": sgs}

    class Session(_boto3.session.Session):
        def client(self, *a, **kw):
            c = super().client(*a, **kw)
            for op, spec in faults.items():
                if spec is None:
                    continue
                state = {"n": 0}

                def hook(model, params, request_signer, context, _op=op, _spec=spec, _state=state, **_):
                    code, partial = _spec
                    _state["n"] += 1
                    if _state["n"] <= len(partial):
                        return SimpleNamespace(status_code=200, headers={}, content=b""), partial[_state["n"] - 1]
                    return (SimpleNamespace(status_code=403, headers={}, content=b""),
                            {"Error": {"Code": code, "Message": "no"}, "ResponseMetadata": {"HTTPStatusCode": 403}})

                c.meta.events.register(f"before-call.ec2.{op}", hook)
            return c

    return Session


async def _pull_world(monkeypatch, *, session=None, mutate=None):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with moto.mock_aws():
        world = _build_world()
        if mutate:
            mutate(world)
        conn = aws_mod.AwsConnector(
            {"regions": [REGION], "role_arn": "arn:aws:iam::123456789012:role/paddock-readonly"},
            SECRETS, http=None)
        if session:
            conn.session_factory = session
        batch = await conn.pull()
    return world, batch, conn


async def test_a_complete_pull_writes_the_inventory_onto_every_group_and_marks_the_region_complete(monkeypatch):
    world, batch, conn = await _pull_world(monkeypatch)
    sgs = _sgs(batch)
    web = sgs["web"]
    inv, mem = web["eni_inventory"], web["eni_members"]
    assert inv["complete"] is True and inv["region"] == REGION and inv["eni_total"] >= 1
    assert dt.datetime.fromisoformat(inv["read_at"]).tzinfo is not None
    assert mem["instances"] == [world["iid"]] and mem["truncated"] is False
    assert mem["unmodeled"] == {"count": 0, "kinds": {}, "sample": []} and mem["lbs"] == []
    assert sgs["db"]["eni_inventory"]["complete"] is True and sgs["db"]["eni_members"]["instances"] == []
    assert all(m["inventory_complete"] is True for m in sgs.values())
    assert all(m["inventory_complete"] is True for m in _insts(batch))
    assert not [w for w in conn.last_warnings if "NetworkInterfaces" in w]


async def test_a_stray_interface_in_a_group_is_counted_unmodelled(monkeypatch):
    def add(world):
        ec2 = boto3.client("ec2", region_name=REGION)
        sg = next(g["GroupId"] for g in ec2.describe_security_groups()["SecurityGroups"] if g["GroupName"] == "web")
        sub = ec2.describe_subnets()["Subnets"][0]["SubnetId"]
        ec2.create_network_interface(SubnetId=sub, Groups=[sg], Description="AWS Lambda VPC ENI-fn")
        ec2.create_network_interface(SubnetId=sub, Groups=[sg], Description="plain")

    _, batch, _ = await _pull_world(monkeypatch, mutate=add)
    web = _sgs(batch)["web"]["eni_members"]
    assert web["unmodeled"]["count"] == 2 and web["unmodeled"]["kinds"] == {"lambda": 1, "detached": 1}
    assert web["instances"] and len(web["unmodeled"]["sample"]) == 2


async def test_access_denied_on_the_interface_read_degrades_to_incomplete_with_a_warning(monkeypatch):
    sess = _faulty(eni=("UnauthorizedOperation", []))
    _, batch, conn = await _pull_world(monkeypatch, session=sess)
    for md in _sgs(batch).values():
        assert md["eni_inventory"]["complete"] is False and md["eni_members"] == {}
        assert md["inventory_complete"] is True                  # the group and instance listings were fine
    assert any("ec2:DescribeNetworkInterfaces[us-east-1]: UnauthorizedOperation" in w for w in conn.last_warnings)
    assert _insts(batch)                                          # the rest of the pull is untouched


async def test_a_partial_interface_page_is_incomplete_not_a_short_list(monkeypatch):
    first = {"NetworkInterfaces": [_eni("eni-1", ["sg-whatever"], itype="lambda")], "NextToken": "page-2"}
    sess = _faulty(eni=("RequestLimitExceeded", [first]))
    _, batch, conn = await _pull_world(monkeypatch, session=sess)
    for md in _sgs(batch).values():
        assert md["eni_inventory"]["complete"] is False and md["eni_members"] == {}
    assert any("DescribeNetworkInterfaces" in w for w in conn.last_warnings)


@pytest.mark.parametrize("op", ["instances", "sgs"])
async def test_a_failed_instance_or_group_listing_marks_the_regions_assets_incomplete(monkeypatch, op):
    sess = _faulty(**{op: ("RequestLimitExceeded", [])})
    _, batch, conn = await _pull_world(monkeypatch, session=sess)
    # a failure on the FIRST page leaves nothing to build from; what is written must say so
    flagged = [m for m in list(_sgs(batch).values()) + _insts(batch)]
    assert all(m["inventory_complete"] is False for m in flagged)
    assert any("RequestLimitExceeded" in w for w in conn.last_warnings)


async def test_a_listing_that_fails_after_its_first_page_flags_the_pages_it_did_return(monkeypatch):
    import boto3 as _boto3

    def pages(monkeypatch_session):
        pass

    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        monkeypatch.setenv(k, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with moto.mock_aws():
        _build_world()
        ec2 = _boto3.client("ec2", region_name=REGION)
        real = ec2.describe_security_groups()["SecurityGroups"]
        first = {"SecurityGroups": real[:1], "NextToken": "2"}
        conn = aws_mod.AwsConnector({"regions": [REGION]}, SECRETS, http=None)
        conn.session_factory = _faulty(sgs=("InternalError", [first]))
        batch = await conn.pull()
    sgs = _sgs(batch)
    assert len(sgs) == 1 and all(m["inventory_complete"] is False for m in sgs.values())
    assert all(m["inventory_complete"] is False for m in _insts(batch))


async def test_a_later_failed_read_overwrites_a_stale_complete_inventory_in_the_assets(
        db_pool, fake_redis, monkeypatch):
    """The metadata merge is shallow: a failed read must WRITE incomplete, never leave the old complete:true."""
    from app.integrations.ingest import apply_source_batch

    _, good, _ = await _pull_world(monkeypatch)
    _, bad, _ = await _pull_world(monkeypatch, session=_faulty(eni=("UnauthorizedOperation", [])))
    await apply_source_batch(db_pool, fake_redis, good, source="integration:aws")

    async def stored():
        rows = await db_pool.fetch(
            "SELECT metadata FROM assets WHERE kind = 'cloud_resource' AND metadata->>'resource_type' = 'security_group' "
            "AND metadata->>'name' = 'web'")
        (r,) = rows
        md = r["metadata"]
        return json.loads(md) if isinstance(md, str) else md

    before = await stored()
    assert before["eni_inventory"]["complete"] is True and before["eni_members"]["instances"]
    await apply_source_batch(db_pool, fake_redis, bad, source="integration:aws")
    after = await stored()
    assert after["eni_inventory"]["complete"] is False and after["eni_members"] == {}


def test_a_group_with_no_read_yet_is_written_incomplete_not_omitted():
    st = aws_mod._State(account="1", partition="aws", admin_ports=(), crown_tags=[], data_stores_sensitive=True)
    st.sgs = {"sg-2": {"GroupId": "sg-2", "_region": REGION, "IpPermissions": []}}
    aws_mod.AwsConnector._security_group_findings(aws_mod.AwsConnector({}, {}, None), st, REGION)
    (a,) = st.batch.assets
    assert a["metadata"]["eni_inventory"]["complete"] is False and a["metadata"]["eni_members"] == {}


def test_the_least_privilege_policy_lists_describe_network_interfaces():
    doc = (Path(__file__).resolve().parents[2] / "docs" / "INTEGRATIONS-CONTEXT.md").read_text()
    start = doc.index('"Sid": "PaddockInventory"')
    block = doc[start:doc.index("]", start)]
    assert '"ec2:DescribeNetworkInterfaces"' in block
    assert '"ec2:DescribeSecurityGroups"' in block
    # every ec2 call the connector makes is in the policy (the doc is the contract with the customer)
    src = Path(aws_mod.__file__).read_text()
    called = set(re.findall(r"ec2:Describe\w+", src))
    listed = set(re.findall(r'"(ec2:Describe\w+)"', block))
    assert called <= listed, called - listed
    assert "network interface" in doc.lower() and "unenumerated" in doc.lower() or "ENI inventory" in doc
