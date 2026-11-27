"""AWS (SOURCE, read-only): inventory + network/IAM paths for the attack-path engine.

Pulls, per configured region:

* EC2 instances (public IP / DNS, security groups, instance profile)
* EC2 network interfaces (``DescribeNetworkInterfaces``): not as assets, but as the security-group MEMBERSHIP
  inventory the reach builder needs to prove that a group referenced by a rule holds nothing it does not model
  (Lambda, Fargate, endpoints, ...; docs/ASSURANCE_P2_1.md section 5)
* ELBv2 (ALB/NLB/GWLB) + classic ELB, their listeners and registered targets
* security groups: which ports are open to 0.0.0.0/0 or ::/0
* RDS instances (``PubliclyAccessible``, endpoint, security groups)

and globally:

* IAM instance profiles -> roles -> which S3 buckets their policies grant
* S3 buckets: account + bucket Public Access Block, ACL grants, policy status
* Route53 public hosted zones and their A/AAAA/CNAME/alias records

It maps them onto existing asset kinds (``cloud_account``, ``cloud_resource``,
``domain``, ``subdomain``, ``ipv4``/``ipv6``) with edges that let the
attack-path engine walk ``internet -> record -> LB -> instance -> role -> bucket``:

    subdomain --routes_to--> load balancer --routes_to--> instance
    subdomain --resolves_to--> ipv4 --attached_to--> instance
    instance --has_role--> IAM role --can_access--> S3 bucket
    instance --can_reach--> RDS instance (its SG admits the instance's SG/IP)

Sources/targets for the engine: internet-reachable things get
``metadata.public = true`` (internet-facing LBs; instances with a public IP
behind a security group that admits the world; records resolving to either);
data stores (S3, RDS) get ``metadata.sensitive = true`` unless
``data_stores_are_crown_jewels`` is off, and anything carrying a configured
``crown_jewel_tags`` tag gets ``metadata.crown_jewel = true``.

Deliberately NOT edges: resource -> account and resource -> security group.
The engine treats edges as undirected, so hub nodes would invent lateral
paths that do not exist. That information lives in metadata instead.

Findings (rule_source ``policy``): publicly accessible RDS, public S3 bucket,
admin/database ports open to the internet on an instance and on the security
group itself.

Every call is a Describe/List/Get. The exact least-privilege IAM policy is in
docs/INTEGRATIONS-CONTEXT.md. boto3 is an optional dependency
(``pip install 'paddock-orchestrator[aws]'``).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import fnmatch
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..base import Capability, Connector, HealthResult, SourceBatch, register
from ._common import SourceError, asset, bool_cfg, edge, finding, ip_kind, is_public_ip

log = logging.getLogger(__name__)

SOURCE = "integration:aws"

DEFAULT_ADMIN_PORTS: tuple[int, ...] = (
    22, 23, 135, 139, 445, 1433, 1521, 2049, 2375, 2376, 2379, 3306, 3389,
    5432, 5601, 5900, 5984, 6379, 7001, 8086, 9042, 9200, 9300, 11211, 27017,
)

# AWS-managed policies that grant s3 on every bucket.
_BROAD_S3_MANAGED = {
    "AdministratorAccess": ["*"],
    "PowerUserAccess": ["*"],
    "AmazonS3FullAccess": ["s3:*"],
    "AmazonS3ReadOnlyAccess": ["s3:Get*", "s3:List*"],
    "ReadOnlyAccess": ["s3:Get*", "s3:List*"],
}

_WORLD_V4 = "0.0.0.0/0"
_WORLD_V6 = "::/0"


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# --------------------------------------------------------------------------- #
# Pure analysis helpers (unit-tested directly)
# --------------------------------------------------------------------------- #

def world_open_ranges(sg: dict[str, Any]) -> list[tuple[str, int, int]]:
    """(protocol, from_port, to_port) for every ingress rule open to the world."""
    out: list[tuple[str, int, int]] = []
    for perm in sg.get("IpPermissions") or []:
        world = any(r.get("CidrIp") == _WORLD_V4 for r in perm.get("IpRanges") or []) or any(
            r.get("CidrIpv6") == _WORLD_V6 for r in perm.get("Ipv6Ranges") or []
        )
        if not world:
            continue
        proto = str(perm.get("IpProtocol", "-1"))
        if proto == "-1":
            out.append(("all", 0, 65535))
        else:
            lo = int(perm.get("FromPort", 0) if perm.get("FromPort") is not None else 0)
            hi = int(perm.get("ToPort", 65535) if perm.get("ToPort") is not None else 65535)
            if lo == -1:   # ICMP "all types"
                lo, hi = 0, 0
            out.append((proto, lo, hi))
    return out


def admin_ports_hit(ranges: list[tuple[str, int, int]], admin_ports: tuple[int, ...]) -> list[int]:
    hit: set[int] = set()
    for proto, lo, hi in ranges:
        if proto not in ("tcp", "6", "all", "udp", "17"):
            continue
        for p in admin_ports:
            if lo <= p <= hi:
                hit.add(p)
    return sorted(hit)


def describe_ranges(ranges: list[tuple[str, int, int]]) -> list[str]:
    out = []
    for proto, lo, hi in ranges:
        if proto == "all":
            out.append("all traffic")
        elif lo == hi:
            out.append(f"{proto}/{lo}")
        else:
            out.append(f"{proto}/{lo}-{hi}")
    return out


def sg_ingress_sources(sg: dict[str, Any]) -> tuple[set[str], list[Any]]:
    """(referenced security-group ids, non-world CIDR networks) a group admits."""
    groups: set[str] = set()
    nets: list[Any] = []
    for perm in sg.get("IpPermissions") or []:
        for pair in perm.get("UserIdGroupPairs") or []:
            if pair.get("GroupId"):
                groups.add(pair["GroupId"])
        for r in perm.get("IpRanges") or []:
            c = r.get("CidrIp")
            if c and c != _WORLD_V4:
                try:
                    nets.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    pass
    return groups, nets


_INGRESS_PROTO = {
    "-1": "any", "all": "any", "any": "any",
    "6": "tcp", "tcp": "tcp", "17": "udp", "udp": "udp",
    "1": "icmp", "icmp": "icmp", "58": "icmp", "icmpv6": "icmp",
}
# Bounds so a hostile or enormous account cannot bloat one asset row. Hitting either sets
# ``ingress_truncated`` and the reach builder then refuses to claim complete coverage.
MAX_INGRESS_RULES = 256
MAX_RULE_SOURCES = 256


def _ingress_ports(proto: str, lo: Any, hi: Any) -> tuple[int, int]:
    """Port range of one rule. Unknown or odd values widen to every port (over-approximate)."""
    if proto == "any":
        return 0, 65535
    if proto == "icmp":     # FromPort/ToPort carry ICMP type/code, not ports
        return 0, 0
    try:
        a, b = int(lo), int(hi)
    except (TypeError, ValueError):
        return 0, 65535
    if a < 0 or b < 0:      # -1 means "all"
        return 0, 65535
    a, b = min(a, b), max(a, b)
    return max(0, a), min(65535, b)


def _unparsed(world: str) -> dict[str, Any]:
    """A source we could not read is treated as the whole world, never silently dropped."""
    return {"type": "cidr6" if world == _WORLD_V6 else "cidr", "value": world, "unparsed": True}


def _ingress_sources(perm: dict[str, Any]) -> list[dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}

    def add(src: dict[str, Any]) -> None:
        out.setdefault((src["type"], src["value"]), src)

    for field_, key, kind, world in (("IpRanges", "CidrIp", "cidr", _WORLD_V4),
                                     ("Ipv6Ranges", "CidrIpv6", "cidr6", _WORLD_V6)):
        for r in _as_list(perm.get(field_)):
            raw = r.get(key) if isinstance(r, dict) else None
            try:
                net = ipaddress.ip_network(str(raw).strip(), strict=False)
            except ValueError:
                add(_unparsed(world))
                continue
            add({"type": kind, "value": net.compressed.lower()})
    for pair in _as_list(perm.get("UserIdGroupPairs")):
        gid = pair.get("GroupId") if isinstance(pair, dict) else None
        if not isinstance(gid, str) or not gid:
            add(_unparsed(_WORLD_V4))
            continue
        src: dict[str, Any] = {"type": "sg", "value": gid}
        if isinstance(pair.get("UserId"), str) and pair["UserId"]:
            src["account"] = pair["UserId"]
        if pair.get("VpcPeeringConnectionId"):
            src["peered"] = True
        add(src)
    for pl in _as_list(perm.get("PrefixListIds")):
        pid = pl.get("PrefixListId") if isinstance(pl, dict) else None
        if isinstance(pid, str) and pid:
            add({"type": "prefix_list", "value": pid})
        else:
            add(_unparsed(_WORLD_V4))
    return sorted(out.values(), key=lambda s: (s["type"], s["value"]))


def normalize_ingress(sg: dict[str, Any]) -> list[dict[str, Any]]:
    """Security-group ingress rules in the shape the reach builder (``aws_sg``) reads.

    ``[{"proto": "tcp|udp|icmp|any", "from": int, "to": int, "sources": [{"type": "cidr|cidr6|sg|
    prefix_list", "value": str, ...}]}]``, sorted for stable output. Pure and defensive: anything
    unparseable widens (an unreadable CIDR becomes the whole world with ``unparsed: true``, an
    unknown IP protocol becomes ``any`` with ``proto_raw``) because under-reporting a rule would
    let an assurance verdict claim containment that does not exist. The caller records whether
    the list was capped (``len(IpPermissions) > MAX_INGRESS_RULES``) via ``ingress_truncated``.
    """
    rules: list[dict[str, Any]] = []
    perms = _as_list(sg.get("IpPermissions")) if isinstance(sg, dict) else []
    for perm in perms[:MAX_INGRESS_RULES]:
        if not isinstance(perm, dict):
            rules.append({"proto": "any", "from": 0, "to": 65535, "sources": [_unparsed(_WORLD_V4)]})
            continue
        raw = str(perm.get("IpProtocol", "-1")).strip().lower()
        proto = _INGRESS_PROTO.get(raw, "any")
        lo, hi = _ingress_ports(proto, perm.get("FromPort"), perm.get("ToPort"))
        sources = _ingress_sources(perm)[:MAX_RULE_SOURCES]
        if not sources:
            continue
        rule: dict[str, Any] = {"proto": proto, "from": lo, "to": hi, "sources": sources}
        if raw not in _INGRESS_PROTO:
            rule["proto_raw"] = raw[:16]
        rules.append(rule)
    rules.sort(key=lambda r: (r["proto"], r["from"], r["to"],
                              [(s["type"], s["value"]) for s in r["sources"]]))
    return rules


def ingress_truncated(sg: dict[str, Any]) -> bool:
    perms = _as_list(sg.get("IpPermissions"))
    return len(perms) > MAX_INGRESS_RULES or any(
        isinstance(p, dict) and sum(len(_as_list(p.get(k))) for k in (
            "IpRanges", "Ipv6Ranges", "UserIdGroupPairs", "PrefixListIds")) > MAX_RULE_SOURCES
        for p in perms)


def s3_grants(document: Any) -> list[tuple[list[str], list[str]]]:
    """Allow statements touching S3: [(actions, resource_patterns)].

    Conservative over-approximation (the engine wants "could reach"):
    ``NotAction``/``NotResource`` with Allow are treated as broad. Conditions
    are ignored. Deny statements are not subtracted.
    """
    if not isinstance(document, dict):
        return []
    out: list[tuple[list[str], list[str]]] = []
    for st in _as_list(document.get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        if "NotAction" in st:
            excluded = [str(a).lower() for a in _as_list(st.get("NotAction"))]
            if any(a in ("*", "s3:*") for a in excluded):
                continue
            actions = ["*"]
        else:
            actions = [str(a) for a in _as_list(st.get("Action"))
                       if str(a) == "*" or str(a).lower().startswith("s3:")]
        if not actions:
            continue
        resources = ["*"] if "NotResource" in st else [str(r) for r in _as_list(st.get("Resource"))]
        out.append((actions, resources or ["*"]))
    return out


def _partition_agnostic(pattern: str) -> str:
    """``arn:aws-us-gov:s3:::b`` -> ``arn:*:s3:::b`` so one matcher fits every partition."""
    if pattern.startswith("arn:") and pattern.count(":") >= 2:
        return "arn:*:" + pattern.split(":", 2)[2]
    return pattern


def bucket_matches(bucket: str, patterns: list[str]) -> bool:
    """True if any IAM Resource pattern covers the bucket or objects in it."""
    for p in patterns:
        pat = _partition_agnostic(p)
        for arn in (f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/x"):
            if fnmatch.fnmatchcase(arn, pat):
                return True
    return False


def tags_dict(tags: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for t in tags or []:
        if isinstance(t, dict) and "Key" in t:
            out[str(t["Key"])] = str(t.get("Value", ""))
    return out


def crown_jewel_by_tags(tags: dict[str, str], wanted: list[str]) -> bool:
    for w in wanted:
        if "=" in w:
            k, v = w.split("=", 1)
            if tags.get(k.strip()) == v.strip():
                return True
        elif w.strip() in tags:
            return True
    return False


# --------------------------------------------------------------------------- #
# ENI inventory: who sits in a security group (docs/ASSURANCE_P2_1.md section 5.3, D32)
# --------------------------------------------------------------------------- #

# Bounds on one group's summary (an asset row is not a database). Hitting either sets ``truncated`` and the reach
# builder then refuses to call the membership proven.
MAX_ENI_INSTANCES = 512
MAX_ENI_LBS = 128
MAX_ENI_SAMPLE = 10

_ELBV2_PREFIX = {"application": "app", "network": "net", "gateway": "gwy"}
_ARN_ECS = re.compile(r"^arn:aws[a-z-]*:ecs:")
# What a requester-managed load balancer interface reports as its type.
_LB_ITYPES = frozenset({"interface", "network_load_balancer", "gateway_load_balancer", "load_balancer"})
# An instance's own interface. Pod ("branch"/"trunk"), Lambda, endpoint and NAT interfaces are never the instance.
_INSTANCE_ITYPES = frozenset({"interface", "efa"})


def lb_typed_name(lb_type: Any, name: Any) -> Optional[str]:
    """``app/<name>``, ``net/<name>``, ``gwy/<name>`` or ``classic/<name>`` (the spelling the builder matches)."""
    if not isinstance(name, str) or not name:
        return None
    if lb_type == "classic":
        return f"classic/{name}"
    prefix = _ELBV2_PREFIX.get(str(lb_type))
    return f"{prefix}/{name}" if prefix else None


def _eni_lb_key(desc: Any) -> Optional[str]:
    """The typed load balancer name an ENI description claims: ``ELB app/<name>/<id>`` or ``ELB <classic name>``."""
    if not isinstance(desc, str) or not desc.startswith("ELB "):
        return None
    parts = desc[4:].split("/")
    if len(parts) == 3 and parts[0] in _ELBV2_PREFIX.values() and parts[1] and parts[2]:
        return f"{parts[0]}/{parts[1]}"
    if len(parts) == 1 and parts[0]:
        return f"classic/{parts[0]}"
    return None


def classify_eni(eni: Any, *, region: str, account: str, instances: dict[str, Any],
                 lb_names: set[str]) -> tuple[str, Optional[str]]:
    """``(kind, who)`` of one interface. Only two kinds are MODELLED, and each needs more than a string a user
    can write: ``instance`` (attached, in use, an instance this pull described in this region and account;
    ``who`` is its id) and ``lb`` (requester-managed, in use, whose typed name a load balancer of this pull
    carries; ``who`` is the typed name: a user-created interface can be given any description, but not
    ``RequesterManaged``). Everything else is UNMODELLED (D32): ``lambda``, ``ecs``, ``rds`` (on purpose),
    ``vpce``, ``nat_gateway``, ``detached``, ``other``. Unknown widens: an interface we cannot place is ``other``."""
    if not isinstance(eni, dict):
        return "other", None
    status = eni.get("Status")
    itype = eni.get("InterfaceType") or "interface"
    if not isinstance(itype, str):          # a shape botocore cannot produce: unplaceable, never hashed
        itype = "?"
    desc = eni.get("Description") if isinstance(eni.get("Description"), str) else ""
    managed = eni.get("RequesterManaged") is True
    att = eni.get("Attachment") if isinstance(eni.get("Attachment"), dict) else {}
    in_use = status == "in-use"
    iid = att.get("InstanceId")
    if in_use and not managed and itype in _INSTANCE_ITYPES and isinstance(iid, str) and iid:
        inst = instances.get(iid)
        owner = att.get("InstanceOwnerId")
        if inst is not None and inst.region == region and (owner is None or owner == account):
            return "instance", iid
    if in_use and managed and itype in _LB_ITYPES:
        key = _eni_lb_key(desc)
        if key is not None and key in lb_names:
            return "lb", key
    if itype == "lambda" or desc.startswith("AWS Lambda VPC ENI"):
        return "lambda", None
    if itype in ("vpc_endpoint", "gateway_load_balancer_endpoint") or desc.startswith("VPC Endpoint Interface"):
        return "vpce", None
    if itype == "nat_gateway":
        return "nat_gateway", None
    if _ARN_ECS.match(desc):
        return "ecs", None
    if desc.startswith("RDSNetworkInterface"):
        return "rds", None
    if status == "available":
        return "detached", None
    return "other", None


def eni_group_ids(eni: Any) -> list[str]:
    """The security group ids of one interface (``[]`` when the answer is unreadable)."""
    groups = eni.get("Groups") if isinstance(eni, dict) else None
    if not isinstance(groups, list):
        return []
    return sorted({g["GroupId"] for g in groups if isinstance(g, dict) and isinstance(g.get("GroupId"), str)
                   and g["GroupId"]})


def eni_groups_readable(eni: Any) -> bool:
    """Every security group entry of the interface names its group (a non-empty ``GroupId`` string), and there is
    at least one. A partly readable list could hide the very group a rule references."""
    groups = eni.get("Groups") if isinstance(eni, dict) else None
    return (isinstance(groups, list) and bool(groups)
            and all(isinstance(g, dict) and isinstance(g.get("GroupId"), str) and bool(g["GroupId"]) for g in groups))


def summarize_enis(enis: list[Any], *, region: str, account: str, instances: dict[str, Any], lb_names: set[str],
                   sg_ids: set[str]) -> dict[str, dict[str, Any]]:
    """Per security group in ``sg_ids``: the modelled members, the unmodelled interfaces and whether a cap hit.
    Pure and order independent (sorted before capping). An interface in several groups counts in each."""
    inst: dict[str, set[str]] = {g: set() for g in sg_ids}
    lbs: dict[str, set[str]] = {g: set() for g in sg_ids}
    kinds: dict[str, dict[str, int]] = {g: {} for g in sg_ids}
    sample: dict[str, list[tuple[str, str, bool]]] = {g: [] for g in sg_ids}
    count: dict[str, int] = {g: 0 for g in sg_ids}
    for eni in enis:
        groups = [g for g in eni_group_ids(eni) if g in sg_ids]
        if not groups:
            continue
        kind, who = classify_eni(eni, region=region, account=account, instances=instances, lb_names=lb_names)
        eid = str(eni.get("NetworkInterfaceId") or "")[:64]
        public = isinstance(eni.get("Association"), dict) and bool(eni["Association"].get("PublicIp"))
        for g in groups:
            if kind == "instance" and who:
                inst[g].add(who)
            elif kind == "lb" and who:
                lbs[g].add(who)
            else:
                count[g] += 1
                kinds[g][kind] = kinds[g].get(kind, 0) + 1
                sample[g].append((eid, kind, public))
    out: dict[str, dict[str, Any]] = {}
    for g in sorted(sg_ids):
        ids, names = sorted(inst[g]), sorted(lbs[g])
        out[g] = {
            "instances": ids[:MAX_ENI_INSTANCES], "lbs": names[:MAX_ENI_LBS],
            "unmodeled": {"count": count[g], "kinds": dict(sorted(kinds[g].items())),
                          "sample": [{"id": i, "kind": k, "public": p}
                                     for i, k, p in sorted(sample[g])[:MAX_ENI_SAMPLE]]},
            "truncated": len(ids) > MAX_ENI_INSTANCES or len(names) > MAX_ENI_LBS,
        }
    return out


# --------------------------------------------------------------------------- #
# Builder: accumulates the batch while the pull walks the account
# --------------------------------------------------------------------------- #

@dataclass
class _Instance:
    arn: str
    region: str
    instance_id: str
    private_ips: list[str]
    public_ips: list[str]
    sg_ids: list[str]
    profile_arn: Optional[str]
    metadata: dict[str, Any]


@dataclass
class _State:
    account: str
    partition: str
    admin_ports: tuple[int, ...]
    crown_tags: list[str]
    data_stores_sensitive: bool
    batch: SourceBatch = field(default_factory=SourceBatch)
    warnings: list[str] = field(default_factory=list)
    instances: dict[str, _Instance] = field(default_factory=dict)        # instance_id -> info
    sgs: dict[str, dict[str, Any]] = field(default_factory=dict)        # sg_id -> raw
    lb_dns: dict[str, str] = field(default_factory=dict)                # dns -> lb arn
    lb_public: dict[str, bool] = field(default_factory=dict)            # lb arn -> public
    public_ip_owner: dict[str, str] = field(default_factory=dict)       # ip -> instance arn
    roles_by_instance: dict[str, list[str]] = field(default_factory=dict)
    role_grants: dict[str, list[tuple[list[str], list[str], str]]] = field(default_factory=dict)
    buckets: list[str] = field(default_factory=list)
    # region -> every DescribeSecurityGroups and DescribeInstances page came back (False: the lists are partial)
    region_ok: dict[str, bool] = field(default_factory=dict)
    # region -> the interface inventory read: {complete, read_at, eni_total, members{sg_id: summary}}
    eni_inv: dict[str, dict[str, Any]] = field(default_factory=dict)
    # region -> typed names (``app/<n>``, ``net/<n>``, ``gwy/<n>``, ``classic/<n>``) of the load balancers described
    lb_names: dict[str, set[str]] = field(default_factory=dict)

    def arn(self, service: str, region: str, resource: str) -> str:
        return f"arn:{self.partition}:{service}:{region}:{self.account}:{resource}"


@register
class AwsConnector(Connector):
    kind = "aws"
    display_name = "Amazon Web Services"
    category = "cloud"
    capabilities = frozenset({Capability.SOURCE})
    config_schema = {
        "type": "object",
        "properties": {
            "role_arn": {"type": "string", "title": "Role ARN to assume (recommended)",
                         "pattern": "^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$"},
            "regions": {"type": "array", "items": {"type": "string"},
                        "default": ["us-east-1"],
                        "description": "Regions to inventory, or [\"all\"] for every enabled region"},
            "home_region": {"type": "string", "default": "us-east-1"},
            "include_s3": {"type": "boolean", "default": True},
            "include_route53": {"type": "boolean", "default": True},
            "include_iam": {"type": "boolean", "default": True},
            "include_private_zones": {"type": "boolean", "default": False},
            "data_stores_are_crown_jewels": {"type": "boolean", "default": True},
            "crown_jewel_tags": {"type": "array", "items": {"type": "string"},
                                 "description": "Tags marking crown jewels: 'Key' or 'Key=Value'"},
            "admin_ports": {"type": "array", "items": {"type": "integer"}},
            "sync_interval_minutes": {"type": "integer", "default": 360, "minimum": 15},
        },
    }
    secret_fields = ("access_key_id", "secret_access_key", "session_token", "external_id")
    docs_url = "docs/INTEGRATIONS-CONTEXT.md#aws"

    # Test seam: a callable returning a boto3-like Session. None -> boto3.
    session_factory: Optional[Callable[..., Any]] = None

    def __init__(self, config, secrets, http) -> None:
        super().__init__(config, secrets, http)
        self.last_warnings: list[str] = []

    # ------------------------------------------------------------------ #
    # Credentials
    # ------------------------------------------------------------------ #
    def _boto(self):
        try:
            import boto3  # noqa: F401
            from botocore.config import Config
        except ImportError as exc:  # pragma: no cover - depends on the extra
            raise SourceError("boto3 is not installed (pip install 'paddock-orchestrator[aws]')",
                              retryable=False) from exc
        return Config(retries={"max_attempts": 5, "mode": "standard"},
                      connect_timeout=10, read_timeout=30,
                      user_agent_extra="paddock-asm-readonly")

    def _session(self):
        import boto3

        factory = self.session_factory or boto3.session.Session
        home = str(self.config.get("home_region") or "us-east-1")
        kw: dict[str, Any] = {"region_name": home}
        if self.secrets.get("access_key_id") and self.secrets.get("secret_access_key"):
            kw["aws_access_key_id"] = self.secrets["access_key_id"]
            kw["aws_secret_access_key"] = self.secrets["secret_access_key"]
            if self.secrets.get("session_token"):
                kw["aws_session_token"] = self.secrets["session_token"]
        base = factory(**kw)
        role_arn = self.config.get("role_arn")
        if not role_arn:
            return base
        params: dict[str, Any] = {"RoleArn": str(role_arn), "RoleSessionName": "paddock-asm-readonly",
                                  "DurationSeconds": 3600}
        if self.secrets.get("external_id"):
            params["ExternalId"] = self.secrets["external_id"]
        creds = self._call("sts:AssumeRole", base.client("sts", config=self._boto()).assume_role,
                           **params)["Credentials"]
        return factory(region_name=home, aws_access_key_id=creds["AccessKeyId"],
                       aws_secret_access_key=creds["SecretAccessKey"],
                       aws_session_token=creds["SessionToken"])

    @staticmethod
    def _code(exc: Exception) -> str:
        resp = getattr(exc, "response", None)
        if isinstance(resp, dict):
            return str(resp.get("Error", {}).get("Code") or type(exc).__name__)
        return type(exc).__name__

    def _call(self, what: str, fn: Callable[..., Any], **kw: Any) -> Any:
        """Hard call: an error aborts the pull with a safe message."""
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

        try:
            return fn(**kw)
        except NoCredentialsError as exc:
            raise SourceError("no AWS credentials configured", retryable=False) from exc
        except (ClientError, BotoCoreError) as exc:
            code = self._code(exc)
            raise SourceError(f"{what} failed: {code}",
                              retryable=code not in ("AccessDenied", "AccessDeniedException",
                                                     "InvalidClientTokenId",
                                                     "UnrecognizedClientException")) from exc

    def _soft(self, st: _State, what: str, fn: Callable[..., Any], default: Any = None,
              ok_codes: tuple[str, ...] = (), **kw: Any) -> Any:
        """Soft call: an error becomes a warning and the pull goes on."""
        from botocore.exceptions import BotoCoreError, ClientError

        try:
            return fn(**kw)
        except (ClientError, BotoCoreError) as exc:
            code = self._code(exc)
            if code not in ok_codes:
                st.warnings.append(f"{what}: {code}")
            return default

    def _pages_ok(self, st: _State, what: str, client: Any, op: str, key: str,
                  **kw: Any) -> tuple[list[Any], bool]:
        """Every page of a paginated call, and whether ALL of them arrived. A failed page is a warning and
        ``ok=False``: the items before it are returned (they are real), but the caller must not treat the list
        as the whole answer."""
        from botocore.exceptions import BotoCoreError, ClientError

        out: list[Any] = []
        try:
            for page in client.get_paginator(op).paginate(**kw):
                out.extend(page.get(key) or [])
        except (ClientError, BotoCoreError) as exc:
            st.warnings.append(f"{what}: {self._code(exc)}")
            return out, False
        return out, True

    def _pages(self, st: _State, what: str, client: Any, op: str, key: str, **kw: Any) -> list[Any]:
        return self._pages_ok(st, what, client, op, key, **kw)[0]

    # ------------------------------------------------------------------ #
    # Contract
    # ------------------------------------------------------------------ #
    async def test(self) -> HealthResult:
        try:
            ident = await asyncio.to_thread(self._identity)
        except SourceError as exc:
            return HealthResult(ok=False, detail=str(exc))
        return HealthResult(ok=True, detail=f"authenticated to AWS account {ident['Account']}")

    def _identity(self) -> dict[str, Any]:
        cfg = self._boto()
        sess = self._session()
        return self._call("sts:GetCallerIdentity", sess.client("sts", config=cfg).get_caller_identity)

    async def pull(self) -> SourceBatch:
        return await asyncio.to_thread(self._pull_sync)

    # ------------------------------------------------------------------ #
    # The walk
    # ------------------------------------------------------------------ #
    def _pull_sync(self) -> SourceBatch:
        cfg = self._boto()
        sess = self._session()
        ident = self._call("sts:GetCallerIdentity", sess.client("sts", config=cfg).get_caller_identity)
        account = str(ident["Account"])
        partition = str(ident.get("Arn", "arn:aws:")).split(":")[1] or "aws"
        admin = tuple(int(p) for p in (self.config.get("admin_ports") or DEFAULT_ADMIN_PORTS))
        st = _State(account=account, partition=partition, admin_ports=admin,
                    crown_tags=[str(t) for t in self.config.get("crown_jewel_tags") or []],
                    data_stores_sensitive=bool_cfg(self.config, "data_stores_are_crown_jewels", True))
        st.batch.assets.append(asset(
            "cloud_account", f"aws:{account}", SOURCE,
            {"provider": "aws", "account_id": account, "partition": partition},
        ))

        for region in self._regions(st, sess, cfg):
            self._region(st, sess, cfg, region)
        if bool_cfg(self.config, "include_iam", True):
            self._iam(st, sess, cfg)
        if bool_cfg(self.config, "include_s3", True):
            self._s3(st, sess, cfg)
            self._role_bucket_edges(st)
        if bool_cfg(self.config, "include_route53", True):
            self._route53(st, sess, cfg)
        self.last_warnings = st.warnings
        return st.batch

    def _regions(self, st: _State, sess: Any, cfg: Any) -> list[str]:
        wanted = [str(r) for r in (self.config.get("regions") or ["us-east-1"])]
        if any(r.lower() == "all" for r in wanted):
            ec2 = sess.client("ec2", config=cfg)
            resp = self._call("ec2:DescribeRegions", ec2.describe_regions)
            return sorted(r["RegionName"] for r in resp.get("Regions", []))
        return wanted

    # -- per region ------------------------------------------------------ #
    def _region(self, st: _State, sess: Any, cfg: Any, region: str) -> None:
        ec2 = sess.client("ec2", region_name=region, config=cfg)
        groups, sg_ok = self._pages_ok(st, f"ec2:DescribeSecurityGroups[{region}]", ec2,
                                       "describe_security_groups", "SecurityGroups")
        for sg in groups:
            st.sgs[sg["GroupId"]] = {**sg, "_region": region}
        reservations, inst_ok = self._pages_ok(st, f"ec2:DescribeInstances[{region}]", ec2,
                                               "describe_instances", "Reservations")
        # A partial group or instance listing means nodes and rules are missing from what we write: every asset
        # of the region says so, and the reach builder withdraws coverage for them (the metadata merge is
        # shallow, so the flag is written True as well as False and a stale False never survives).
        st.region_ok[region] = sg_ok and inst_ok
        for res in reservations:
            for inst in res.get("Instances") or []:
                self._instance(st, region, inst)

        self._load_balancers(st, sess, cfg, region)
        self._eni_inventory(st, ec2, region)
        self._security_group_findings(st, region)
        self._rds(st, sess, cfg, region)

    def _eni_inventory(self, st: _State, ec2: Any, region: str) -> None:
        """Read every network interface of the region once and summarise it per security group of the region.

        A failed or partial read, or an interface whose groups cannot be read, makes the whole inventory
        INCOMPLETE (no per-group member lists are kept: a short list read as complete is the false HOLDS this
        exists to prevent). AccessDenied is a warning, not a failed pull."""
        items, ok = self._pages_ok(st, f"ec2:DescribeNetworkInterfaces[{region}]", ec2,
                                   "describe_network_interfaces", "NetworkInterfaces")
        if ok and any(not eni_groups_readable(e) for e in items):
            st.warnings.append(f"ec2:DescribeNetworkInterfaces[{region}]: unreadable interface")
            ok = False
        read_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        members: dict[str, dict[str, Any]] = {}
        if ok:
            sg_ids = {sid for sid, sg in st.sgs.items() if sg.get("_region") == region}
            members = summarize_enis(
                items, region=region, account=st.account,
                instances={iid: i for iid, i in st.instances.items() if i.region == region},
                lb_names=st.lb_names.get(region, set()), sg_ids=sg_ids)
        st.eni_inv[region] = {"complete": ok, "read_at": read_at, "eni_total": len(items) if ok else 0,
                              "members": members}

    def _instance(self, st: _State, region: str, inst: dict[str, Any]) -> None:
        iid = inst["InstanceId"]
        state = (inst.get("State") or {}).get("Name")
        if state == "terminated":
            return
        arn = st.arn("ec2", region, f"instance/{iid}")
        tags = tags_dict(inst.get("Tags"))
        private_ips: list[str] = []
        public_ips: list[str] = []
        for eni in inst.get("NetworkInterfaces") or []:
            for pa in eni.get("PrivateIpAddresses") or []:
                if pa.get("PrivateIpAddress"):
                    private_ips.append(pa["PrivateIpAddress"])
                pub = (pa.get("Association") or {}).get("PublicIp")
                if pub:
                    public_ips.append(pub)
            for v6 in eni.get("Ipv6Addresses") or []:
                if v6.get("Ipv6Address") and is_public_ip(v6["Ipv6Address"]):
                    public_ips.append(v6["Ipv6Address"])
        if inst.get("PrivateIpAddress") and inst["PrivateIpAddress"] not in private_ips:
            private_ips.insert(0, inst["PrivateIpAddress"])
        if inst.get("PublicIpAddress") and inst["PublicIpAddress"] not in public_ips:
            public_ips.insert(0, inst["PublicIpAddress"])
        sg_ids = [g["GroupId"] for g in inst.get("SecurityGroups") or [] if g.get("GroupId")]
        for eni in inst.get("NetworkInterfaces") or []:     # multi-ENI instances
            for g in eni.get("Groups") or []:
                if g.get("GroupId") and g["GroupId"] not in sg_ids:
                    sg_ids.append(g["GroupId"])
        world: list[tuple[str, int, int]] = []
        for sid in sg_ids:
            world.extend(world_open_ranges(st.sgs.get(sid, {})))
        running = state in (None, "running", "pending")
        public = bool(public_ips) and bool(world) and running
        profile = (inst.get("IamInstanceProfile") or {}).get("Arn")
        md: dict[str, Any] = {
            "provider": "aws", "service": "ec2", "resource_type": "instance",
            "account_id": st.account, "region": region, "instance_id": iid,
            "name": tags.get("Name"), "state": state,
            "instance_type": inst.get("InstanceType"), "platform": inst.get("PlatformDetails"),
            "image_id": inst.get("ImageId"), "vpc_id": inst.get("VpcId"),
            "subnet_id": inst.get("SubnetId"),
            "private_ips": private_ips, "public_ips": public_ips,
            "ip": private_ips[0] if private_ips else None,
            "public_dns": inst.get("PublicDnsName") or None,
            "private_dns": inst.get("PrivateDnsName") or None,
            "hostname": (inst.get("PrivateDnsName") or None),
            "security_groups": sg_ids, "iam_instance_profile": profile,
            "internet_ingress": describe_ranges(world) if public_ips else [],
            "public": public, "aws_tags": tags or None,
            "inventory_complete": st.region_ok.get(region, True),
        }
        if crown_jewel_by_tags(tags, st.crown_tags):
            md["crown_jewel"] = True
        st.batch.assets.append(asset("cloud_resource", arn, SOURCE, md))
        st.instances[iid] = _Instance(arn, region, iid, private_ips, public_ips, sg_ids, profile, md)

        for ip in public_ips:
            k = ip_kind(ip)
            st.batch.assets.append(asset(k, ip, SOURCE, {
                "provider": "aws", "cloud_resource": arn, "public": public,
                "internet_ingress": describe_ranges(world),
            }))
            st.batch.edges.append(edge(k, ip, "cloud_resource", arn, "attached_to",
                                       {"source": SOURCE}))
            st.public_ip_owner[ip] = arn

        hit = admin_ports_hit(world, st.admin_ports)
        if public_ips and hit and running:
            st.batch.findings.append(finding(
                "cloud_resource", arn, "aws.ec2.admin_port_open_to_internet", "high",
                f"EC2 {tags.get('Name') or iid} exposes admin/database ports {hit} to the internet",
                f"Instance {iid} in {region} has public address(es) {public_ips} and a security "
                f"group admitting 0.0.0.0/0 or ::/0 on ports {hit}.",
                source=SOURCE,
                impact="Remote administration and database ports reachable from anywhere are a "
                       "primary initial-access vector (credential stuffing, unpatched services).",
                remediation="Restrict the security group rule to known source ranges, or move "
                            "administration behind SSM Session Manager / a bastion / VPN.",
                evidence={"ports": hit, "security_groups": sg_ids, "public_ips": public_ips},
            ))

    @staticmethod
    def _eni_md(st: _State, region: str, sid: str) -> dict[str, Any]:
        """``eni_inventory`` and ``eni_members`` for one group. ALWAYS both keys: a failed or missing read writes
        ``complete: False`` and ``{}``, so a ``complete: True`` from an earlier pull can never survive the shallow
        metadata merge."""
        inv = st.eni_inv.get(region)
        if inv and inv["complete"] and sid in inv["members"]:
            return {"eni_inventory": {"complete": True, "read_at": inv["read_at"], "region": region,
                                      "eni_total": inv["eni_total"]},
                    "eni_members": inv["members"][sid]}
        read_at = inv["read_at"] if inv else dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        return {"eni_inventory": {"complete": False, "read_at": read_at, "region": region, "eni_total": 0},
                "eni_members": {}}

    def _security_group_findings(self, st: _State, region: str) -> None:
        attached: dict[str, list[str]] = {}
        for inst in st.instances.values():
            if inst.region != region:
                continue
            for sid in inst.sg_ids:
                attached.setdefault(sid, []).append(inst.instance_id)
        for sid, sg in st.sgs.items():
            if sg.get("_region") != region:
                continue
            world = world_open_ranges(sg)
            hit = admin_ports_hit(world, st.admin_ports)
            arn = st.arn("ec2", region, f"security-group/{sid}")
            md: dict[str, Any] = {
                "provider": "aws", "service": "ec2", "resource_type": "security_group",
                "account_id": st.account, "region": region, "group_id": sid,
                "name": sg.get("GroupName"), "vpc_id": sg.get("VpcId"),
                "world_ingress": describe_ranges(world),
                "attached_instances": attached.get(sid, []),
                "inventory_complete": st.region_ok.get(region, True),
            }
            md.update(self._eni_md(st, region, sid))
            # Full ingress rules for the reach graph (aws_sg builder). Present even when empty
            # ("rules synced"); omitted when the API gave no IpPermissions list at all, so a
            # malformed answer never reads as "this group admits nothing".
            if isinstance(sg.get("IpPermissions"), list):
                md["ingress_rules"] = normalize_ingress(sg)
                md["ingress_truncated"] = ingress_truncated(sg)
            else:   # the merge is shallow: flag any older rules as no longer complete
                md["ingress_truncated"] = True
            st.batch.assets.append(asset("cloud_resource", arn, SOURCE, md))
            if hit:
                st.batch.findings.append(finding(
                    "cloud_resource", arn, "aws.ec2.sg_admin_port_open_to_world", "medium",
                    f"Security group {sg.get('GroupName') or sid} admits the internet on "
                    f"admin/database ports {hit}",
                    f"Security group {sid} ({region}) has ingress from 0.0.0.0/0 or ::/0 "
                    f"covering {hit}. Attached instances: {attached.get(sid, []) or 'none'}.",
                    source=SOURCE,
                    remediation="Scope the rule to specific CIDRs or security groups.",
                    evidence={"ports": hit, "rules": describe_ranges(world)},
                ))

    def _load_balancers(self, st: _State, sess: Any, cfg: Any, region: str) -> None:
        by_private_ip = {ip: i for i in st.instances.values() if i.region == region
                         for ip in i.private_ips}
        elbv2 = sess.client("elbv2", region_name=region, config=cfg)
        for lb in self._pages(st, f"elbv2:DescribeLoadBalancers[{region}]", elbv2,
                              "describe_load_balancers", "LoadBalancers"):
            arn = lb["LoadBalancerArn"]
            public = lb.get("Scheme") == "internet-facing"
            listeners = self._pages(st, f"elbv2:DescribeListeners[{region}]", elbv2,
                                    "describe_listeners", "Listeners", LoadBalancerArn=arn)
            ports = sorted({(int(x["Port"]), str(x.get("Protocol"))) for x in listeners
                            if x.get("Port") is not None})
            dns = (lb.get("DNSName") or "").lower().rstrip(".")
            st.batch.assets.append(asset("cloud_resource", arn, SOURCE, {
                "provider": "aws", "service": "elasticloadbalancing",
                "resource_type": f"{lb.get('Type', 'application')}_load_balancer",
                "account_id": st.account, "region": region, "name": lb.get("LoadBalancerName"),
                "scheme": lb.get("Scheme"), "dns_name": dns or None, "public": public,
                "listeners": [{"port": p, "protocol": proto} for p, proto in ports],
                "security_groups": lb.get("SecurityGroups") or [], "vpc_id": lb.get("VpcId"),
            }))
            if dns:
                st.lb_dns[dns] = arn
            st.lb_public[arn] = public
            typed = lb_typed_name(lb.get("Type", "application"), lb.get("LoadBalancerName"))
            if typed:
                st.lb_names.setdefault(region, set()).add(typed)
            tgs = self._pages(st, f"elbv2:DescribeTargetGroups[{region}]", elbv2,
                              "describe_target_groups", "TargetGroups", LoadBalancerArn=arn)
            for tg in tgs:
                health = self._soft(st, f"elbv2:DescribeTargetHealth[{region}]",
                                    elbv2.describe_target_health, {},
                                    TargetGroupArn=tg["TargetGroupArn"])
                for desc in (health or {}).get("TargetHealthDescriptions") or []:
                    tid = str((desc.get("Target") or {}).get("Id") or "")
                    inst = st.instances.get(tid) or by_private_ip.get(tid)
                    if inst is None:
                        continue
                    st.batch.edges.append(edge("cloud_resource", arn, "cloud_resource", inst.arn,
                                               "routes_to", {
                                                   "source": SOURCE,
                                                   "port": (desc.get("Target") or {}).get("Port"),
                                                   "protocol": tg.get("Protocol"),
                                                   "target_group": tg.get("TargetGroupName"),
                                               }))

        elb = sess.client("elb", region_name=region, config=cfg)
        for lb in self._pages(st, f"elb:DescribeLoadBalancers[{region}]", elb,
                              "describe_load_balancers", "LoadBalancerDescriptions"):
            name = lb["LoadBalancerName"]
            arn = st.arn("elasticloadbalancing", region, f"loadbalancer/{name}")
            public = lb.get("Scheme") == "internet-facing"
            dns = (lb.get("DNSName") or "").lower().rstrip(".")
            listeners = [ld.get("Listener") or {} for ld in lb.get("ListenerDescriptions") or []]
            st.batch.assets.append(asset("cloud_resource", arn, SOURCE, {
                "provider": "aws", "service": "elasticloadbalancing",
                "resource_type": "classic_load_balancer", "account_id": st.account,
                "region": region, "name": name, "scheme": lb.get("Scheme"),
                "dns_name": dns or None, "public": public,
                "listeners": [{"port": li.get("LoadBalancerPort"), "protocol": li.get("Protocol"),
                               "instance_port": li.get("InstancePort")} for li in listeners],
                "security_groups": lb.get("SecurityGroups") or [],
            }))
            if dns:
                st.lb_dns[dns] = arn
            st.lb_public[arn] = public
            typed = lb_typed_name("classic", name)
            if typed:
                st.lb_names.setdefault(region, set()).add(typed)
            for ref in lb.get("Instances") or []:
                inst = st.instances.get(ref.get("InstanceId", ""))
                if inst:
                    st.batch.edges.append(edge("cloud_resource", arn, "cloud_resource", inst.arn,
                                               "routes_to", {"source": SOURCE}))

    def _rds(self, st: _State, sess: Any, cfg: Any, region: str) -> None:
        rds = sess.client("rds", region_name=region, config=cfg)
        for db in self._pages(st, f"rds:DescribeDBInstances[{region}]", rds,
                              "describe_db_instances", "DBInstances"):
            arn = db.get("DBInstanceArn") or st.arn("rds", region, f"db:{db['DBInstanceIdentifier']}")
            endpoint = db.get("Endpoint") or {}
            port = endpoint.get("Port")
            sg_ids = [g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups") or []
                      if g.get("VpcSecurityGroupId")]
            tags = tags_dict(db.get("TagList"))
            world: list[tuple[str, int, int]] = []
            for sid in sg_ids:
                world.extend(world_open_ranges(st.sgs.get(sid, {})))
            world_on_port = [r for r in world if r[0] in ("tcp", "6", "all")
                             and port is not None and r[1] <= int(port) <= r[2]]
            public = bool(db.get("PubliclyAccessible"))
            md: dict[str, Any] = {
                "provider": "aws", "service": "rds", "resource_type": "db_instance",
                "account_id": st.account, "region": region,
                "name": db.get("DBInstanceIdentifier"), "engine": db.get("Engine"),
                "engine_version": db.get("EngineVersion"),
                "endpoint": endpoint.get("Address"), "port": port,
                "publicly_accessible": public, "storage_encrypted": db.get("StorageEncrypted"),
                "security_groups": sg_ids, "vpc_id": (db.get("DBSubnetGroup") or {}).get("VpcId"),
                "data_store": True, "aws_tags": tags or None,
            }
            if st.data_stores_sensitive:
                md["sensitive"] = True
            if crown_jewel_by_tags(tags, st.crown_tags):
                md["crown_jewel"] = True
            st.batch.assets.append(asset("cloud_resource", arn, SOURCE, md))

            if public:
                sev = "critical" if world_on_port else "high"
                st.batch.findings.append(finding(
                    "cloud_resource", arn, "aws.rds.publicly_accessible", sev,
                    f"RDS instance {db.get('DBInstanceIdentifier')} is publicly accessible",
                    f"RDS {db.get('DBInstanceIdentifier')} ({db.get('Engine')}, {region}) has "
                    "PubliclyAccessible=true, so its endpoint resolves to a public address"
                    + (" and a security group admits the internet on its port." if world_on_port
                       else "."),
                    source=SOURCE,
                    impact="A database reachable from the internet is one weak password or "
                           "unpatched engine away from a data breach.",
                    remediation="Set PubliclyAccessible=false (modify-db-instance) and reach the "
                                "database from inside the VPC only.",
                    evidence={"port": port, "security_groups": sg_ids,
                              "world_ingress": describe_ranges(world_on_port)},
                ))

            # instance --can_reach--> db when the db's SGs admit the instance's
            # SG or private IP. Directional fact from the SG rules.
            admit_groups: set[str] = set()
            admit_nets: list[Any] = []
            for sid in sg_ids:
                g, n = sg_ingress_sources(st.sgs.get(sid, {}))
                admit_groups |= g
                admit_nets.extend(n)
            for inst in st.instances.values():
                if inst.region != region:
                    continue
                via = sorted(admit_groups.intersection(inst.sg_ids))
                by_cidr = any(ipaddress.ip_address(ip) in net for ip in inst.private_ips
                              for net in admit_nets if ipaddress.ip_address(ip).version == net.version)
                if via or by_cidr:
                    st.batch.edges.append(edge("cloud_resource", inst.arn, "cloud_resource", arn,
                                               "can_reach", {"source": SOURCE, "port": port,
                                                             "via_security_groups": via}))

    # -- IAM --------------------------------------------------------------- #
    def _iam(self, st: _State, sess: Any, cfg: Any) -> None:
        iam = sess.client("iam", config=cfg)
        profiles: dict[str, list[dict[str, Any]]] = {}
        for inst in st.instances.values():
            if not inst.profile_arn:
                continue
            if inst.profile_arn not in profiles:
                name = inst.profile_arn.rsplit("/", 1)[-1]
                resp = self._soft(st, "iam:GetInstanceProfile", iam.get_instance_profile, {},
                                  InstanceProfileName=name)
                profiles[inst.profile_arn] = ((resp or {}).get("InstanceProfile") or {}).get("Roles") or []
            for role in profiles[inst.profile_arn]:
                rarn = role["Arn"]
                if rarn not in st.role_grants:
                    st.role_grants[rarn] = self._role_grants(st, iam, role["RoleName"])
                    st.batch.assets.append(asset("cloud_resource", rarn, SOURCE, {
                        "provider": "aws", "service": "iam", "resource_type": "role",
                        "account_id": st.account, "name": role["RoleName"],
                        "s3_grants": [{"actions": a[:10], "resources": r[:10], "policy": p}
                                      for a, r, p in st.role_grants[rarn]][:20],
                    }))
                st.roles_by_instance.setdefault(inst.arn, []).append(rarn)
                st.batch.edges.append(edge("cloud_resource", inst.arn, "cloud_resource", rarn,
                                           "has_role", {"source": SOURCE,
                                                        "instance_profile": inst.profile_arn}))

    def _role_grants(self, st: _State, iam: Any, role: str) -> list[tuple[list[str], list[str], str]]:
        grants: list[tuple[list[str], list[str], str]] = []
        for pol in self._pages(st, "iam:ListAttachedRolePolicies", iam,
                               "list_attached_role_policies", "AttachedPolicies", RoleName=role):
            parn, pname = pol.get("PolicyArn", ""), pol.get("PolicyName", "")
            if ":iam::aws:policy/" in parn:
                base = parn.rsplit("/", 1)[-1]
                if base in _BROAD_S3_MANAGED:
                    grants.append((_BROAD_S3_MANAGED[base], ["*"], pname))
                continue
            meta = self._soft(st, "iam:GetPolicy", iam.get_policy, {}, PolicyArn=parn)
            ver = ((meta or {}).get("Policy") or {}).get("DefaultVersionId")
            if not ver:
                continue
            doc = self._soft(st, "iam:GetPolicyVersion", iam.get_policy_version, {},
                             PolicyArn=parn, VersionId=ver)
            for acts, res in s3_grants(((doc or {}).get("PolicyVersion") or {}).get("Document")):
                grants.append((acts, res, pname))
        for pname in self._pages(st, "iam:ListRolePolicies", iam, "list_role_policies",
                                 "PolicyNames", RoleName=role):
            doc = self._soft(st, "iam:GetRolePolicy", iam.get_role_policy, {},
                             RoleName=role, PolicyName=pname)
            for acts, res in s3_grants((doc or {}).get("PolicyDocument")):
                grants.append((acts, res, pname))
        return grants

    # -- S3 ---------------------------------------------------------------- #
    def _s3(self, st: _State, sess: Any, cfg: Any) -> None:
        s3 = sess.client("s3", config=cfg)
        resp = self._soft(st, "s3:ListAllMyBuckets", s3.list_buckets, {})
        buckets = (resp or {}).get("Buckets") or []
        acct_pab: dict[str, Any] = {}
        if buckets:
            s3c = sess.client("s3control", config=cfg)
            r = self._soft(st, "s3:GetAccountPublicAccessBlock", s3c.get_public_access_block, {},
                           ok_codes=("NoSuchPublicAccessBlockConfiguration",),
                           AccountId=st.account)
            acct_pab = (r or {}).get("PublicAccessBlockConfiguration") or {}
        clients: dict[str, Any] = {}
        for b in buckets:
            name = b["Name"]
            loc = self._soft(st, "s3:GetBucketLocation", s3.get_bucket_location, {}, Bucket=name)
            region = (loc or {}).get("LocationConstraint") or "us-east-1"
            if region == "EU":
                region = "eu-west-1"
            c = clients.get(region) or sess.client("s3", region_name=region, config=cfg)
            clients[region] = c
            r = self._soft(st, "s3:GetBucketPublicAccessBlock", c.get_public_access_block, {},
                           ok_codes=("NoSuchPublicAccessBlockConfiguration",), Bucket=name)
            pab = dict((r or {}).get("PublicAccessBlockConfiguration") or {})
            eff = {k: bool(pab.get(k) or acct_pab.get(k)) for k in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
            acl = self._soft(st, "s3:GetBucketAcl", c.get_bucket_acl, {}, Bucket=name)
            acl_public = any(
                (g.get("Grantee") or {}).get("URI", "").endswith(("/global/AllUsers",
                                                                  "/global/AuthenticatedUsers"))
                for g in (acl or {}).get("Grants") or []
            ) and not eff["IgnorePublicAcls"]
            ps = self._soft(st, "s3:GetBucketPolicyStatus", c.get_bucket_policy_status, {},
                            ok_codes=("NoSuchBucketPolicy",), Bucket=name)
            policy_public = bool(((ps or {}).get("PolicyStatus") or {}).get("IsPublic")) \
                and not eff["RestrictPublicBuckets"]
            tags: dict[str, str] = {}
            if st.crown_tags:
                t = self._soft(st, "s3:GetBucketTagging", c.get_bucket_tagging, {},
                               ok_codes=("NoSuchTagSet",), Bucket=name)
                tags = tags_dict((t or {}).get("TagSet"))
            arn = f"arn:{st.partition}:s3:::{name}"
            via = [v for v, on in (("acl", acl_public), ("policy", policy_public)) if on]
            md: dict[str, Any] = {
                "provider": "aws", "service": "s3", "resource_type": "bucket",
                "account_id": st.account, "region": region, "name": name,
                "public_access_block": eff, "publicly_readable": bool(via),
                "public_via": via, "data_store": True, "aws_tags": tags or None,
            }
            if st.data_stores_sensitive:
                md["sensitive"] = True
            if crown_jewel_by_tags(tags, st.crown_tags):
                md["crown_jewel"] = True
            st.batch.assets.append(asset("cloud_resource", arn, SOURCE, md))
            st.buckets.append(name)
            if via:
                st.batch.findings.append(finding(
                    "cloud_resource", arn, "aws.s3.bucket_public", "high",
                    f"S3 bucket {name} is public (via {', '.join(via)})",
                    f"Bucket {name} grants access to everyone through its "
                    f"{' and '.join(via)}, and Block Public Access does not neutralise it.",
                    source=SOURCE,
                    impact="Anyone on the internet can list or read (and possibly write) objects.",
                    remediation="Enable S3 Block Public Access at the account and bucket level; "
                                "serve public content through CloudFront with OAC instead.",
                    evidence={"public_via": via, "public_access_block": eff},
                ))

    def _role_bucket_edges(self, st: _State) -> None:
        for rarn, grants in st.role_grants.items():
            for name in st.buckets:
                acts: set[str] = set()
                pols: set[str] = set()
                for a, r, p in grants:
                    if bucket_matches(name, r):
                        acts.update(a)
                        pols.add(p)
                if acts:
                    st.batch.edges.append(edge(
                        "cloud_resource", rarn, "cloud_resource", f"arn:{st.partition}:s3:::{name}",
                        "can_access", {"source": SOURCE, "actions": sorted(acts)[:20],
                                       "policies": sorted(pols)[:20]},
                    ))

    # -- Route53 ----------------------------------------------------------- #
    def _route53(self, st: _State, sess: Any, cfg: Any) -> None:
        r53 = sess.client("route53", config=cfg)
        include_private = bool_cfg(self.config, "include_private_zones", False)
        for zone in self._pages(st, "route53:ListHostedZones", r53, "list_hosted_zones",
                                "HostedZones"):
            private = bool((zone.get("Config") or {}).get("PrivateZone"))
            if private and not include_private:
                continue
            zname = zone["Name"].rstrip(".").lower()
            st.batch.assets.append(asset("domain", zname, SOURCE, {
                "provider": "aws", "route53_zone_id": zone["Id"].rsplit("/", 1)[-1],
                "private_zone": private, "account_id": st.account,
            }))
            for rec in self._pages(st, "route53:ListResourceRecordSets", r53,
                                   "list_resource_record_sets", "ResourceRecordSets",
                                   HostedZoneId=zone["Id"]):
                self._record(st, zname, rec, private)

    def _record(self, st: _State, zone: str, rec: dict[str, Any], private: bool) -> None:
        rtype = rec.get("Type")
        if rtype not in ("A", "AAAA", "CNAME"):
            return
        name = str(rec.get("Name", "")).rstrip(".").lower()
        if not name or name.startswith("\\052") or name.startswith("*"):
            return
        kind = "domain" if name == zone else "subdomain"
        values = [str(v.get("Value", "")).rstrip(".").lower()
                  for v in rec.get("ResourceRecords") or []]
        alias = (rec.get("AliasTarget") or {}).get("DNSName")
        targets_dns = [v for v in values if rtype == "CNAME"]
        if alias:
            targets_dns.append(str(alias).rstrip(".").lower())
        public = False
        edges: list[dict[str, Any]] = []
        if rtype in ("A", "AAAA") and not alias:
            for ip in values:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                k = ip_kind(ip)
                pub = is_public_ip(ip)
                owned = ip in st.public_ip_owner
                if not owned:
                    st.batch.assets.append(asset(k, ip, SOURCE, {"provider": "aws",
                                                                 "dns_record": name}))
                public = public or (pub and not private)
                edges.append(edge(kind, name, k, ip, "resolves_to", {"source": SOURCE,
                                                                     "record_type": rtype}))
        lb_hit = None
        for t in targets_dns:
            t = t[len("dualstack."):] if t.startswith("dualstack.") else t
            if t in st.lb_dns:
                lb_hit = st.lb_dns[t]
                public = public or (st.lb_public.get(lb_hit, False) and not private)
                edges.append(edge(kind, name, "cloud_resource", lb_hit, "routes_to",
                                  {"source": SOURCE, "record_type": rtype, "alias": bool(alias)}))
        md: dict[str, Any] = {"provider": "aws", "dns_zone": zone, "record_type": rtype,
                              "private_zone": private}
        if rtype == "CNAME" or alias:
            md["cname"] = targets_dns[0] if targets_dns else None
        if public:
            md["public"] = True
        st.batch.assets.append(asset(kind, name, SOURCE, md))
        st.batch.edges.extend(edges)
