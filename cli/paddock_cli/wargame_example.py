"""The sample project that ``paddock wargame init`` writes.

Guest Wi-Fi -> a smart fridge on the IoT VLAN -> the POS controller -> the payments database
(docs/WARGAME.md section 5). Everything is synthetic (RFC 5737 / private ranges, no real hosts).
The exports are deliberately small so the whole model fits on one screen.
"""
from __future__ import annotations

WARGAME_TOML = '''\
# wargame.toml: describes your environment to `paddock wargame`.
# Everything here is read locally. Nothing is sent anywhere and nothing is ever exploited:
# Wargame only reasons about what your firewall and cloud configs *permit*.
#
#   paddock wargame check          which routes reach a crown jewel, and the cheapest fix
#   paddock wargame plan plan.json would this Terraform change open a route or break live flows

[project]
name = "example-retail"

# Segments: the networks that matter. Roles:
#   entry         where an attacker could start (guest Wi-Fi, a vendor VPN, the internet)
#   crown_jewel   what must stay unreachable (cardholder data, patient records, the OT core)
#   intermediate  everything in between (the default)
[[segment]]
id = "guest-wifi"
role = "entry"
cidrs = ["10.9.0.0/24"]
reason = "guest wireless"

[[segment]]
id = "vendor-support"
role = "entry"
cidrs = ["203.0.113.0/28"]
reason = "remote support vendor"

[[segment]]
id = "branch-office"
role = "entry"
cidrs = ["10.20.0.0/24"]
reason = "branch office LAN"

[[segment]]
id = "iot"
cidrs = ["10.9.10.0/24"]
reason = "smart fridge, cameras, badge readers"

[[segment]]
id = "pos"
cidrs = ["10.5.0.0/24"]
reason = "POS controllers"

[[segment]]
id = "payments-db"
role = "crown_jewel"
jewel_kind = "cardholder_data"
cidrs = ["10.1.0.0/24"]
reason = "cardholder data"

# Config sources, paths relative to this file. vendor is one of:
#   fortinet | cisco_asa | paloalto   a firewall config export
#   aws                               `aws ec2 describe-security-groups` or `describe-network-acls` JSON
#   aws_routes                        `aws ec2 describe-route-tables` JSON (drops hops with no route)
# Optional: id_prefix = "fw1" (two devices that reuse rule set names), sg_members (aws only).
[[source]]
vendor = "fortinet"
path = "wargame/firewall.conf"

[[source]]
vendor = "aws"
path = "wargame/aws-security-groups.json"

# Firewall zones / interfaces and AWS subnets or ENIs -> the segment behind them. Rule sets whose
# two sides both resolve here are wired into the model automatically.
[zones]
guest = "guest-wifi"
wan = "vendor-support"
iot = "iot"
pos = "pos"

# [subnets]
# subnet-0abc = "payments-db"

# Declared edges for anything not auto-wired. `ruleset` names a rule set from a source (it is
# an error if it does not exist). With no ruleset the edge is an ungoverned adjacency and is only
# ever "inferred" (the weakest evidence): the honest label for "these share a switch".
# `port` is optional ("tcp/5432", "udp/53", "tcp/1000-2000"); `evidence` may be "observed".
[[edge]]
from = "pos"
to = "payments-db"
ruleset = "sg-0paymentsdb"
port = "tcp/5432"

[[edge]]
from = "branch-office"
to = "payments-db"
ruleset = "sg-0paymentsdb"

# Optional: observed traffic (Zeek conn.log JSON lines, firewall allow logs, generic JSON).
# Real flows add "observed" evidence, and `plan` uses them to list the live flows a change breaks.
[flows]
file = "wargame/flows.jsonl"
'''

FIREWALL_CONF = '''\
config firewall address
    edit "GUEST_NET"
        set subnet 10.9.0.0 255.255.255.0
    next
    edit "IOT_NET"
        set subnet 10.9.10.0 255.255.255.0
    next
    edit "POS_NET"
        set subnet 10.5.0.0 255.255.255.0
    next
    edit "support.vendor.example"
        set type fqdn
        set fqdn "support.vendor.example"
    next
end
config firewall service custom
    edit "PORTAL_8080"
        set tcp-portrange 8080
    next
end
config firewall policy
    edit 1
        set name "guest-to-iot-portal"
        set srcintf "guest"
        set dstintf "iot"
        set srcaddr "GUEST_NET"
        set dstaddr "IOT_NET"
        set action accept
        set schedule "always"
        set service "PORTAL_8080"
    next
    edit 2
        set name "iot-to-pos"
        set srcintf "iot"
        set dstintf "pos"
        set srcaddr "IOT_NET"
        set dstaddr "POS_NET"
        set action accept
        set schedule "always"
        set service "PORTAL_8080"
    next
    edit 3
        set name "vendor-support-to-pos"
        set srcintf "wan"
        set dstintf "pos"
        set srcaddr "support.vendor.example"
        set dstaddr "POS_NET"
        set action accept
        set schedule "always"
        set service "PORTAL_8080"
    next
end
'''

AWS_SECURITY_GROUPS = '''\
{
  "SecurityGroups": [
    {
      "GroupId": "sg-0paymentsdb",
      "GroupName": "payments-db",
      "AttachedTo": ["eni-0payments01"],
      "IpPermissions": [
        {
          "IpProtocol": "tcp",
          "FromPort": 5432,
          "ToPort": 5432,
          "IpRanges": [{"CidrIp": "10.5.0.0/24", "Description": "POS controllers"}],
          "Ipv6Ranges": [],
          "UserIdGroupPairs": [],
          "PrefixListIds": []
        }
      ]
    }
  ]
}
'''

FLOWS = (
    '{"ts":1700000001.1,"uid":"C1","id.orig_h":"10.9.0.23","id.orig_p":50211,'
    '"id.resp_h":"10.9.10.4","id.resp_p":8080,"proto":"tcp","conn_state":"SF"}\n'
    '{"ts":1700000002.2,"uid":"C2","id.orig_h":"10.5.0.12","id.orig_p":50212,'
    '"id.resp_h":"10.1.0.9","id.resp_p":5432,"proto":"tcp","conn_state":"SF"}\n'
    '{"ts":1700000003.3,"uid":"C3","id.orig_h":"10.5.0.13","id.orig_p":50213,'
    '"id.resp_h":"10.1.0.9","id.resp_p":5432,"proto":"tcp","conn_state":"SF"}\n'
)

EXAMPLE_PLAN = '''\
{
  "format_version": "1.2",
  "terraform_version": "1.7.5",
  "resource_changes": [
    {
      "address": "aws_security_group_rule.branch_to_payments_db",
      "mode": "managed",
      "type": "aws_security_group_rule",
      "name": "branch_to_payments_db",
      "change": {
        "actions": ["create"],
        "before": null,
        "after": {
          "type": "ingress",
          "from_port": 5432,
          "to_port": 5432,
          "protocol": "tcp",
          "cidr_blocks": ["10.20.0.0/24"],
          "security_group_id": "sg-0paymentsdb",
          "description": "branch reporting"
        },
        "after_unknown": {}
      }
    }
  ]
}
'''

# relative path -> content, in the order they are written
FILES: dict[str, str] = {
    "wargame.toml": WARGAME_TOML,
    "wargame/firewall.conf": FIREWALL_CONF,
    "wargame/aws-security-groups.json": AWS_SECURITY_GROUPS,
    "wargame/flows.jsonl": FLOWS,
    "wargame/example-plan.json": EXAMPLE_PLAN,
}
