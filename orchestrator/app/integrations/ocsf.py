"""Map Paddock findings and integration events to OCSF 1.3.

OCSF (Open Cybersecurity Schema Framework) is the lingua franca every SIEM
connector in ``connectors/`` sends, and what ``GET /v1/export/findings.ocsf``
streams. Two classes from the *Findings* category (``category_uid = 2``):

* **Vulnerability Finding** (``class_uid 2002``) -- any finding that carries a
  CVE: ``rule_source = 'cve_match'``, a ``CVE-...`` rule id, or SCA evidence
  with ``cve_ids``. The CVE goes into ``vulnerabilities[].cve`` with its CVSS
  and EPSS scores and the KEV flag (``is_exploit_available``).
* **Detection Finding** (``class_uid 2004``) -- everything else (SAST,
  exposed files, TLS/header checks, policies, chains, and the non-finding
  events such as ``attack_path.opened`` or ``device.behavior``). A CWE, when
  known, rides in ``vulnerabilities[].cwe`` (an optional 1.3 attribute of
  Detection Finding) together with the affected code location for SAST.

``type_uid`` is ``class_uid * 100 + activity_id`` (1 Create, 2 Update,
3 Close, 99 Other) as the spec requires. Paddock's own values that OCSF has no
slot for -- the original severity label, CVSS/EPSS, rule source, status,
classification and blast score -- are kept verbatim under
``unmapped.paddock`` so nothing is lost on the way into the SIEM.

The mapping is pure (no I/O) and never includes secrets: a finding's
``evidence`` is NOT copied wholesale (it can contain response snippets), only
the specific location/identifier fields listed here.
"""
from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping, Optional

from .. import __version__

OCSF_VERSION = "1.3.0"

CATEGORY_FINDINGS = 2
CLASS_VULNERABILITY_FINDING = 2002
CLASS_DETECTION_FINDING = 2004

ACTIVITY_CREATE = 1
ACTIVITY_UPDATE = 2
ACTIVITY_CLOSE = 3
ACTIVITY_OTHER = 99

_ACTIVITY_NAME = {1: "Create", 2: "Update", 3: "Close", 99: "Other"}
_CLASS_NAME = {2002: "Vulnerability Finding", 2004: "Detection Finding"}

# OCSF severity_id: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High,
# 5 Critical, 6 Fatal, 99 Other.
SEVERITY_ID: dict[str, int] = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_SEVERITY_CAPTION = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
                     4: "High", 5: "Critical"}

# OCSF finding status_id: 1 New, 2 In Progress, 3 Suppressed, 4 Resolved, 99 Other.
STATUS_ID: dict[str, int] = {
    "open": 1,
    "triaged": 2,
    "accepted_risk": 3,
    "false_positive": 3,
    "wontfix": 3,
    "fixed": 4,
}
_STATUS_CAPTION = {1: "New", 2: "In Progress", 3: "Suppressed", 4: "Resolved", 99: "Other"}

# Event type -> (activity_id, status override). Non-finding events are
# Detection Findings with activity Create (something new was detected) or
# Other (operational notices).
_EVENT_ACTIVITY: dict[str, int] = {
    "finding.opened": ACTIVITY_CREATE,
    "finding.updated": ACTIVITY_UPDATE,
    "finding.reopened": ACTIVITY_UPDATE,
    "finding.accepted": ACTIVITY_UPDATE,
    "finding.resolved": ACTIVITY_CLOSE,
    "finding.verified": ACTIVITY_UPDATE,
    "finding.fix_verified": ACTIVITY_CLOSE,
    "finding.fix_failed": ACTIVITY_UPDATE,
    "attack_path.opened": ACTIVITY_CREATE,
    "change.detected": ACTIVITY_CREATE,
    "asset.discovered": ACTIVITY_CREATE,
    "device.behavior": ACTIVITY_CREATE,
    "sensor.offline": ACTIVITY_CREATE,
}
_EVENT_STATUS: dict[str, int] = {
    "finding.opened": 1,
    "finding.reopened": 1,
    "finding.accepted": 3,
    "finding.resolved": 4,
    "finding.fix_verified": 4,
    "finding.fix_failed": 1,
}

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-(\d{1,5})\b", re.IGNORECASE)

# Observable type_ids (OCSF 1.3): 1 Hostname, 2 IP Address, 6 URL String.
_OBS_HOSTNAME, _OBS_IP, _OBS_URL = 1, 2, 6
_HOST_KINDS = {"domain", "subdomain"}
_IP_KINDS = {"ipv4", "ipv6"}


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def severity_id(severity: Optional[str]) -> int:
    return SEVERITY_ID.get((severity or "").lower(), 0)


def severity_caption(sid: int) -> str:
    return _SEVERITY_CAPTION.get(sid, "Other")


def to_epoch_ms(value: Any) -> Optional[int]:
    """OCSF ``timestamp_t``: integer milliseconds since the Unix epoch."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp() * 1000)
    if isinstance(value, date):
        return int(datetime(value.year, value.month, value.day, tzinfo=timezone.utc).timestamp() * 1000)
    return None


def _num(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    return [v]


def _dedupe(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(i for i in items if i))


def _mapping(v: Any) -> Mapping[str, Any]:
    return v if isinstance(v, Mapping) else {}


def _str(v: Any) -> Optional[str]:
    return None if v is None else str(v)


def extract_cves(finding: Mapping[str, Any]) -> list[str]:
    """Every CVE id a finding refers to, upper-cased and de-duplicated."""
    ev = _mapping(finding.get("evidence"))
    md = _mapping(finding.get("metadata"))
    cands: list[str] = []
    rule_id = str(finding.get("rule_id") or "")
    cands += _CVE_RE.findall(rule_id)
    for src in (ev, md):
        for key in ("cve", "cve_id", "cve_ids", "cves"):
            for v in _as_list(src.get(key)):
                cands += _CVE_RE.findall(str(v))
    return _dedupe(c.upper() for c in cands)


def extract_cwes(finding: Mapping[str, Any], cve: Optional[Mapping[str, Any]] = None) -> list[str]:
    """Every CWE id (``CWE-89`` form) known for a finding."""
    ev = _mapping(finding.get("evidence"))
    md = _mapping(finding.get("metadata"))
    cands: list[str] = []
    for src in (ev, md):
        for key in ("cwe", "cwe_id", "cwe_ids", "cwes"):
            for v in _as_list(src.get(key)):
                cands += [f"CWE-{n}" for n in _CWE_RE.findall(str(v))]
    if cve:
        for v in _as_list(cve.get("cwe_ids")):
            cands += [f"CWE-{n}" for n in _CWE_RE.findall(str(v))]
    return _dedupe(c.upper() for c in cands)


def cwe_object(cwe: str) -> dict[str, Any]:
    num = cwe.split("-")[-1]
    return {
        "uid": cwe,
        "caption": cwe,
        "src_url": f"https://cwe.mitre.org/data/definitions/{num}.html",
    }


def _product() -> dict[str, Any]:
    return {
        "name": "Paddock",
        "vendor_name": "Paddock",
        "version": __version__,
        "url_string": "https://github.com/brandongraff-dev/cybersec",
    }


def _metadata(uid: str, *, labels: Iterable[str] = (), original_time: Any = None,
              modified: Any = None, correlation_uid: Optional[str] = None) -> dict[str, Any]:
    md: dict[str, Any] = {
        "version": OCSF_VERSION,
        "product": _product(),
        "uid": uid,
        "logged_time": to_epoch_ms(datetime.now(timezone.utc)),
    }
    labels = _dedupe(labels)
    if labels:
        md["labels"] = labels
    if original_time is not None:
        md["original_time"] = str(original_time.isoformat() if hasattr(original_time, "isoformat")
                                  else original_time)
    if modified is not None:
        md["modified_time"] = to_epoch_ms(modified)
    if correlation_uid:
        md["correlation_uid"] = correlation_uid
    return md


def _resource(finding: Mapping[str, Any], asset: Optional[Mapping[str, Any]]) -> Optional[dict[str, Any]]:
    a = _mapping(asset)
    uid = a.get("id") or finding.get("asset_id")
    name = a.get("value") or finding.get("asset_value")
    kind = a.get("kind") or finding.get("asset_kind")
    if not (uid or name):
        return None
    res: dict[str, Any] = {}
    if uid:
        res["uid"] = str(uid)
    if name:
        res["name"] = str(name)
    if kind:
        res["type"] = str(kind)
    labels = []
    cls = finding.get("classification") or a.get("classification")
    if cls:
        labels.append(f"classification:{cls}")
    if labels:
        res["labels"] = labels
    if a.get("canonical"):
        res["data"] = {"canonical": a.get("canonical")}
    return res


def _observables(resource: Optional[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if not resource or not resource.get("name"):
        return []
    kind = resource.get("type")
    name = resource["name"]
    if kind in _HOST_KINDS:
        return [{"name": "resources[0].name", "type_id": _OBS_HOSTNAME, "type": "Hostname", "value": name}]
    if kind in _IP_KINDS:
        return [{"name": "resources[0].name", "type_id": _OBS_IP, "type": "IP Address", "value": name}]
    if kind == "endpoint" and "://" in str(name):
        return [{"name": "resources[0].name", "type_id": _OBS_URL, "type": "URL String", "value": name}]
    return []


def _affected_code(finding: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    ev = _mapping(finding.get("evidence"))
    path = ev.get("file") or finding.get("file")
    if not path:
        return None
    path = str(path)
    code: dict[str, Any] = {"file": {"name": path.rsplit("/", 1)[-1], "path": path, "type_id": 1,
                                     "type": "Regular File"}}
    start = ev.get("start_line", finding.get("start_line"))
    end = ev.get("end_line", finding.get("end_line"))
    if isinstance(start, int) and start > 0:
        code["start_line"] = start
    if isinstance(end, int) and end > 0:
        code["end_line"] = end
    return code


def _affected_package(finding: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    ev = _mapping(finding.get("evidence"))
    name = ev.get("package")
    version = ev.get("version")
    if not (name and version):
        return None
    pkg: dict[str, Any] = {"name": str(name), "version": str(version)}
    if ev.get("ecosystem"):
        pkg["package_manager"] = str(ev["ecosystem"])
    if ev.get("purl"):
        pkg["purl"] = str(ev["purl"])
    if ev.get("fixed_version"):
        pkg["fixed_in_version"] = str(ev["fixed_version"])
    return pkg


def _cve_object(cve_id: str, finding: Mapping[str, Any], cve: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    c = _mapping(cve) if cve and str(cve.get("id", cve_id)).upper() == cve_id else {}
    obj: dict[str, Any] = {"uid": cve_id}
    score = _num(c.get("cvss_v3")) if c else None
    if score is None:
        score = _num(finding.get("cvss"))
    if score is not None:
        cvss: dict[str, Any] = {"version": "3.1", "base_score": score}
        if c.get("cvss_v3_vector"):
            vec = str(c["cvss_v3_vector"])
            cvss["vector_string"] = vec
            if vec.startswith("CVSS:3.0"):
                cvss["version"] = "3.0"
        obj["cvss"] = [cvss]
    epss = _num(c.get("epss")) if c else None
    if epss is None:
        epss = _num(finding.get("epss"))
    if epss is not None:
        e: dict[str, Any] = {"score": str(epss)}
        if c.get("epss_percentile") is not None:
            e["percentile"] = _num(c.get("epss_percentile"))
        obj["epss"] = e
    if c.get("description"):
        obj["desc"] = str(c["description"])
    if c.get("published_at") is not None:
        obj["created_time"] = to_epoch_ms(c["published_at"])
    if c.get("modified_at") is not None:
        obj["modified_time"] = to_epoch_ms(c["modified_at"])
    obj["references"] = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
    return obj


def _kev(finding: Mapping[str, Any], cve: Optional[Mapping[str, Any]]) -> Optional[bool]:
    md = _mapping(finding.get("metadata"))
    if cve and cve.get("known_exploited") is not None:
        return bool(cve["known_exploited"]) or bool(md.get("kev"))
    if "kev" in md:
        return bool(md.get("kev"))
    return None


# --------------------------------------------------------------------------- #
# public: findings
# --------------------------------------------------------------------------- #

def finding_class_uid(finding: Mapping[str, Any]) -> int:
    return CLASS_VULNERABILITY_FINDING if extract_cves(finding) else CLASS_DETECTION_FINDING


def finding_to_ocsf(
    finding: Mapping[str, Any],
    *,
    asset: Optional[Mapping[str, Any]] = None,
    cve: Optional[Mapping[str, Any]] = None,
    activity_id: Optional[int] = None,
    event_type: Optional[str] = None,
    event_id: Optional[str] = None,
    event_time: Any = None,
    url: Optional[str] = None,
) -> dict[str, Any]:
    """Map one Paddock finding (``FindingOut``-shaped mapping) to OCSF 1.3.

    ``cve`` is the optional ``cves`` row for the finding's CVE (adds the
    CVSS vector, EPSS percentile, CWE ids and the KEV flag). ``activity_id``
    defaults from the finding status (Close when fixed, else Create).
    """
    f = finding
    sev = str(f.get("severity") or "").lower() or None
    sid = severity_id(sev)
    status = str(f.get("status") or "open")
    status_id = STATUS_ID.get(status, 99)
    if event_type in _EVENT_STATUS:
        status_id = _EVENT_STATUS[event_type]
    if activity_id is None:
        activity_id = _EVENT_ACTIVITY.get(event_type or "", None) or (
            ACTIVITY_CLOSE if status == "fixed" else ACTIVITY_CREATE)
    cves = extract_cves(f)
    cwes = extract_cwes(f, cve)
    class_uid = CLASS_VULNERABILITY_FINDING if cves else CLASS_DETECTION_FINDING
    fid = str(f.get("id") or event_id or "")
    rule_id = str(f.get("rule_id") or "")
    rule_source = f.get("rule_source")
    title = str(f.get("title") or rule_id or "Paddock finding")
    desc = str(f.get("description") or "")
    refs = [str(r) for r in _as_list(f.get("references")) if r]

    time_ms = to_epoch_ms(event_time) or to_epoch_ms(f.get("last_seen")) or to_epoch_ms(
        datetime.now(timezone.utc))

    finding_info: dict[str, Any] = {
        "uid": fid,
        "title": title,
        "desc": desc,
        "types": _dedupe([str(rule_source)] if rule_source else []),
        "analytic": {
            "uid": rule_id,
            "name": rule_id,
            "type_id": 1,
            "type": "Rule",
            "category": str(rule_source) if rule_source else None,
        },
    }
    finding_info["analytic"] = {k: v for k, v in finding_info["analytic"].items() if v}
    if f.get("first_seen") is not None:
        finding_info["first_seen_time"] = to_epoch_ms(f["first_seen"])
        finding_info["created_time"] = to_epoch_ms(f["first_seen"])
    if f.get("last_seen") is not None:
        finding_info["last_seen_time"] = to_epoch_ms(f["last_seen"])
        finding_info["modified_time"] = to_epoch_ms(f["last_seen"])
    if url:
        finding_info["src_url"] = url

    ocsf: dict[str, Any] = {
        "category_uid": CATEGORY_FINDINGS,
        "category_name": "Findings",
        "class_uid": class_uid,
        "class_name": _CLASS_NAME[class_uid],
        "activity_id": activity_id,
        "activity_name": _ACTIVITY_NAME.get(activity_id, "Other"),
        "type_uid": class_uid * 100 + activity_id,
        "type_name": f"{_CLASS_NAME[class_uid]}: {_ACTIVITY_NAME.get(activity_id, 'Other')}",
        "time": time_ms,
        "severity_id": sid,
        "severity": severity_caption(sid),
        "status_id": status_id,
        "status": _STATUS_CAPTION.get(status_id, "Other"),
        "message": title,
        "finding_info": finding_info,
        "metadata": _metadata(
            event_id or fid,
            labels=["paddock", str(rule_source or ""), *(["event:" + event_type] if event_type else [])],
            original_time=f.get("last_seen"),
            modified=f.get("last_seen"),
            correlation_uid=fid or None,
        ),
    }
    if status_id == 99:
        ocsf["status_detail"] = status

    resource = _resource(f, asset)
    if resource:
        ocsf["resources"] = [resource]
        obs = _observables(resource)
        if obs:
            ocsf["observables"] = obs

    remediation_text = f.get("remediation")
    if remediation_text or refs:
        rem: dict[str, Any] = {"desc": str(remediation_text or "See references.")}
        if refs:
            rem["references"] = refs[:50]
        ocsf["remediation"] = rem

    # vulnerabilities[] -- required for 2002, optional (CWE / code) for 2004.
    vulns: list[dict[str, Any]] = []
    kev = _kev(f, cve)
    code = _affected_code(f)
    pkg = _affected_package(f)
    base_vuln: dict[str, Any] = {"title": title, "desc": desc, "severity": severity_caption(sid)}
    if refs:
        base_vuln["references"] = refs[:50]
    if remediation_text:
        base_vuln["remediation"] = {"desc": str(remediation_text)}
    if pkg:
        base_vuln["affected_packages"] = [pkg]
        base_vuln["is_fix_available"] = bool(pkg.get("fixed_in_version"))
    if code:
        base_vuln["affected_code"] = [code]
    if f.get("first_seen") is not None:
        base_vuln["first_seen_time"] = to_epoch_ms(f["first_seen"])
    if f.get("last_seen") is not None:
        base_vuln["last_seen_time"] = to_epoch_ms(f["last_seen"])
    if cves:
        for cve_id in cves:
            v = dict(base_vuln)
            v["cve"] = _cve_object(cve_id, f, cve)
            if cwes:
                v["cwe"] = cwe_object(cwes[0])
            if kev is not None:
                v["is_exploit_available"] = kev
            vulns.append(v)
    elif cwes or code:
        v = dict(base_vuln)
        if cwes:
            v["cwe"] = cwe_object(cwes[0])
        vulns.append(v)
    if vulns:
        ocsf["vulnerabilities"] = vulns

    paddock: dict[str, Any] = {
        "finding_id": fid or None,
        "severity": sev,
        "status": status,
        "rule_id": rule_id or None,
        "rule_source": rule_source,
        "cvss": _num(f.get("cvss")),
        "epss": _num(f.get("epss")),
        "blast_score": _num(f.get("blast_score")),
        "classification": f.get("classification"),
        "assigned_to": f.get("assigned_to"),
        "kev": kev,
        "impact": _str(f.get("impact")),
        "cwes": cwes or None,
    }
    if event_type:
        paddock["event_type"] = event_type
    ocsf["unmapped"] = {"paddock": {k: v for k, v in paddock.items() if v is not None}}
    return ocsf


# --------------------------------------------------------------------------- #
# public: integration events
# --------------------------------------------------------------------------- #

def _finding_from_event_data(data: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    f = data.get("finding")
    if isinstance(f, Mapping):
        return f
    if "rule_id" in data and ("title" in data or "severity" in data):
        return data
    return None


def event_to_ocsf(event: Any) -> dict[str, Any]:
    """Map an ``integrations.Event`` (or its ``as_dict()``) to OCSF 1.3.

    ``finding.*`` events whose ``data`` carries the finding (``data.finding``
    or the finding fields at the top level) become full Vulnerability/
    Detection Findings with the right activity (opened -> Create,
    updated/reopened/accepted -> Update, resolved -> Close). Every other
    event type becomes a Detection Finding built from the event's title,
    summary, severity and (optional) ``data.asset``.
    """
    ev = event.as_dict() if hasattr(event, "as_dict") else dict(event)
    etype = str(ev.get("type") or "")
    data = _mapping(ev.get("data"))
    occurred = ev.get("occurred_at")
    asset = data.get("asset") if isinstance(data.get("asset"), Mapping) else None
    cve = data.get("cve") if isinstance(data.get("cve"), Mapping) else None
    finding = _finding_from_event_data(data)
    if finding is not None:
        f = dict(finding)
        if not f.get("severity") and ev.get("severity"):
            f["severity"] = ev["severity"]
        if not f.get("title"):
            f["title"] = ev.get("title")
        out = finding_to_ocsf(
            f, asset=asset, cve=cve, event_type=etype, event_id=str(ev.get("id") or ""),
            event_time=occurred, url=ev.get("url"),
        )
        if ev.get("tenant_id"):
            out["metadata"]["tenant_uid"] = str(ev["tenant_id"])
        return out

    activity = _EVENT_ACTIVITY.get(etype, ACTIVITY_OTHER)
    sid = severity_id(ev.get("severity")) or 1
    eid = str(ev.get("id") or "")
    # A stable finding uid for the thing the event is about, when the payload
    # names one (attack path id, change id, device id...), else the event id.
    subject = next((str(data[k]) for k in ("finding_id", "attack_path_id", "path_id", "change_id",
                                            "device_id", "asset_id", "scan_id") if data.get(k)), eid)
    title = str(ev.get("title") or etype)
    finding_info: dict[str, Any] = {
        "uid": subject,
        "title": title,
        "desc": str(ev.get("summary") or ""),
        "types": [etype],
        "analytic": {"uid": etype, "name": etype, "type_id": 1, "type": "Rule"},
    }
    if ev.get("url"):
        finding_info["src_url"] = ev["url"]
    out = {
        "category_uid": CATEGORY_FINDINGS,
        "category_name": "Findings",
        "class_uid": CLASS_DETECTION_FINDING,
        "class_name": _CLASS_NAME[CLASS_DETECTION_FINDING],
        "activity_id": activity,
        "activity_name": _ACTIVITY_NAME.get(activity, "Other"),
        "type_uid": CLASS_DETECTION_FINDING * 100 + activity,
        "type_name": f"Detection Finding: {_ACTIVITY_NAME.get(activity, 'Other')}",
        "time": to_epoch_ms(occurred) or to_epoch_ms(datetime.now(timezone.utc)),
        "severity_id": sid,
        "severity": severity_caption(sid),
        "status_id": 1,
        "status": "New",
        "message": title,
        "finding_info": finding_info,
        "metadata": _metadata(eid, labels=["paddock", "event:" + etype], original_time=occurred),
    }
    if ev.get("tenant_id"):
        out["metadata"]["tenant_uid"] = str(ev["tenant_id"])
    if asset:
        res = _resource({}, asset)
        if res:
            out["resources"] = [res]
            obs = _observables(res)
            if obs:
                out["observables"] = obs
    paddock = {"event_type": etype, "severity": ev.get("severity")}
    # Small scalar context only -- never dump arbitrary nested payloads.
    ctx = {k: v for k, v in data.items() if isinstance(v, (str, int, float, bool)) and k != "asset"}
    if ctx:
        paddock["data"] = dict(list(ctx.items())[:25])
    out["unmapped"] = {"paddock": {k: v for k, v in paddock.items() if v is not None}}
    return out


def event_uid(ocsf: Mapping[str, Any]) -> str:
    """The idempotency key a connector sends alongside an OCSF record."""
    return str(_mapping(ocsf.get("metadata")).get("uid") or "")
