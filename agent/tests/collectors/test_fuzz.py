"""Hostile and corrupted input: parsers either return structured data or raise only the
declared exceptions (which the collectors map to ``error``); nothing else may escape, and a
mutated real capture must never produce a more permissive claim than a parse failure."""
import copy
import json
import random

from paddock_agent.collectors import fwmodel, listeners, patch, sshd

from .helpers import fixture

NFT = json.loads(fixture("ubuntu2404/nft_json_unshare.json"))
IPT = fixture("ubuntu2404/iptables_save_unshare.txt")
TCP = fixture("ubuntu2404/proc_net_tcp.container.txt")
DQ = fixture("ubuntu2404/dpkg_query_sample.ubuntu2404.tsv")
APT = fixture("ubuntu2404/apt_get_s_dist_upgrade.ubuntu2404.txt")
SSHD_T = fixture("synthetic/sshd/sshd_T.ubuntu2404.txt")
JUNK = ["", "\x00", "\n\n", "::::", "a" * 5000, "\t" * 7, "-A INPUT -j", "-A INPUT -s", "!", "\"", "'",
        "Inst", "Match", "0A", "{", "]]", "\ud800".encode("utf-8", "replace").decode("utf-8"), "%s%s"]


def mutate_text(rng, text):
    lines = text.splitlines()
    for _ in range(rng.randint(1, 6)):
        op = rng.choice(["drop", "dup", "junk", "trunc", "swap", "chop"])
        if not lines:
            break
        i = rng.randrange(len(lines))
        if op == "drop":
            del lines[i]
        elif op == "dup":
            lines.insert(i, lines[i])
        elif op == "junk":
            lines.insert(i, rng.choice(JUNK))
        elif op == "trunc":
            lines[i] = lines[i][:rng.randint(0, len(lines[i]))]
        elif op == "swap":
            j = rng.randrange(len(lines))
            lines[i], lines[j] = lines[j], lines[i]
        else:
            lines[i] = lines[i].replace(rng.choice(" :-/,"), rng.choice(JUNK[:6]), 1)
    return "\n".join(lines)


def mutate_json(rng, obj, depth=0):
    if isinstance(obj, dict):
        for k in list(obj):
            r = rng.random()
            if r < 0.04:
                del obj[k]
            elif r < 0.08:
                obj[k] = rng.choice([None, 0, -1, "", "x", [], {}, [1, 2], {"a": 1}, True, 2 ** 70])
            else:
                mutate_json(rng, obj[k], depth + 1)
    elif isinstance(obj, list):
        for i in range(len(obj)):
            r = rng.random()
            if r < 0.04:
                obj[i] = rng.choice([None, 0, "", "x", [], {}, {"match": {}}, {"accept": 1}])
            else:
                mutate_json(rng, obj[i], depth + 1)
    return obj


def test_nft_normaliser_only_raises_declared_errors_and_model_stays_serialisable():
    allowed = (ValueError, KeyError, TypeError, AttributeError, IndexError, fwmodel.FwModelError,
               fwmodel.FwTooLarge)
    ok = bad = 0
    for seed in range(400):
        rng = random.Random(seed)
        doc = mutate_json(rng, copy.deepcopy(NFT))
        try:
            m = fwmodel.build_model(fwmodel.normalise_nft(doc), "nft", [], False)
        except allowed:
            bad += 1
            continue
        ok += 1
        json.dumps(m)
        assert m["flat_view"]["confidence"] in ("exact", "approximate", "unknown")
        for fam in ("ip4", "ip6"):
            assert m["families"][fam]["effective_default"] in ("accept", "drop", "reject", "unknown")
    assert ok > 15 and bad > 20  # the fuzzer exercised both outcomes


def test_iptables_parser_only_raises_declared_errors():
    for seed in range(400):
        rng = random.Random(seed)
        text = mutate_text(rng, IPT)
        try:
            m = fwmodel.build_model(fwmodel.parse_iptables_save(text, 4, "legacy4"), "legacy", [], False)
        except (fwmodel.FwModelError, fwmodel.FwTooLarge):
            continue
        json.dumps(m)


def test_unparsed_rule_never_leaves_an_exact_model():
    """A rule line the parser cannot read must downgrade the model, never vanish."""
    text = "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -m comment --comment \"unterminated -j ACCEPT\nCOMMIT\n"
    m = fwmodel.build_model(fwmodel.parse_iptables_save(text, 4, "legacy4"), "legacy", [], False)
    assert m["flat_view"]["confidence"] == "unknown"
    assert fwmodel.default_inbound_all_families(m) == "unknown"


def test_proc_net_parser_never_raises():
    for seed in range(300):
        rng = random.Random(seed)
        text = mutate_text(rng, TCP)
        rows, bad = listeners.parse_proc_net(text, "tcp", 4)
        for r in rows:
            assert 0 < r["port"] < 65536 and r["bind_class"] in ("wildcard4", "loopback", "specific")
        rows, bad = listeners.parse_proc_net(text, "udp", 4)
        assert bad >= 0


def test_cgroup_parser_never_raises():
    for seed in range(200):
        rng = random.Random(seed)
        listeners.parse_cgroup(mutate_text(rng, "0::/system.slice/ssh.service\n12:cpu:/docker/" + "a" * 64 + "\n"))


def test_sshd_parsers_never_raise_and_stay_in_the_allowlist():
    for seed in range(300):
        rng = random.Random(seed)
        text = mutate_text(rng, SSHD_T)
        cfg, problems = sshd.normalise_config(sshd.parse_sshd_T(text))
        assert set(cfg) <= sshd.ALLOWLIST and isinstance(problems, list)
        st = sshd.parse_sshd_config(
            lambda p: ("ok", text.encode("utf-8")) if p == "/etc/ssh/sshd_config" else ("missing", b""),
            lambda p: ("missing", []))
        assert isinstance(st["matches"], list)
    for item in ["", "*", "!", "10.0.0.0/33", "::/129", "a,b", "1.2.3.4/8,!1.2.3.4/16", "x" * 500]:
        addrs, why = sshd.address_probe_points([item])
        assert (why is None) or addrs == []


def test_patch_parsers_never_raise():
    for seed in range(300):
        rng = random.Random(seed)
        rows, bad, held = patch.parse_dpkg_query(mutate_text(rng, DQ))
        assert all(len(r) == 5 for r in rows)
        p = patch.parse_apt_sim(mutate_text(rng, APT))
        assert p is None or p["unparsed"] >= 0
        patch.parse_dpkg_status(mutate_text(rng, fixture("synthetic/patch/dpkg_status_sample.txt")))
        patch.parse_rpm_qf(mutate_text(rng, fixture("synthetic/patch/rpm_qa_el9.tsv")))
        patch.parse_dnf_updateinfo(mutate_text(rng, fixture("synthetic/patch/dnf_updateinfo_security.el9.txt")))
        patch.parse_os_release(mutate_text(rng, fixture("ubuntu2404/os-release.ubuntu2404.txt")))
