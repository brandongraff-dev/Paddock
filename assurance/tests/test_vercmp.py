"""``vulnmatch.vercmp``: dpkg and rpm version comparison (contract 1.6.1).

A wrong order here is a wrong "patched": the suite pins the policy examples, the 89 ``rpmvercmp``
vectors (each also reversed), real-shape EVR rows, every refusal, hostile strings (contract 8.4 row
3) and a brute-force oracle against the real ``dpkg --compare-versions`` (skipped when dpkg is
absent), plus seeded property tests (always run) and hypothesis properties (when installed).
"""
from __future__ import annotations

import itertools
import pathlib
import random
import shutil
import subprocess

import pytest

from paddock_assurance.vulnmatch import vercmp as V
from paddock_assurance.vulnmatch.vercmp import VersionError

FIX = pathlib.Path(__file__).parent / "fixtures" / "vulnmatch"


def _rpm_vectors():
    rows = []
    for line in (FIX / "rpmvercmp.vectors.txt").read_text().splitlines():
        a, b, e = line.split("|")
        rows.append((a, b, int(e)))
    return rows


RPMVER = _rpm_vectors()


def test_rpmvercmp_vector_file_has_the_contract_count():
    assert len(RPMVER) == 89


@pytest.mark.parametrize("a,b,e", RPMVER)
def test_rpmvercmp_vectors_both_directions(a, b, e):
    assert V.rpmvercmp(a, b) == e
    assert V.rpmvercmp(b, a) == -e


RPMEVR = [
    ("5.14.0-427.13.1.el9_4", "5.14.0-503.11.1.el9_5", -1),
    ("1:1.0-1.el9", "0:9.9-9.el9", 1),                          # epoch dominates
    ("0:8.2.2637-15.el9", "2:8.2.2637-15.el9", -1),
    ("8.2.2637-15.el9", "0:8.2.2637-15.el9", 0),               # a missing epoch is 0
    ("3.0.7-27.el9", "3.0.7-27.el9_4.1", -1),
    ("3.0.7-27.el9_4.1", "3.0.7-27.el9_4.2", -1),
    ("3.0.7-27.el9_4.10", "3.0.7-27.el9_4.9", 1),              # numeric, not lexical
    ("1.2.3-1.module+el9.3.0+1234+abcd", "1.2.3-1.el9", 1),    # modular vs plain: the CALLER must not compare
    ("2.0-1.el9~beta", "2.0-1.el9", -1),
    ("9:1-1", "10:1-1", -1),                                   # epoch is numeric
]


@pytest.mark.parametrize("a,b,e", RPMEVR)
def test_rpm_evr_rows(a, b, e):
    assert V.rpm_cmp(a, b) == e and V.rpm_cmp(b, a) == -e


@pytest.mark.parametrize("bad", ["", "1.0", "x:1-1", "1:2:3-1", "-1", "1-", ":1-1", "1:-1",
                                 "1.0 -1", "1.0-1\n", "1\x00-1", "١-1", "1-١", "1" * 300 + "-1",
                                 "1--", "é-1"])
def test_rpm_refuses_what_is_not_an_evr(bad):
    with pytest.raises(VersionError):
        V.rpm_cmp(bad, "1-1")
    with pytest.raises(VersionError):
        V.rpm_cmp("1-1", bad)


DPKG = [
    ("1.0", "1.0", 0), ("1.0", "1.0-0", 0), ("1.0-1", "1.0-2", -1), ("1.0~rc1", "1.0", -1),
    ("1.0~~", "1.0~", -1), ("1.0~", "1.0", -1), ("1.0", "1.0+b1", -1), ("1.0a", "1.0", 1),
    ("1:0.1", "9.9", 1), ("0:1.0", "1.0", 0), ("1.0-1~bpo12+1", "1.0-1", -1),
    ("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u10", -1),            # numeric, not lexical
    ("3.0.13-0ubuntu3.1", "3.0.13-0ubuntu3.4", -1),
    ("3.0.13-0ubuntu3.1~esm1", "3.0.13-0ubuntu3.1", -1),       # ESM tilde sorts BEFORE the public fix
    ("2.36-9+deb12u7", "2.36-9+deb12u10", -1),
    ("1.2.3-1+b1", "1.2.3-1", 1),
    ("6.1.115-1", "6.1.99-1", 1),
    ("5.6.1+really5.4.5-1", "5.6.1-1", 1),                     # the 'really' hack
    ("1.0-1ubuntu0.24.04.1", "1.0-1", 1),
    ("007", "7", 0), ("1.0.0", "1.0", 1), ("1.0-0.1", "1.0", 1),
    ("1+dfsg-1", "1-1", 1), ("1.0+dfsg-1", "1.0-1", 1), ("1.0-1", "1.0+dfsg-1", -1),
    ("2.0-1", "10.0-1", -1),
    ("1:2.3-1", "1:2.3-1", 0),
    ("2.36-9+deb12u2", "2.36-9+deb12u3", -1),
    ("1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u9", -1),
    ("6.1.69-1", "6.1.76-1", -1),
    ("1:2:3-1", "1:2:4-1", -1),                                # a colon after the epoch is upstream text
    ("0:1-1", "1-1", 0),
    ("1-2-3", "1-2-4", -1),                                    # revision is after the LAST hyphen
]


@pytest.mark.parametrize("a,b,e", DPKG)
def test_dpkg_vectors_both_directions(a, b, e):
    assert V.dpkg_cmp(a, b) == e
    assert V.dpkg_cmp(b, a) == -e


HOSTILE_DPKG = [
    "", "a1", "x:1.0", "1.0 ", " 1.0", "1.0\n", "1:", "-1", "1.0_1", "v1.0", "V1.0",
    "1.0-",                                        # empty revision (dpkg refuses it)
    "١٢٣",                                         # arabic-indic digits: isdigit() is True, we are ASCII only
    "1.٣", "1.0-١", "²",                           # superscript two
    "1" * 257,                                     # over 256
    "1." + "0" * 10_240,                           # the 10 KB string
    "1234567890:1.0",                              # over-long epoch
    "-1:1.0", "+1:1.0", "1e3:1.0", "１:1.0",       # fullwidth digit epoch
    "1.0\x00", "1.0​", "1.0é", "1 0", "1.0;rm", "1/0",
    "::", ":1.0", "1.0-1-",
]


@pytest.mark.parametrize("bad", HOSTILE_DPKG)
def test_dpkg_refuses_hostile_strings_on_either_side(bad):
    with pytest.raises(VersionError):
        V.dpkg_cmp(bad, "1.0")
    with pytest.raises(VersionError):
        V.dpkg_cmp("1.0", bad)


@pytest.mark.parametrize("bad", [None, 1, 1.0, b"1.0", ["1.0"], object()])
def test_non_strings_are_refused_never_coerced(bad):
    with pytest.raises(VersionError):
        V.dpkg_cmp(bad, "1.0")
    with pytest.raises(VersionError):
        V.rpm_cmp("1-1", bad)
    with pytest.raises(VersionError):
        V.rpmvercmp(bad, "1")


def test_version_error_is_a_value_error_and_has_no_secrets():
    assert issubclass(VersionError, ValueError)
    try:
        V.dpkg_cmp("x" * 40, "1.0")
    except VersionError as e:
        assert "x" * 40 not in str(e)          # never echo an attacker string back


def test_dpkg_parse_shapes():
    assert V.dpkg_parse("1:9.2p1-2+deb12u3") == (1, "9.2p1", "2+deb12u3")
    assert V.dpkg_parse("1.0") == (0, "1.0", "")
    assert V.dpkg_parse("2:1-2-3") == (2, "1-2", "3")
    assert V.dpkg_parse("0:1.0-1") == (0, "1.0", "1")


def test_rpm_parse_shapes():
    assert V.rpm_parse("1:2.3-4.el9") == (1, "2.3", "4.el9")
    assert V.rpm_parse("2.3-4.el9") == (0, "2.3", "4.el9")
    assert V.rpm_parse("1.2-3-4.el9") == (0, "1.2-3", "4.el9")       # release after the LAST hyphen


def test_cmp_for_family():
    assert V.cmp_for("deb") is V.dpkg_cmp
    assert V.cmp_for("rpm") is V.rpm_cmp
    with pytest.raises(ValueError):
        V.cmp_for("apk")


def test_looks_esm_and_modular_helpers():
    assert V.is_esm_version("3.0.13-0ubuntu3.1~esm1")
    assert V.is_esm_version("1.0+esm2-1")
    assert V.is_esm_version("1.0-1~ESM3")
    assert not V.is_esm_version("1.0-1+deb12u1")
    assert not V.is_esm_version("1.0-1esmeralda")
    assert V.is_modular_evr("1:18.18.2-1.module+el9.3.0+1234+abcd")
    assert V.is_modular_evr("1.0-1.module_el8.7.0+3346+68867adb")
    assert not V.is_modular_evr("3.0.7-27.el9_4.1")


# ---------------------------------------------------------------- oracle: the real dpkg
_ALPH = "0123456789" * 3 + "abcXYZ" + ".+~-:" * 2


def _gen(rnd: random.Random) -> str:
    plain = _ALPH.replace(":", "").replace("-", "")
    up = rnd.choice("0123456789") + "".join(rnd.choice(plain) for _ in range(rnd.randint(0, 7)))
    rev = ""
    if rnd.random() < .6:
        rev = "".join(rnd.choice(_ALPH.replace(":", "")) for _ in range(rnd.randint(1, 6)))
        up = up.replace("-", "")
    ep = (str(rnd.randint(0, 3)) + ":") if rnd.random() < .25 else ""
    return ep + up + ("-" + rev if rev else "")


def _real_dpkg(a: str, b: str):
    for op, val in (("lt", -1), ("gt", 1)):
        rc = subprocess.run(["dpkg", "--compare-versions", a, op, b], capture_output=True).returncode
        if rc == 0:
            return val
        if rc not in (0, 1):
            return None                      # dpkg itself refuses the text
    return 0


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg is not installed")
def test_dpkg_oracle_3000_random_pairs_against_the_real_dpkg():
    rnd = random.Random(20261126)
    checked = bad = 0
    mismatches = []
    for _ in range(3000):
        a, b = _gen(rnd), _gen(rnd)
        try:
            mine = V.dpkg_cmp(a, b)
        except VersionError:
            continue                          # we refuse more than dpkg: allowed (UNKNOWN, never patched)
        real = _real_dpkg(a, b)
        if real is None:
            bad += 1                          # dpkg refuses what we accepted: NOT allowed
            mismatches.append(("dpkg refuses", a, b))
            continue
        checked += 1
        if mine != real:
            mismatches.append((a, b, mine, real))
    assert mismatches == []
    assert checked > 2000                     # the oracle really compared (probe: 2838)
    assert bad == 0


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg is not installed")
def test_every_dpkg_vector_agrees_with_the_real_dpkg():
    for a, b, e in DPKG:
        real = _real_dpkg(a, b)
        assert real in (None, e), (a, b, real, e)


# ---------------------------------------------------------------- properties (seeded, always run)
def _dpkg_samples(n=60, seed=7):
    rnd = random.Random(seed)
    out = []
    while len(out) < n:
        s = _gen(rnd)
        try:
            V.dpkg_cmp(s, s)
        except VersionError:
            continue
        out.append(s)
    return out


def _rpm_samples(n=60, seed=11):
    rnd = random.Random(seed)
    alph = "0123456789" * 3 + "abc" + "._+~^"
    out = []
    while len(out) < n:
        ver = rnd.choice("0123456789") + "".join(rnd.choice(alph) for _ in range(rnd.randint(0, 5)))
        rel = "".join(rnd.choice(alph) for _ in range(rnd.randint(1, 5)))
        ep = (str(rnd.randint(0, 3)) + ":") if rnd.random() < .3 else ""
        s = f"{ep}{ver}-{rel}"
        try:
            V.rpm_cmp(s, s)
        except VersionError:
            continue
        out.append(s)
    return out


@pytest.mark.parametrize("cmp,samples", [(V.dpkg_cmp, _dpkg_samples()), (V.rpm_cmp, _rpm_samples())])
def test_total_order_properties(cmp, samples):
    for a in samples:
        assert cmp(a, a) == 0
    for a, b in itertools.combinations(samples, 2):
        assert cmp(a, b) == -cmp(b, a)                                   # antisymmetry
    for a, b, c in itertools.islice(itertools.permutations(samples[:24], 3), 4000):
        if cmp(a, b) <= 0 and cmp(b, c) <= 0:
            assert cmp(a, c) <= 0                                        # transitivity
        if cmp(a, b) == 0 and cmp(b, c) == 0:
            assert cmp(a, c) == 0


def test_epoch_dominance_and_tilde_minimality():
    for s in _dpkg_samples(40, 3):
        if ":" in s:
            continue
        assert V.dpkg_cmp("1:" + s, "0:" + s + "999") == 1
        assert V.dpkg_cmp(s + "~", s) == -1                              # "~" sorts before the end
        assert V.dpkg_cmp(s + "~~", s + "~") == -1
    for s in _rpm_samples(40, 5):
        if ":" in s:
            continue
        assert V.rpm_cmp("1:" + s, "0:" + s) == 1
        assert V.rpm_cmp(s + "~x", s) == -1


def test_rpm_v_prefix_orders_older_never_patched():
    # rpm orders an alpha segment before a numeric one, so a "v" prefix can only look OLDER (the safe direction)
    assert V.rpm_cmp("v9.0-1", "1.0-1") == -1
    assert V.rpm_cmp("1.0-1", "v9.0-1") == 1


def test_rpm_numeric_compare_ignores_leading_zeros_and_is_not_lexical():
    assert V.rpmvercmp("10", "9") == 1
    assert V.rpmvercmp("007", "7") == 0
    assert V.rpmvercmp("1" * 40, "9" * 39) == 1                          # no int overflow, length first


def test_deep_digit_runs_do_not_crash_or_hang():
    big = "1" + "0" * 250
    assert V.dpkg_cmp(big + "1", big + "2") == -1
    assert V.rpm_cmp("1.0-" + "9" * 250, "1.0-" + "9" * 250 + "1") == -1


# ---------------------------------------------------------------- hypothesis (when installed)
def test_hypothesis_properties():
    hyp = pytest.importorskip("hypothesis")
    st = pytest.importorskip("hypothesis.strategies")
    ver = st.from_regex(r"\A(?:[0-3]:)?[0-9][A-Za-z0-9.+~]{0,8}(?:-[A-Za-z0-9.+~]{1,6})?\Z")

    @hyp.settings(max_examples=300, deadline=None, derandomize=True)
    @hyp.given(ver, ver, ver)
    def prop(a, b, c):
        assert V.dpkg_cmp(a, a) == 0
        assert V.dpkg_cmp(a, b) == -V.dpkg_cmp(b, a)
        if V.dpkg_cmp(a, b) <= 0 and V.dpkg_cmp(b, c) <= 0:
            assert V.dpkg_cmp(a, c) <= 0

    prop()

    rver = st.from_regex(r"\A(?:[0-3]:)?[0-9][A-Za-z0-9._+~^]{0,8}-[A-Za-z0-9._+~^]{1,6}\Z")

    @hyp.settings(max_examples=300, deadline=None, derandomize=True)
    @hyp.given(rver, rver, rver)
    def rprop(a, b, c):
        assert V.rpm_cmp(a, b) == -V.rpm_cmp(b, a)
        if V.rpm_cmp(a, b) <= 0 and V.rpm_cmp(b, c) <= 0:
            assert V.rpm_cmp(a, c) <= 0

    rprop()
