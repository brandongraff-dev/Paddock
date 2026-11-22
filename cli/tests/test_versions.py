import pytest

from paddock_cli import versions as V


@pytest.mark.parametrize("a,b,expected", [
    ("1.2.3", "1.2.4", -1), ("1.10.0", "1.9.9", 1), ("v1.7.0", "v1.7.0", 0),
    ("2.0", "2.0.0", 0), ("2.15.0", "2.0-beta9", 1), ("1.0.0rc1", "1.0.0", -1),
    ("1.0.0-beta.2", "1.0.0-beta.10", -1), ("1.0.0", "1.0.0.post1", -1),
    ("4.17.21", "4.17.20", 1), ("1.0.0-SNAPSHOT", "1.0.0", -1),
])
def test_compare(a, b, expected):
    assert V.compare(a, b) == expected
    assert V.compare(b, a) == -expected


def test_sort_and_newest():
    assert V.newest(["1.2.0", "1.10.0", "1.9.0"]) == "1.10.0"
    assert sorted(["2.0.0", "1.0.0rc1", "1.0.0"], key=V.sort_key) == ["1.0.0rc1", "1.0.0", "2.0.0"]


def test_major():
    assert V.major("v1.7.0") == 1 and V.major("4.17.21") == 4 and V.major("junk") is None


@pytest.mark.parametrize("spec,ver,expected", [
    ("^4.17.19", "4.17.21", True), ("^4.17.19", "5.0.0", False), ("~1.2.3", "1.2.9", True),
    ("~1.2.3", "1.3.0", False), ("1.2.3", "1.2.3", True), ("1.2.3", "1.2.4", False),
    (">=2.0.0", "3.1.0", True), ("*", "9.9.9", True), ("^0.2.3", "0.2.9", True),
    ("^0.2.3", "0.3.0", False), ("1.x", "1.9.0", True), ("1 || 2", "2.0.0", None),
])
def test_satisfies(spec, ver, expected):
    assert V.satisfies(spec, ver) is expected
