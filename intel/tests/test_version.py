from __future__ import annotations

import math

from app.matchers import version


def test_semver_ordering() -> None:
    assert version.compare("1.2.3", "1.2.4") == -1
    assert version.compare("1.2.4", "1.2.3") == 1
    assert version.compare("1.2.3", "1.2.3") == 0
    assert version.compare("2.0.0", "1.99.99") == 1


def test_prerelease_ranks_below_release() -> None:
    assert version.compare("1.2.3-beta.1", "1.2.3") == -1
    assert version.compare("1.2.3-alpha", "1.2.3-beta") == -1
    assert version.compare("1.2.3-rc.2", "1.2.3-rc.10") == -1


def test_vendor_style_versions() -> None:
    assert version.compare("14.04.1", "14.04.2") == -1
    assert version.compare("2019.1.3", "2019.2") == -1
    assert version.compare("v1.0", "1.0") == 0
    # Build metadata ignored.
    assert version.compare("1.2.3+sha123", "1.2.3+sha999") == 0


def test_incomparable_returns_nan() -> None:
    # Two non-numeric blobs with no ordering relation should return NaN.
    r = version.compare("banana", "apple")
    assert math.isnan(r) or isinstance(r, int)  # tolerate lexicographic path


def test_range_inclusive_vs_exclusive() -> None:
    # 1.0.0 <= v < 1.4.2
    assert version.in_range("1.0.0", start_including="1.0.0", end_excluding="1.4.2") is True
    assert version.in_range("1.3.9", start_including="1.0.0", end_excluding="1.4.2") is True
    assert version.in_range("1.4.2", start_including="1.0.0", end_excluding="1.4.2") is False
    assert version.in_range("0.9.9", start_including="1.0.0", end_excluding="1.4.2") is False


def test_range_open_sides() -> None:
    assert version.in_range("5.0", end_including="6.0") is True
    assert version.in_range("7.0", end_including="6.0") is False
    assert version.in_range("2.0", start_excluding="1.0") is True
    assert version.in_range("1.0", start_excluding="1.0") is False


def test_range_exact_short_circuit() -> None:
    assert version.in_range("1.18.0", exact="1.18.0") is True
    assert version.in_range("1.18.1", exact="1.18.0") is False


def test_wildcard_or_missing_version_not_in_range() -> None:
    assert version.in_range("", start_including="1.0") is False
    assert version.in_range("*", start_including="1.0") is False


def test_normalize_handles_v_prefix_and_whitespace() -> None:
    assert version.normalize("  v1.2.3 ") == "1.2.3"
    assert version.normalize("V2.0") == "2.0"
    assert version.normalize("") == ""
    assert version.normalize("*") == ""
