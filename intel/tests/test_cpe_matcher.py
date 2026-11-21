from __future__ import annotations

from app.matchers import cpe


def _cve_entry(**overrides):
    base = {
        "vendor": "nginx",
        "product": "nginx",
        "version": "*",
        "vulnerable": True,
        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
    }
    base.update(overrides)
    return base


def test_exact_raw_cpe_match_is_100() -> None:
    cve_affected = [_cve_entry(version="1.18.0",
                               criteria="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")]
    asset_meta = {"cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"}
    assert cpe.best_match(cve_affected, asset_meta) == 100


def test_vendor_product_version_in_range_is_85() -> None:
    cve_affected = [_cve_entry(
        versionStartIncluding="1.0.0",
        versionEndExcluding="1.4.2",
        vendor="example", product="example-lib",
    )]
    meta = {"vendor": "example", "product": "example-lib", "version": "1.3.9"}
    assert cpe.best_match(cve_affected, meta) == 85


def test_vendor_product_version_out_of_range_is_zero() -> None:
    cve_affected = [_cve_entry(
        versionStartIncluding="1.0.0",
        versionEndExcluding="1.4.2",
        vendor="example", product="example-lib",
    )]
    meta = {"vendor": "example", "product": "example-lib", "version": "1.4.2"}
    assert cpe.best_match(cve_affected, meta) == 0


def test_vendor_product_only_is_60() -> None:
    cve_affected = [_cve_entry(vendor="nginx", product="nginx", version="*")]
    meta = {"vendor": "nginx", "product": "nginx"}
    # no version in metadata -> falls through to vendor+product-only tier
    assert cpe.best_match(cve_affected, meta) == 60


def test_product_only_heuristic_is_40() -> None:
    cve_affected = [_cve_entry(vendor="nginx", product="nginx", version="*")]
    # No vendor on the asset, only product name
    meta = {"product": "nginx", "version": "1.18.0"}
    assert cpe.best_match(cve_affected, meta) == 40


def test_wildcard_cve_version_with_versioned_asset_is_85() -> None:
    cve_affected = [_cve_entry(vendor="nginx", product="nginx", version="*")]
    meta = {"vendor": "nginx", "product": "nginx", "version": "1.18.0"}
    assert cpe.best_match(cve_affected, meta) == 85


def test_non_vulnerable_entry_is_skipped() -> None:
    cve_affected = [_cve_entry(vulnerable=False)]
    meta = {"vendor": "nginx", "product": "nginx", "version": "1.18.0"}
    assert cpe.best_match(cve_affected, meta) == 0


def test_mismatched_product_is_zero() -> None:
    cve_affected = [_cve_entry(vendor="nginx", product="nginx", version="*")]
    meta = {"vendor": "apache", "product": "httpd", "version": "2.4.0"}
    assert cpe.best_match(cve_affected, meta) == 0


def test_best_of_multiple_entries_wins() -> None:
    cve_affected = [
        _cve_entry(vendor="nginx", product="nginx", version="*"),
        _cve_entry(
            vendor="nginx", product="nginx",
            versionStartIncluding="1.0.0", versionEndExcluding="2.0.0",
        ),
    ]
    meta = {"vendor": "nginx", "product": "nginx", "version": "1.18.0"}
    # First entry would match at 85 (wildcard CVE version with versioned asset),
    # second also at 85. Make sure we don't degrade to 60.
    assert cpe.best_match(cve_affected, meta) == 85


def test_parse_cpe_rejects_junk() -> None:
    assert cpe.parse_cpe("") is None
    assert cpe.parse_cpe("not-a-cpe") is None
    assert cpe.parse_cpe("cpe:2.3:a:nginx") is None


def test_parse_cpe_roundtrip() -> None:
    parsed = cpe.parse_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
    assert parsed is not None
    assert parsed["vendor"] == "nginx"
    assert parsed["product"] == "nginx"
    assert parsed["version"] == "1.18.0"
