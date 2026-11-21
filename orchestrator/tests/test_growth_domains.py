"""Public-domain validation: what the unauthenticated endpoints will accept."""
from __future__ import annotations

import pytest
from app.growth.domains import DomainError, mask_host, registrable_of, validate_public_domain


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("example.com.", "example.com"),
        ("example.co.uk", "example.co.uk"),
        ("foo.herokuapp.com", "foo.herokuapp.com"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("BÜCHER.de", "xn--bcher-kva.de"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("例え.jp", "xn--r8jz45g.jp"),
        ("a-b.com", "a-b.com"),
        ("1password.com", "1password.com"),
        ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com"),
    ],
)
def test_accepts_registrable_public_domains(raw, expected):
    assert validate_public_domain(raw) == expected


@pytest.mark.parametrize(
    "raw,code",
    [
        # IP literals in every spelling
        ("1.2.3.4", "ip_literal"),
        ("127.0.0.1", "ip_literal"),
        ("[::1]", "ip_literal"),
        ("::1", "ip_literal"),
        ("2001:db8::1", "ip_literal"),
        ("2130706433", "ip_literal"),
        ("0x7f.1", "ip_literal"),
        ("0x7f000001", "ip_literal"),
        ("017700000001", "ip_literal"),
        ("127.1", "ip_literal"),
        ("1.2.3", "ip_literal"),
        ("192.168.1.1.", "ip_literal"),
        # internal / reserved names
        ("localhost", "internal_name"),
        ("intranet", "internal_name"),
        ("server.local", "internal_name"),
        ("db.internal", "internal_name"),
        ("printer.lan", "internal_name"),
        ("corp.home", "internal_name"),
        ("foo.test", "internal_name"),
        ("foo.invalid", "internal_name"),
        ("foo.example", "internal_name"),
        ("abc.onion", "internal_name"),
        ("1.0.0.127.in-addr.arpa", "internal_name"),
        ("router.home.arpa", "internal_name"),
        # public suffixes and sub-domains
        ("com", "internal_name"),
        ("co.uk", "public_suffix"),
        ("www.example.com", "not_registrable"),
        ("a.b.example.co.uk", "not_registrable"),
        # URLs and syntax
        ("https://example.com", "invalid_chars"),
        ("example.com/path", "invalid_chars"),
        ("example.com:8080", "invalid_chars"),
        ("user@example.com", "invalid_chars"),
        ("*.example.com", "invalid_chars"),
        ("exa mple.com", "invalid_chars"),
        ("example.com\n", None),  # stripped: valid
        ("exam\x00ple.com", "invalid_chars"),
        ("example..com", "invalid"),
        (".example.com", "invalid"),
        ("-example.com", "invalid_idn"),
        ("example-.com", "invalid_idn"),
        ("exa_mple.com", "invalid_idn"),
        ("example.c", "invalid"),
        ("example.123", "ip_literal"),
        ("", "empty"),
        ("   ", "empty"),
        # malformed IDN
        ("xn--.com", "invalid_idn"),
        ("xn--zz.com", "invalid_idn"),
        ("-.com", "invalid_idn"),
    ],
)
def test_rejects(raw, code):
    if code is None:
        assert validate_public_domain(raw) == "example.com"
        return
    with pytest.raises(DomainError) as e:
        validate_public_domain(raw)
    assert e.value.code == code, (raw, e.value.code)


def test_very_long_names_are_rejected_cheaply():
    with pytest.raises(DomainError) as e:
        validate_public_domain("a" * 5000 + ".com")
    assert e.value.code == "too_long"
    # 64-octet label
    with pytest.raises(DomainError):
        validate_public_domain("a" * 64 + ".com")
    # exactly 63 is fine
    assert validate_public_domain("a" * 63 + ".com") == "a" * 63 + ".com"
    # > 253 total (several valid labels)
    many = ".".join(["a" * 60] * 5) + ".com"
    with pytest.raises(DomainError) as e:
        validate_public_domain(many)
    assert e.value.code in {"too_long", "not_registrable"}


@pytest.mark.parametrize("bad", [None, 5, ["example.com"], {"d": "example.com"}, b"example.com"])
def test_non_strings_rejected(bad):
    with pytest.raises(DomainError):
        validate_public_domain(bad)


def test_registrable_of_and_mask():
    assert registrable_of("a.b.example.co.uk") == "example.co.uk"
    assert registrable_of("www.example.com") == "example.com"
    assert registrable_of("com") is None
    assert mask_host("admin.example.com", "example.com") == "a***.example.com"
    assert mask_host("example.com", "example.com") == "example.com"
    assert mask_host("evil.org", "example.com") == "***"
