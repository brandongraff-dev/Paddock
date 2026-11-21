from __future__ import annotations

from app.normalize.tech_detect import detect


def test_detects_nginx_via_server_header():
    hits = detect(headers={"Server": "nginx/1.25.3"}, body=None)
    names = {h.name: h for h in hits}
    assert "nginx" in names
    assert names["nginx"].version == "1.25.3"


def test_detects_wordpress_body_generator():
    body = b'<html><head><meta name="generator" content="WordPress 6.4.1" /></head></html>'
    hits = detect(headers={}, body=body)
    assert any(h.name == "wordpress" and h.version == "6.4.1" for h in hits)


def test_detects_django_cookie():
    hits = detect(headers={"Set-Cookie": "sessionid=abc; Path=/"}, body=None)
    assert any(h.name == "django" for h in hits)


def test_no_false_positives_for_empty():
    assert detect(headers={}, body=None) == []
