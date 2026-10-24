"""
Tests for php2shell-recon.

Run with:
    pip install -r requirements.txt -r requirements-dev.txt
    pytest

These tests cover pure logic only (version classification, CPE parsing,
private-IP detection, retry/backoff behavior with a mocked session) --
no real network calls are made.
"""

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import php2shell_recon as m


# ---------------------------------------------------------------------
# classify_php2shell
# ---------------------------------------------------------------------

@pytest.mark.parametrize("version,expected", [
    ("8.2.9", m.STATUS_VULNERABLE_UNPATCHED),
    ("8.2.34", m.STATUS_VULNERABLE_UNPATCHED),
    ("8.2.35", m.STATUS_PATCHED),
    ("8.2.36", m.STATUS_PATCHED),
    ("8.3.35", m.STATUS_VULNERABLE_UNPATCHED),
    ("8.3.36", m.STATUS_PATCHED),
    ("8.4.26", m.STATUS_VULNERABLE_UNPATCHED),
    ("8.4.27", m.STATUS_PATCHED),
    ("8.5.11", m.STATUS_VULNERABLE_UNPATCHED),
    ("8.5.12", m.STATUS_PATCHED),
    ("8.1.99", m.STATUS_VULNERABLE_EOL),
    ("8.0.0", m.STATUS_VULNERABLE_EOL),
    ("7.4.33", m.STATUS_VULNERABLE_EOL),
    ("5.6.40", m.STATUS_VULNERABLE_EOL),
    ("9.0.0", m.STATUS_UNKNOWN_BRANCH),
    ("9.9.9", m.STATUS_UNKNOWN_BRANCH),
    (None, m.STATUS_NO_VERSION),
    ("", m.STATUS_NO_VERSION),
    ("not-a-version", m.STATUS_NO_VERSION),
    ("8.x.y", m.STATUS_NO_VERSION),
])
def test_classify_php2shell(version, expected):
    assert m.classify_php2shell(version) == expected


# ---------------------------------------------------------------------
# extract_php_version
# ---------------------------------------------------------------------

def test_extract_php_version_finds_php_cpe():
    cpes = [
        "cpe:/o:unix:unix:-",
        "cpe:/a:apache:http_server:2.4.57",
        "cpe:/a:php:php:8.2.9",
        "cpe:/a:openssl:openssl:1.1.1v",
    ]
    assert m.extract_php_version(cpes) == "8.2.9"


def test_extract_php_version_no_php_cpe():
    cpes = ["cpe:/a:apache:http_server:2.4.57"]
    assert m.extract_php_version(cpes) is None


def test_extract_php_version_empty_list():
    assert m.extract_php_version([]) is None


def test_extract_php_version_first_match_wins():
    cpes = ["cpe:/a:php:php:8.2.9", "cpe:/a:php:php:8.4.27"]
    assert m.extract_php_version(cpes) == "8.2.9"


# ---------------------------------------------------------------------
# is_private_ip
# ---------------------------------------------------------------------

@pytest.mark.parametrize("ip,expected", [
    ("10.0.0.5", True),
    ("172.16.0.1", True),
    ("172.31.255.255", True),
    ("172.32.0.1", False),  # just outside the 172.16/12 private range
    ("192.168.1.1", True),
    ("127.0.0.1", True),
    ("169.254.1.1", True),  # link-local
    ("8.8.8.8", False),
    ("1.1.1.1", False),
    ("not-an-ip", False),
    ("", False),
])
def test_is_private_ip(ip, expected):
    assert m.is_private_ip(ip) == expected


# ---------------------------------------------------------------------
# HostResult.to_row
# ---------------------------------------------------------------------

def test_host_result_to_row_shape():
    r = m.HostResult(
        vendor_domain="vendor.com",
        subdomain="sub.vendor.com",
        ip="1.2.3.4",
        open_ports=[80, 443],
        cpes=["cpe:/a:php:php:8.2.9"],
        other_vulns=["CVE-2026-1234"],
        php_version="8.2.9",
        status=m.STATUS_VULNERABLE_UNPATCHED,
        likely_cdn=True,
    )
    row = r.to_row()
    assert row["vendor_domain"] == "vendor.com"
    assert row["open_ports"] == "80;443"
    assert row["cpes"] == "cpe:/a:php:php:8.2.9"
    assert row["php2shell_status"] == m.STATUS_VULNERABLE_UNPATCHED
    assert row["likely_cdn"] == "yes"


def test_host_result_to_row_defaults_are_empty_not_none():
    r = m.HostResult(vendor_domain="v.com", subdomain="v.com")
    row = r.to_row()
    assert row["ip"] == ""
    assert row["php_version"] == ""
    assert row["likely_cdn"] == ""


# ---------------------------------------------------------------------
# _request_with_retry (mocked session, no real network)
# ---------------------------------------------------------------------

def test_retry_succeeds_after_429(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)  # don't actually wait in tests

    session = MagicMock()
    resp_429 = MagicMock(status_code=429, headers={})
    resp_ok = MagicMock(status_code=200, headers={})
    session.request.side_effect = [resp_429, resp_429, resp_ok]

    result = m._request_with_retry(session, "GET", "http://fake", 5)

    assert result is not None
    assert result.status_code == 200
    assert session.request.call_count == 3


def test_retry_gives_up_after_max_attempts(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)

    session = MagicMock()
    resp_429 = MagicMock(status_code=429, headers={})
    session.request.side_effect = [resp_429] * m.MAX_RETRIES

    result = m._request_with_retry(session, "GET", "http://fake", 5)

    assert result is None
    assert session.request.call_count == m.MAX_RETRIES


def test_retry_returns_immediately_on_200():
    session = MagicMock()
    resp_ok = MagicMock(status_code=200, headers={})
    session.request.side_effect = [resp_ok]

    result = m._request_with_retry(session, "GET", "http://fake", 5)

    assert result is resp_ok
    assert session.request.call_count == 1


def test_retry_does_not_retry_on_404():
    """A 404 (or any non-429/5xx error) should not be retried -- it's not transient."""
    session = MagicMock()
    resp_404 = MagicMock(status_code=404, headers={})
    session.request.side_effect = [resp_404]

    result = m._request_with_retry(session, "GET", "http://fake", 5)

    assert result is resp_404
    assert session.request.call_count == 1


# ---------------------------------------------------------------------
# CDN tag detection (logic as used in run_recon's processing loop)
# ---------------------------------------------------------------------

@pytest.mark.parametrize("tags,expected", [
    (["cdn"], True),
    (["cloud"], True),
    (["cdn", "cloud"], True),
    (["vpn"], False),
    ([], False),
    (None, False),
    (["CDN"], True),  # case-insensitive
])
def test_cdn_tag_detection(tags, expected):
    tag_set = {t.lower() for t in (tags or [])}
    likely_cdn = bool(tag_set & m.CDN_TAGS)
    assert likely_cdn == expected
