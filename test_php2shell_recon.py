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
# get_subdomains (crt.sh -> Cert Spotter fallback, mocked session)
# ---------------------------------------------------------------------

def test_get_subdomains_uses_crtsh_when_available(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)

    session = MagicMock()
    resp = MagicMock(status_code=200, headers={})
    resp.json.return_value = [{"name_value": "sub1.example.com\nsub2.example.com"}]
    session.request.side_effect = [resp]

    names, source, failed = m.get_subdomains("example.com", session, 5)

    assert source == "crt.sh"
    assert failed is False
    assert "sub1.example.com" in names
    assert "example.com" in names  # apex always included
    assert session.request.call_count == 1  # Cert Spotter never touched


def test_get_subdomains_falls_back_to_certspotter(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)

    session = MagicMock()
    resp_crtsh_fail = MagicMock(status_code=503, headers={})
    resp_certspotter_ok = MagicMock(status_code=200, headers={})
    resp_certspotter_ok.json.return_value = [
        {"dns_names": ["sub3.example.com", "example.com"]}
    ]
    # crt.sh exhausts its retries (all 503), then Cert Spotter succeeds
    session.request.side_effect = (
        [resp_crtsh_fail] * m.MAX_RETRIES + [resp_certspotter_ok]
    )

    names, source, failed = m.get_subdomains("example.com", session, 5)

    assert source == "certspotter"
    assert failed is False
    assert "sub3.example.com" in names


def test_get_subdomains_both_sources_fail(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)

    session = MagicMock()
    resp_fail = MagicMock(status_code=503, headers={})
    session.request.side_effect = [resp_fail] * (m.MAX_RETRIES * 2)

    names, source, failed = m.get_subdomains("example.com", session, 5)

    assert source == "none"
    assert failed is True
    assert names == {"example.com"}


def test_certspotter_handles_error_object_response(monkeypatch):
    """Cert Spotter returns a JSON object (not a list) with an 'error' key
    on failure (e.g. rate limited) -- this must be treated as a failure,
    not parsed as if it were issuance data."""
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)

    session = MagicMock()
    resp = MagicMock(status_code=200, headers={})
    resp.json.return_value = {"code": "rate_limited", "message": "slow down"}
    session.request.side_effect = [resp]

    result = m._query_certspotter("example.com", session, 5)

    assert result is None


# ---------------------------------------------------------------------
# extract_php_version_from_header
# ---------------------------------------------------------------------

@pytest.mark.parametrize("header,expected", [
    ("PHP/8.2.35", "8.2.35"),
    ("PHP/8.2.35-1+ubuntu24.04.1", "8.2.35"),
    ("php/8.4.27", "8.4.27"),  # case-insensitive
    ("PHP", None),             # version stripped
    ("Express", None),         # unrelated framework
    (None, None),
    ("", None),
])
def test_extract_php_version_from_header(header, expected):
    assert m.extract_php_version_from_header(header) == expected


# ---------------------------------------------------------------------
# reconciliation_note
# ---------------------------------------------------------------------

def test_reconciliation_vulnerable_to_patched_is_good_news():
    """The exact real-world case this feature exists for: InternetDB says
    vulnerable (often stale/CDN-fronted data), live header check reveals
    the host is actually patched."""
    note = m.reconciliation_note(m.STATUS_VULNERABLE_UNPATCHED, m.STATUS_PATCHED, "8.2.35")
    assert note is not None
    text, color = note
    assert color == m.C.GREEN
    assert "PATCHED" in text
    assert "8.2.35" in text


def test_reconciliation_vulnerable_confirmed_still_vulnerable():
    note = m.reconciliation_note(m.STATUS_VULNERABLE_UNPATCHED, m.STATUS_VULNERABLE_UNPATCHED, "8.2.9")
    assert note is not None
    text, color = note
    assert color == m.C.RED
    assert "CONFIRMS" in text


def test_reconciliation_eol_confirmed_still_vulnerable():
    note = m.reconciliation_note(m.STATUS_VULNERABLE_EOL, m.STATUS_VULNERABLE_EOL, "8.1.5")
    assert note is not None
    assert note[1] == m.C.RED


def test_reconciliation_patched_confirmed_patched():
    note = m.reconciliation_note(m.STATUS_PATCHED, m.STATUS_PATCHED, "8.4.27")
    assert note is not None
    assert note[1] == m.C.GREEN


def test_reconciliation_surprise_vulnerability_found_live():
    """Edge case: passive data said patched (or wasn't flagged), but the
    live check reveals it's actually vulnerable. Should be treated as a
    real finding, colored as a warning, not silently dropped."""
    note = m.reconciliation_note(m.STATUS_PATCHED, m.STATUS_VULNERABLE_UNPATCHED, "8.2.9")
    assert note is not None
    assert note[1] == m.C.RED
    assert "VULNERABLE" in note[0]


def test_reconciliation_no_live_version_recoverable():
    """If --verify-headers got a response but no PHP version was in it
    (stripped X-Powered-By, or a non-PHP framework), there should still be
    an explanatory note rather than silence."""
    note = m.reconciliation_note(m.STATUS_VULNERABLE_UNPATCHED, None, None)
    assert note is not None
    assert "no PHP version visible" in note[0]


def test_reconciliation_no_note_when_nothing_to_say():
    """If live_status is simply absent and there's genuinely nothing to
    report (shouldn't normally occur given the None/None case above is
    handled, but confirms the function doesn't crash on falsy live_status
    with a non-None live_version, an inconsistent-but-possible state)."""
    result = m.reconciliation_note(m.STATUS_VULNERABLE_UNPATCHED, None, "8.2.9")
    # live_status falsy but live_version present -- not the "nothing
    # recoverable" case, so this should fall through to no note.
    assert result is None


# ---------------------------------------------------------------------
# effective_status
# ---------------------------------------------------------------------

def test_effective_status_prefers_live_when_present():
    r = m.HostResult(
        vendor_domain="v.com", subdomain="v.com",
        status=m.STATUS_VULNERABLE_UNPATCHED,
        live_status=m.STATUS_PATCHED,
    )
    assert m.effective_status(r) == m.STATUS_PATCHED


def test_effective_status_falls_back_to_passive_when_no_live_data():
    r = m.HostResult(
        vendor_domain="v.com", subdomain="v.com",
        status=m.STATUS_VULNERABLE_UNPATCHED,
        live_status=None,
    )
    assert m.effective_status(r) == m.STATUS_VULNERABLE_UNPATCHED


def test_effective_status_confirmed_vulnerable_stays_vulnerable():
    r = m.HostResult(
        vendor_domain="v.com", subdomain="v.com",
        status=m.STATUS_VULNERABLE_EOL,
        live_status=m.STATUS_VULNERABLE_EOL,
    )
    assert m.effective_status(r) == m.STATUS_VULNERABLE_EOL


def test_effective_status_feeds_summary_counts_correctly():
    """Regression test for the exact bug reported: a host corrected from
    VULNERABLE_UNPATCHED to PATCHED by --verify-headers must not be
    counted toward the vulnerable total anymore."""
    results = [
        m.HostResult(
            vendor_domain="v.com", subdomain="corrected.v.com",
            cpes=["cpe:/a:php:php:8.2.9"],
            status=m.STATUS_VULNERABLE_UNPATCHED,
            live_status=m.STATUS_PATCHED,
        ),
        m.HostResult(
            vendor_domain="v.com", subdomain="still-bad.v.com",
            cpes=["cpe:/a:php:php:8.1.5"],
            status=m.STATUS_VULNERABLE_EOL,
        ),
    ]
    unpatched_count = sum(1 for r in results if m.effective_status(r) == m.STATUS_VULNERABLE_UNPATCHED)
    eol_count = sum(1 for r in results if m.effective_status(r) == m.STATUS_VULNERABLE_EOL)

    assert unpatched_count == 0  # the corrected host must NOT be counted here anymore
    assert eol_count == 1        # the genuinely-still-vulnerable host is still counted


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
