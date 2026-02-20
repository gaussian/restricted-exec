"""
Tests for HTTP SSRF (Server-Side Request Forgery) prevention
in SafeAPI's http_get() method.

Maps to SECURITY.md: A-30 (HTTP SSRF), A-31 (header injection).
"""

from __future__ import annotations

import pytest

from restricted_exec.safe_api import SafeAPI, ApiViolation


class TestHttpSSRF:
    """Test http_get() host allowlist and scheme enforcement."""

    def test_metadata_ip_blocked_by_allowlist(self):
        """Cloud metadata endpoint blocked when allowlist is set."""
        api = SafeAPI(
            workspace_root="/tmp/test",
            http_allow_hosts={"api.example.com"},
        )
        with pytest.raises(ApiViolation, match="Host not allowlisted"):
            api.http_get("https://169.254.169.254/latest/meta-data/")

    def test_localhost_blocked_by_allowlist(self):
        """localhost blocked when allowlist is set."""
        api = SafeAPI(
            workspace_root="/tmp/test",
            http_allow_hosts={"api.example.com"},
        )
        with pytest.raises(ApiViolation, match="Host not allowlisted"):
            api.http_get("https://localhost/admin")

    def test_internal_ip_blocked_by_allowlist(self):
        """Internal 10.x.x.x IP blocked when allowlist is set."""
        api = SafeAPI(
            workspace_root="/tmp/test",
            http_allow_hosts={"api.example.com"},
        )
        with pytest.raises(ApiViolation, match="Host not allowlisted"):
            api.http_get("https://10.0.0.1/internal")

    def test_ipv6_loopback_blocked_by_allowlist(self):
        """IPv6 loopback [::1] blocked when allowlist is set."""
        api = SafeAPI(
            workspace_root="/tmp/test",
            http_allow_hosts={"api.example.com"},
        )
        with pytest.raises(ApiViolation, match="Host not allowlisted"):
            api.http_get("https://[::1]/admin")

    def test_http_scheme_rejected(self):
        """Plain HTTP is rejected regardless of allowlist."""
        api = SafeAPI(
            workspace_root="/tmp/test",
            http_allow_hosts={"example.com"},
        )
        with pytest.raises(ApiViolation, match="Only https"):
            api.http_get("http://example.com")

    def test_uppercase_http_scheme_rejected(self):
        """HTTP:// (uppercase) should also be rejected."""
        api = SafeAPI(
            workspace_root="/tmp/test",
            http_allow_hosts={"example.com"},
        )
        with pytest.raises(ApiViolation, match="Only https"):
            api.http_get("HTTP://example.com")

    def test_no_allowlist_permits_any_https_host(self):
        """Without allowlist, any HTTPS host is allowed (scheme check only).

        We don't make a real request — just verify the host check
        doesn't fire. The request will fail on network.
        """
        api = SafeAPI(workspace_root="/tmp/test", http_allow_hosts=set())
        try:
            api.http_get("https://169.254.169.254/latest/meta-data/", timeout_s=1)
        except ApiViolation as e:
            assert "Host not allowlisted" not in str(e)
        except Exception:
            pass
