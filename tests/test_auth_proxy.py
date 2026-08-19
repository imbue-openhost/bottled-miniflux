"""Unit tests for the auth_proxy helper functions.

Setup and invocation are documented in the README's "Development" section.

Scope: the pure helpers that matter for security — header stripping (the
defense that prevents a client from injecting the proxy-auth header) and port
parsing. The HTTP handler's socket I/O is exercised at deploy time via the
smoke-test commands in the README.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import auth_proxy  # noqa: E402  (sys.path manipulation required)


# --------------------------------------------------------------- _strip_headers


def test_strip_headers_removes_named_case_insensitively():
    headers = [
        ("X-OpenHost-Is-Owner", "true"),
        ("X-Openhost-User", "admin"),
        ("Accept", "text/html"),
    ]
    drop = {auth_proxy.OWNER_HEADER_NAME.lower(), auth_proxy.AUTH_HEADER_NAME.lower()}

    result = auth_proxy._strip_headers(headers, drop)

    assert result == [("Accept", "text/html")]


def test_strip_headers_is_case_insensitive_on_the_header_name():
    # Header names arrive in whatever case the client sent; stripping must not
    # depend on that case or an injected `x-openhost-user` would slip through.
    headers = [("x-openhost-user", "admin"), ("Host", "example")]
    drop = {auth_proxy.AUTH_HEADER_NAME.lower()}

    result = auth_proxy._strip_headers(headers, drop)

    assert result == [("Host", "example")]


def test_strip_headers_preserves_order_and_untouched_headers():
    headers = [("A", "1"), ("B", "2"), ("C", "3")]

    result = auth_proxy._strip_headers(headers, {"b"})

    assert result == [("A", "1"), ("C", "3")]


def test_strip_headers_preserves_duplicate_header_names():
    # e.g. chained X-Forwarded-For entries must not be collapsed.
    headers = [("X-Forwarded-For", "1.1.1.1"), ("X-Forwarded-For", "2.2.2.2")]

    result = auth_proxy._strip_headers(headers, {"connection"})

    assert result == headers


def test_strip_headers_empty_drop_returns_everything():
    headers = [("A", "1"), ("B", "2")]

    assert auth_proxy._strip_headers(headers, set()) == headers


# --------------------------------------------------------------- _port_from_env


def test_port_from_env_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv("SOME_PORT", raising=False)

    assert auth_proxy._port_from_env("SOME_PORT", 8080) == 8080


def test_port_from_env_returns_default_when_blank(monkeypatch):
    monkeypatch.setenv("SOME_PORT", "   ")

    assert auth_proxy._port_from_env("SOME_PORT", 8081) == 8081


def test_port_from_env_parses_and_trims_valid_value(monkeypatch):
    monkeypatch.setenv("SOME_PORT", "  9090  ")

    assert auth_proxy._port_from_env("SOME_PORT", 8080) == 9090


def test_port_from_env_rejects_non_integer(monkeypatch):
    monkeypatch.setenv("SOME_PORT", "not-a-number")

    with pytest.raises(ValueError):
        auth_proxy._port_from_env("SOME_PORT", 8080)


@pytest.mark.parametrize("value", ["0", "65536", "-1", "99999"])
def test_port_from_env_rejects_out_of_range(monkeypatch, value):
    monkeypatch.setenv("SOME_PORT", value)

    with pytest.raises(ValueError):
        auth_proxy._port_from_env("SOME_PORT", 8080)
