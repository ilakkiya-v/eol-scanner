"""Scope enforcement: every request the scanner makes is checked against the
operator-maintained allowlist. Deny rules win. An empty allowlist blocks all.

Rule formats:
    app.lab.corp            exact host
    *.lab.corp              any subdomain (not the apex)
    10.20.0.0/16            CIDR (hostnames are resolved and every IP must match)
    10.20.30.40             single IP
    app.lab.corp:8443       host + port
"""
from __future__ import annotations

import fnmatch
import ipaddress
import socket
from functools import lru_cache
from typing import Iterable
from urllib.parse import urlsplit

from . import db


class OutOfScope(Exception):
    pass


@lru_cache(maxsize=1024)
def _resolve(host: str) -> tuple[str, ...]:
    try:
        return tuple(sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)}))
    except socket.gaierror:
        return ()


def _host_port(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise OutOfScope(f"unsupported scheme: {parts.scheme or '(none)'}")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise OutOfScope("URL has no host")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return host, port


def _match(rule: str, host: str, port: int) -> bool:
    rule = rule.strip().lower()
    if not rule or rule.startswith("#"):
        return False
    if "://" in rule:
        rule = urlsplit(rule).netloc or rule
    rule_port = None
    if rule.count(":") == 1 and "/" not in rule:
        rule, p = rule.split(":")
        rule_port = int(p) if p.isdigit() else None
    if rule_port is not None and rule_port != port:
        return False
    try:
        net = ipaddress.ip_network(rule, strict=False)
    except ValueError:
        net = None
    if net is not None:
        try:
            ips = (host,) if ipaddress.ip_address(host) else ()
        except ValueError:
            ips = _resolve(host)
        return bool(ips) and all(ipaddress.ip_address(ip) in net for ip in ips)
    if rule.startswith("*."):
        return fnmatch.fnmatch(host, rule) and host != rule[2:]
    return host == rule


def check(url: str, rules: dict | None = None) -> None:
    rules = rules or db.get_setting("scope")
    host, port = _host_port(url)
    if any(_match(r, host, port) for r in rules.get("deny", [])):
        raise OutOfScope(f"{host}:{port} matches a deny rule")
    allow: Iterable[str] = rules.get("allow", [])
    if not any(_match(r, host, port) for r in allow):
        raise OutOfScope(f"{host}:{port} is not in the authorized scope allowlist (Settings -> Scope)")


def in_scope(url: str, rules: dict | None = None) -> bool:
    try:
        check(url, rules)
        return True
    except OutOfScope:
        return False
