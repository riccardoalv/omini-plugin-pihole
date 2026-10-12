import copy
import json
from functools import partial
from urllib.parse import unquote

import httpx
import pytest
from omini_sdk import Config

import omini_pihole.collect as collect_module
from omini_pihole.client import Client

PASSWORD = "app-password-123"


def error(status: int, key: str, message: str, hint: str | None = None) -> httpx.Response:
    return httpx.Response(
        status, json={"error": {"key": key, "message": message, "hint": hint}, "took": 0.001}
    )


class FakePihole:
    """Pi-hole v6 (FTL 6.2) answering its REST API (the shapes of its
    /api/docs), with state: the configuration, sessions, leases, lists."""

    def __init__(self):
        self.calls = []
        self.hook = None  # a test's own handler in front of this one
        self.sessions = set()
        self.app_sudo = True
        self.next_sid = 0
        self.config = {
            "dns": {
                "upstreams": ["9.9.9.9", "149.112.112.112"],
                "hosts": [
                    "192.168.1.20 nas.lan",
                    "192.168.1.30 printer.lan scanner.lan",
                    "fd00::20 v6.lan",
                ],
                "domain": {"name": "lan", "local": True},
                "cnameRecords": ["media.lan,nas.lan"],
            },
            "dhcp": {
                "active": True,
                "start": "192.168.1.100",
                "end": "192.168.1.199",
                "router": "192.168.1.1",
                "netmask": "255.255.255.0",
                "leaseTime": "24h",
                "hosts": [
                    "aa:bb:cc:dd:ee:20,192.168.1.20,nas",
                    "AA-BB-CC-DD-EE-21,192.168.1.21,camera,infinite",
                    "id:*,192.168.1.99",
                ],
            },
            "webserver": {
                "port": "80o,443os",
                "api": {
                    "pwhash": "$BALLOON-SHA256$v=1$s=1024,t=32$abc$def",
                    "app_pwhash": "$BALLOON-SHA256$v=1$s=1024,t=32$ghi$jkl",
                    "totp_secret": "JBSWY3DPEHPK3PXP",
                    "app_sudo": True,
                    "max_sessions": 16,
                },
            },
        }
        self.leases = [
            {
                "expires": 1791374400,
                "name": "laptop",
                "hwaddr": "aa:bb:cc:dd:ee:01",
                "ip": "192.168.1.101",
                "clientid": "01:aa:bb:cc:dd:ee:01",
            },
            {
                "expires": 0,
                "name": "*",
                "hwaddr": "aa:bb:cc:dd:ee:02",
                "ip": "192.168.1.102",
                "clientid": "*",
            },
        ]
        self.version = {
            "core": {"local": {"branch": "master", "version": "v6.1.2", "hash": "abc"}},
            "web": {"local": {"branch": "master", "version": "v6.2.1", "hash": "def"}},
            "ftl": {"local": {"branch": "master", "version": "v6.2.3", "hash": "ghi"}},
            "docker": {"local": None},
        }
        self.interfaces = [
            {"name": "lo", "address": "00:00:00:00:00:00", "addresses": [{"address": "127.0.0.1"}]},
            {
                "name": "eth0",
                "address": "dc:a6:32:01:02:03",
                "addresses": [
                    {"family": "inet", "address": "192.168.1.53", "prefixlen": 24},
                    {"family": "inet6", "address": "fe80::dea6:32ff:fe01:203", "prefixlen": 64},
                ],
            },
        ]
        self.lists = [
            {
                "address": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                "type": "block",
                "comment": "Migrated from /etc/pihole/adlists.list",
                "groups": [0],
                "enabled": True,
                "id": 1,
                "date_added": 1700000000,
                "date_modified": 1700000000,
                "date_updated": 1791370000,
                "number": 81000,
                "invalid_domains": 0,
                "abp_entries": 0,
                "status": 2,
            }
        ]
        self.groups = [
            {
                "name": "Default",
                "comment": "The default group",
                "enabled": True,
                "id": 0,
                "date_added": 1700000000,
                "date_modified": 1700000000,
            }
        ]
        self.domains = [
            {
                "domain": "example.org",
                "unicode": "example.org",
                "type": "allow",
                "kind": "exact",
                "comment": None,
                "groups": [0],
                "enabled": True,
                "id": 1,
                "date_added": 1700000000,
                "date_modified": 1700000000,
            }
        ]
        self.clients = [
            {
                "client": "192.168.1.50",
                "name": "tablet.lan",
                "comment": "Kids",
                "groups": [0],
                "id": 1,
                "date_added": 1700000000,
                "date_modified": 1700000000,
            }
        ]

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.calls.append((method, unquote(request.url.raw_path.decode())))
        if path == "/api/auth" and method == "POST":
            body = json.loads(request.content or b"{}")
            if body.get("password") != PASSWORD:
                return httpx.Response(
                    401,
                    json={
                        "session": {
                            "valid": False,
                            "totp": False,
                            "sid": None,
                            "validity": -1,
                            "message": "password incorrect",
                        },
                        "took": 0.01,
                    },
                )
            self.next_sid += 1
            sid = f"sid-{self.next_sid}"
            self.sessions.add(sid)
            return httpx.Response(
                200,
                json={
                    "session": {
                        "valid": True,
                        "totp": False,
                        "sid": sid,
                        "csrf": "csrf",
                        "validity": 1800,
                        "message": "app-password correct",
                    },
                    "took": 0.01,
                },
            )
        sid = request.headers.get("x-ftl-sid")
        if sid not in self.sessions:
            return error(401, "unauthorized", "Unauthorized")
        if path == "/api/auth" and method == "DELETE":
            self.sessions.discard(sid)
            return httpx.Response(204)
        if method == "GET":
            routes = {
                "/api/config": lambda: {"config": self.config},
                "/api/config/dns/hosts": lambda: {"config": {"dns": {"hosts": self.hosts}}},
                "/api/info/version": lambda: {"version": self.version},
                "/api/info/host": lambda: {
                    "host": {"uname": {"nodename": "pihole", "machine": "aarch64"}, "model": None}
                },
                "/api/network/interfaces": lambda: {"interfaces": self.interfaces},
                "/api/dhcp/leases": lambda: {"leases": self.leases},
                "/api/lists": lambda: {"lists": self.lists},
                "/api/groups": lambda: {"groups": self.groups},
                "/api/domains": lambda: {"domains": self.domains},
                "/api/clients": lambda: {"clients": self.clients},
            }
            if path not in routes:
                return error(404, "not_found", "Not found")
            return httpx.Response(200, json={**copy.deepcopy(routes[path]()), "took": 0.001})
        prefix = "/api/config/dns/hosts/"
        if path.startswith(prefix) and method in ("PUT", "DELETE"):
            if not self.app_sudo:
                return error(403, "forbidden", "Unable to change configuration (read-only)")
            line = unquote(request.url.raw_path.decode()[len(prefix) :])
            if method == "PUT":
                if line in self.hosts:
                    return error(400, "bad_request", "Item already present", line)
                self.hosts.append(line)
                return httpx.Response(201, json={"took": 0.01})
            if line not in self.hosts:
                return error(404, "not_found", "Item not found")
            self.hosts.remove(line)
            return httpx.Response(204)
        return error(404, "not_found", "Not found")

    @property
    def hosts(self):
        return self.config["dns"]["hosts"]

    def writes(self):
        return [c for c in self.calls if c[0] != "GET" and not c[1].startswith("/api/auth")]


@pytest.fixture
def pihole(monkeypatch):
    fake = FakePihole()
    monkeypatch.setattr(
        collect_module,
        "Client",
        partial(Client, transport=httpx.MockTransport(lambda r: (fake.hook or fake.handler)(r))),
    )
    return fake


@pytest.fixture
def cfg():
    return Config({"url": "http://192.168.1.53/admin/", "password": PASSWORD})
