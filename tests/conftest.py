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
        # GET /api/network/interfaces (FTL 6.x, netlink): the counters come
        # rounded as {value, unit}, the speed in Mbit/s (-1 when unknown).
        self.interfaces = [
            {
                "name": "lo",
                "index": 1,
                "type": "loopback",
                "flags": ["up", "loopback", "running", "lower_up"],
                "state": "unknown",
                "carrier": True,
                "speed": -1,
                "address": "00:00:00:00:00:00",
                "stats": {"rx_bytes": {"value": 1.2, "unit": "M"}, "rx_packets": 300},
                "addresses": [
                    {"family": "inet", "address": "127.0.0.1", "prefixlen": 8, "scope": "host"},
                    {"family": "inet6", "address": "::1", "prefixlen": 128, "scope": "host"},
                ],
            },
            {
                "name": "eth0",
                "index": 2,
                "type": "ether",
                "flags": ["up", "broadcast", "running", "multicast", "lower_up"],
                "state": "up",
                "carrier": True,
                "speed": 1000,
                "address": "dc:a6:32:01:02:03",
                "perm_address": "dc:a6:32:01:02:03",
                "broadcast": "ff:ff:ff:ff:ff:ff",
                "stats": {
                    "rx_bytes": {"value": 2.97, "unit": "G"},
                    "tx_bytes": {"value": 685.3, "unit": "M"},
                    "rx_packets": 4512345,
                    "tx_packets": 1234567,
                    "rx_errors": 0,
                    "tx_errors": 0,
                },
                "addresses": [
                    {
                        "family": "inet",
                        "address": "192.168.1.53",
                        "prefixlen": 24,
                        "scope": "global",
                        "broadcast": "192.168.1.255",
                        "label": "eth0",
                    },
                    {
                        "family": "inet6",
                        "address": "2001:db8:1::53",
                        "prefixlen": 64,
                        "scope": "global",
                    },
                    {"family": "inet6", "address": "fd00::53", "prefixlen": 64, "scope": "global"},
                    {
                        "family": "inet6",
                        "address": "fe80::dea6:32ff:fe01:203",
                        "prefixlen": 64,
                        "scope": "link",
                    },
                ],
            },
            {
                "name": "wlan0",
                "index": 3,
                "type": "ether",
                "flags": ["broadcast", "multicast"],
                "state": "down",
                "carrier": False,
                "speed": -1,
                "address": "dc:a6:32:01:02:04",
                "stats": {"rx_bytes": {"value": 0, "unit": ""}},
                "addresses": [],
            },
        ]
        # GET /api/info/system: memory in kB (/proc/meminfo).
        self.system = {
            "uptime": 1234567,
            "memory": {
                "ram": {
                    "total": 3882924,
                    "free": 2187380,
                    "used": 707472,
                    "available": 2949408,
                    "%used": 18.22,
                },
                "swap": {"total": 102396, "free": 76797, "used": 25599, "%used": 25.0},
            },
            "procs": 171,
            "cpu": {
                "nprocs": 4,
                "%cpu": 1.6,
                "load": {"raw": [0.05, 0.09, 0.08], "percent": [1.25, 2.25, 2.0]},
            },
            "ftl": {"%mem": 0.68, "%cpu": 0.2},
        }
        # GET /api/info/sensors: hwmon chips, in webserver.api.temp.unit.
        self.sensors = {
            "list": [
                {
                    "name": "cpu_thermal",
                    "path": "devices/virtual/thermal/thermal_zone0/hwmon0",
                    "source": "/sys/class/hwmon/hwmon0",
                    "temps": [
                        {"name": None, "value": 48.3, "max": None, "crit": None, "sensor": "temp1"}
                    ],
                },
                {
                    "name": "nvme",
                    "path": "devices/pci0000:00/nvme/nvme0/hwmon1",
                    "source": "/sys/class/hwmon/hwmon1",
                    "temps": [
                        {
                            "name": "Composite",
                            "value": 39.85,
                            "max": 81.85,
                            "crit": 84.85,
                            "sensor": "temp1",
                        },
                        {
                            "name": "Sensor 1",
                            "value": 41.85,
                            "max": 65261.85,
                            "crit": None,
                            "sensor": "temp2",
                        },
                    ],
                },
            ],
            "cpu_temp": 48.3,
            "hot_limit": 60,
            "unit": "C",
        }
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
        # GET /api/queries: newest first; Pi-hole logs no answer addresses.
        self.queries = [
            {
                "id": 7,
                "time": 1791370007.1,
                "type": "A",
                "domain": "Example.com",
                "cname": None,
                "status": "FORWARDED",
                "client": {"ip": "192.168.1.42", "name": "laptop.lan"},
                "dnssec": "INSECURE",
                "reply": {"type": "IP", "time": 12.3},
                "list_id": None,
                "upstream": "9.9.9.9#53",
            },
            {
                "id": 6,
                "time": 1791370006.1,
                "type": "AAAA",
                "domain": "example.com",
                "status": "CACHE",
                "client": {"ip": "192.168.1.42", "name": "laptop.lan"},
                "reply": {"type": "IP", "time": 0.1},
            },
            {
                "id": 5,
                "time": 1791370005.1,
                "type": "A",
                "domain": "ads.example.net",
                "status": "GRAVITY",
                "client": {"ip": "192.168.1.50", "name": None},
                "reply": {"type": "IP", "time": 0.1},
            },
            {
                "id": 4,
                "time": 1791370004.1,
                "type": "A",
                "domain": "tracker.example.net",
                "status": "DENYLIST_CNAME",
                "client": {"ip": "192.168.1.50", "name": None},
            },
            {
                "id": 3,
                "time": 1791370003.1,
                "type": "AAAA",
                "domain": "video.example.org",
                "status": "FORWARDED",
                "client": {"ip": "fd00::50", "name": None},
            },
            {
                "id": 2,
                "time": 1791370002.1,
                "type": "A",
                "domain": "hidden",
                "status": "FORWARDED",
                "client": {"ip": "192.168.1.51", "name": None},
            },
            {
                "id": 1,
                "time": 1791370001.1,
                "type": "A",
                "domain": "secret.example",
                "status": "FORWARDED",
                "client": {"ip": "0.0.0.0", "name": "hidden"},
            },
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
                "/api/info/system": lambda: {"system": self.system},
                "/api/info/sensors": lambda: {"sensors": self.sensors},
                "/api/dhcp/leases": lambda: {"leases": self.leases},
                "/api/lists": lambda: {"lists": self.lists},
                "/api/groups": lambda: {"groups": self.groups},
                "/api/domains": lambda: {"domains": self.domains},
                "/api/clients": lambda: {"clients": self.clients},
                "/api/queries": lambda: {
                    "queries": self.queries,
                    "cursor": 7,
                    "recordsTotal": len(self.queries),
                    "recordsFiltered": len(self.queries),
                    "draw": 0,
                },
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
