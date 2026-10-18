import json
from datetime import datetime, timezone

import httpx
import pytest
from omini_sdk import Change, PluginError

import main  # noqa: F401  (registers the functions on the SDK's plugin)
import omini_pihole.collect as collect_module
from omini_pihole.collect import apply, backup, collect
from omini_pihole.collect import test as check

MAC = "dc:a6:32:01:02:03"


def change(kind, value):
    return Change(device=MAC, kind=kind, value=value)


def names(dev):
    return [(r.name, r.ip) for r in dev.dns_records or []]


def lookups(dev):
    return [(x.client, x.domain, x.answers) for x in dev.dns_lookups or []]


def test_collect_reads_the_queries(pihole, cfg):
    [dev] = collect(cfg)
    assert ("GET", "/api/queries?length=1000") in pihole.calls
    # One per client and name, newest first, no addresses (Pi-hole does not log
    # them); blocked queries and names or clients hidden by the privacy level
    # are left out.
    assert lookups(dev) == [
        ("192.168.1.42", "example.com", None),
        ("fd00::50", "video.example.org", None),
    ]


def test_collect_caps_the_lookups(pihole, cfg, monkeypatch):
    monkeypatch.setattr(collect_module, "MAX_LOOKUPS", 1)
    [dev] = collect(cfg)
    assert [d for _, d, _ in lookups(dev)] == ["example.com"]


@pytest.mark.parametrize("status", [404, 500])
def test_collect_without_the_queries(pihole, cfg, status):
    def handler(request):
        if request.url.path == "/api/queries":
            return httpx.Response(status, json={"error": {"key": "x", "message": "no"}})
        return pihole.handler(request)

    pihole.hook = handler
    [dev] = collect(cfg)
    assert dev.dns_lookups is None
    assert names(dev)  # the rest is read as usual


def test_collect_with_an_older_omini(pihole, cfg, monkeypatch):
    monkeypatch.setattr(collect_module, "DnsLookup", None)
    [dev] = collect(cfg)
    assert dev.dns_lookups is None
    assert not [c for c in pihole.calls if c[1].startswith("/api/queries")]


def test_collect_reads_the_server(pihole, cfg):
    [dev] = collect(cfg)
    assert dev.key == MAC and [m.root for m in dev.macs] == [MAC]
    assert (dev.name, dev.host, dev.role, dev.vendor, dev.model) == (
        "pihole",
        "192.168.1.53",
        "server",
        "Pi-hole",
        "Pi-hole",
    )
    assert dev.os_version == "6.1.2"
    assert dev.ips == ["192.168.1.53"]
    # IPv4 names only; a line may hold several names.
    assert names(dev) == [
        ("nas.lan", "192.168.1.20"),
        ("printer.lan", "192.168.1.30"),
        ("scanner.lan", "192.168.1.30"),
    ]
    assert dev.dns_domain == "lan"
    assert [(s.name, s.running) for s in dev.services] == [("pihole-FTL", True), ("DHCP", True)]
    assert dev.services[0].description == "Pi-hole DNS server (FTL 6.2.3)"
    # Signed out at the end.
    assert pihole.sessions == set()


def test_collect_reads_dhcp(pihole, cfg):
    [dev] = collect(cfg)
    assert [(x.ip, x.mac, x.hostname, x.expires_at) for x in dev.dhcp_leases] == [
        (
            "192.168.1.101",
            "aa:bb:cc:dd:ee:01",
            "laptop",
            datetime.fromtimestamp(1791374400, timezone.utc),
        ),
        ("192.168.1.102", "aa:bb:cc:dd:ee:02", None, None),
    ]
    assert [(r.mac, r.ip, r.name) for r in dev.dhcp_reservations] == [
        ("aa:bb:cc:dd:ee:20", "192.168.1.20", "nas"),
        ("aa:bb:cc:dd:ee:21", "192.168.1.21", "camera"),
    ]
    [pool] = dev.dhcp_pools
    assert (pool.network, pool.total, pool.used) == ("192.168.1.0/24", 100, 2)


def test_collect_without_dhcp(pihole, cfg):
    pihole.config["dhcp"]["active"] = False
    [dev] = collect(cfg)
    assert dev.dhcp_leases is None and dev.dhcp_reservations is None and dev.dhcp_pools is None
    assert ("GET", "/api/dhcp/leases") not in pihole.calls


def test_old_domain_setting_and_no_interfaces(pihole, cfg):
    pihole.config["dns"]["domain"] = "home.arpa"

    def handler(request):
        if request.url.path == "/api/network/interfaces":
            return httpx.Response(404, json={"error": {"key": "not_found"}})
        return pihole.handler(request)

    pihole.hook = handler
    [dev] = collect(cfg)
    assert dev.dns_domain == "home.arpa"
    # Without the interfaces, the address is the key.
    assert dev.key == "192.168.1.53" and dev.macs is None and dev.ips == ["192.168.1.53"]


def test_wrong_password(pihole, cfg):
    cfg["password"] = "nope"
    with pytest.raises(PluginError, match="rejected the password"):
        collect(cfg)


def test_pihole_v5(pihole, cfg):
    pihole.hook = lambda request: httpx.Response(404, text="Not found")
    with pytest.raises(PluginError, match="Pi-hole v6"):
        collect(cfg)


def test_test_returns_the_version(pihole, cfg):
    assert check(cfg) == "Connected to Pi-hole 6.1.2, 3 local names"
    assert pihole.sessions == set()


# -- dns.set / dns.delete --


def test_dns_set_adds_a_name(pihole, cfg):
    [dev] = apply(cfg, change("dns.set", {"name": "NAS2.lan.", "ip": "192.168.1.21"}))
    assert ("nas2.lan", "192.168.1.21") in names(dev)
    assert pihole.writes() == [("PUT", "/api/config/dns/hosts/192.168.1.21 nas2.lan")]
    assert pihole.sessions == set()


def test_dns_set_sends_the_line_url_encoded(pihole, cfg):
    seen = []

    def handler(request):
        if request.method == "PUT":
            seen.append(request.url.raw_path.decode())
        return pihole.handler(request)

    pihole.hook = handler
    apply(cfg, change("dns.set", {"name": "nas2.lan", "ip": "192.168.1.21"}))
    assert seen == ["/api/config/dns/hosts/192.168.1.21%20nas2.lan"]


def test_dns_set_changes_the_address_of_the_same_name(pihole, cfg):
    [dev] = apply(cfg, change("dns.set", {"name": "nas.lan", "ip": "192.168.1.25"}))
    assert ("nas.lan", "192.168.1.25") in names(dev)
    assert ("nas.lan", "192.168.1.20") not in names(dev)
    assert pihole.hosts.count("192.168.1.25 nas.lan") == 1
    assert "192.168.1.20 nas.lan" not in pihole.hosts


def test_dns_set_keeps_the_other_names_of_a_line(pihole, cfg):
    apply(cfg, change("dns.set", {"name": "scanner.lan", "ip": "192.168.1.31"}))
    assert "192.168.1.30 printer.lan" in pihole.hosts
    assert "192.168.1.31 scanner.lan" in pihole.hosts
    assert "192.168.1.30 printer.lan scanner.lan" not in pihole.hosts


def test_dns_set_already_there_changes_nothing(pihole, cfg):
    apply(cfg, change("dns.set", {"name": "printer.lan", "ip": "192.168.1.30"}))
    assert pihole.writes() == []


def test_dns_set_without_app_sudo(pihole, cfg):
    pihole.app_sudo = False
    with pytest.raises(PluginError, match="app_sudo"):
        apply(cfg, change("dns.set", {"name": "new.lan", "ip": "192.168.1.5"}))
    assert pihole.sessions == set()


def test_dns_set_puts_lines_back_when_refused(pihole, cfg):
    def handler(request):
        if request.method == "PUT" and "192.168.1.25" in request.url.raw_path.decode():
            return httpx.Response(
                400, json={"error": {"key": "bad_request", "message": "Invalid item"}}
            )
        return pihole.handler(request)

    pihole.hook = handler
    before = list(pihole.hosts)
    with pytest.raises(PluginError, match="Invalid item"):
        apply(cfg, change("dns.set", {"name": "nas.lan", "ip": "192.168.1.25"}))
    assert sorted(pihole.hosts) == sorted(before)


def test_dns_set_puts_lines_back_on_not_found(pihole, cfg):
    def handler(request):
        if request.method == "PUT" and "192.168.1.25" in request.url.raw_path.decode():
            return httpx.Response(404, json={"error": {"key": "not_found", "message": "Gone"}})
        return pihole.handler(request)

    pihole.hook = handler
    before = list(pihole.hosts)
    with pytest.raises(PluginError, match="put back"):
        apply(cfg, change("dns.set", {"name": "nas.lan", "ip": "192.168.1.25"}))
    assert sorted(pihole.hosts) == sorted(before)


def test_dns_set_not_kept_fails_the_verification(pihole, cfg):
    def handler(request):
        resp = pihole.handler(request)
        if request.method == "PUT":
            pihole.hosts.pop()  # accepted, then lost
        return resp

    pihole.hook = handler
    with pytest.raises(PluginError, match=r"did not keep new\.lan"):
        apply(cfg, change("dns.set", {"name": "new.lan", "ip": "192.168.1.5"}))


def test_dns_set_refuses_bad_values(pihole, cfg):
    with pytest.raises(PluginError, match="IPv4"):
        apply(cfg, change("dns.set", {"name": "nas.lan", "ip": "nope"}))
    with pytest.raises(PluginError, match="name is required"):
        apply(cfg, change("dns.set", {"name": "a b", "ip": "192.168.1.2"}))
    with pytest.raises(PluginError, match="does not support"):
        apply(cfg, change("wol.send", {"mac": "aa:bb:cc:dd:ee:01"}))
    assert pihole.writes() == []


def test_dns_delete(pihole, cfg):
    [dev] = apply(cfg, change("dns.delete", {"name": "printer.lan"}))
    assert names(dev) == [("nas.lan", "192.168.1.20"), ("scanner.lan", "192.168.1.30")]
    assert "192.168.1.30 scanner.lan" in pihole.hosts
    pihole.calls.clear()
    apply(cfg, change("dns.delete", {"name": "printer.lan"}))
    assert pihole.writes() == []


# -- backup --


def test_backup_without_secrets_or_live_state(pihole, cfg):
    [b] = backup(cfg)
    assert (b.device, b.format) == (MAC, "json")
    data = json.loads(b.content)
    assert set(data) == {"config", "groups", "lists", "domains", "clients"}
    api = data["config"]["webserver"]["api"]
    assert api == {"app_sudo": True, "max_sessions": 16}
    for secret in ("BALLOON", "JBSWY3DPEHPK3PXP", PASSWORD_FRAGMENT):
        assert secret not in b.content
    assert data["lists"] == [
        {
            "address": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "type": "block",
            "comment": "Migrated from /etc/pihole/adlists.list",
            "groups": [0],
            "enabled": True,
        }
    ]
    assert data["clients"] == [{"client": "192.168.1.50", "comment": "Kids", "groups": [0]}]
    assert data["groups"][0]["id"] == 0 and "date_added" not in data["groups"][0]
    assert b.content == json.dumps(data, sort_keys=True, indent=2) + "\n"


PASSWORD_FRAGMENT = "app-password"


def test_backup_is_deterministic(pihole, cfg):
    first = backup(cfg)[0].content
    pihole.leases.append({"expires": 1, "hwaddr": "aa:bb:cc:dd:ee:09", "ip": "192.168.1.109"})
    pihole.lists[0]["number"] += 5
    pihole.lists[0]["date_updated"] += 86400
    pihole.clients[0]["name"] = "tablet-2.lan"
    assert backup(cfg)[0].content == first
    pihole.hosts.append("192.168.1.9 new.lan")
    assert backup(cfg)[0].content != first
