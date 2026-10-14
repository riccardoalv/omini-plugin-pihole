"""Pi-hole v6: the server itself, its local DNS names (dns.hosts), its DHCP
server's leases and fixed addresses, and the dns.set / dns.delete changes."""

from __future__ import annotations

import contextlib
import ipaddress
import json
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, TypeVar
from urllib.parse import quote, urlsplit

from omini_sdk import (
    Change,
    Config,
    ConfigBackup,
    Device,
    DhcpLease,
    DhcpPool,
    DhcpReservation,
    DnsRecord,
    PluginError,
    Service,
    log,
)

try:  # DNS lookups: Omini 1.6 and later
    from omini_sdk import DnsLookup
except ImportError:
    DnsLookup = None  # type: ignore[assignment,misc]

from omini_pihole.client import Client, NotFound

T = TypeVar("T")

HOSTS = "/api/config/dns/hosts"
# Fields of the lists, groups, domains and clients that are bookkeeping, not configuration.
LIVE_ROW = {
    "id",
    "date_added",
    "date_modified",
    "date_updated",
    "number",
    "invalid_domains",
    "abp_entries",
    "status",
    "name",  # a client's name as Pi-hole resolved it (not set by the user)
}
# Queries read, and distinct (client, name) lookups kept.
QUERIES_LIMIT = 1000
MAX_LOOKUPS = 500
# Statuses of a query Pi-hole (or its upstream) blocked: nothing was reached.
BLOCKED = ("GRAVITY", "REGEX", "DENYLIST", "BLACKLIST", "EXTERNAL_BLOCKED", "SPECIAL_DOMAIN")


def client_from(cfg: Config) -> Client:
    url = cfg.str("url")
    if not url:
        raise PluginError("the address is required")
    return Client(url, cfg.str("password"), verify_tls=cfg.bool("verify_tls"))


def host_of(cfg: Config) -> str:
    """The host part of the address, as the user typed it."""
    url = cfg.str("url").strip()
    if "://" not in url:
        url = "http://" + url
    return (urlsplit(url).hostname or url).lower()


def optional(fn: Callable[[], T], default: T) -> T:
    """An endpoint some versions lack (404): its default instead."""
    try:
        return fn()
    except NotFound:
        return default


def mac(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    hexdigits = "".join(ch for ch in value.lower() if ch in "0123456789abcdef")
    if len(hexdigits) != 12 or hexdigits == "0" * 12:
        return None
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))


def ipv4(value: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError:
        return None


def dns_name(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def plain_version(value: Any) -> str | None:
    v = str(value or "").strip()
    return v.removeprefix("v") or None


def versions(info: dict[str, Any]) -> dict[str, str]:
    """Installed versions of Pi-hole's parts: core, web, ftl (and docker)."""
    out = {}
    for part, row in (info.get("version") or {}).items():
        local = row.get("local") if isinstance(row, dict) else None
        v = local.get("version") if isinstance(local, dict) else local
        if (pv := plain_version(v)) is not None:
            out[part] = pv
    return out


def hosts_lines(hosts: Any) -> list[tuple[str, list[str]]]:
    """dns.hosts lines ("ip name [name…]") as (ip, names)."""
    out = []
    for line in hosts or []:
        parts = str(line).split()
        if len(parts) >= 2:
            out.append((parts[0], [dns_name(n) for n in parts[1:]]))
    return out


def records(hosts: Any) -> list[DnsRecord]:
    seen: dict[tuple[str, str], DnsRecord] = {}
    for ip, names in hosts_lines(hosts):
        if not (v4 := ipv4(ip)):
            continue
        for name in names:
            if name:
                seen[(name, v4)] = DnsRecord(name=name, ip=v4)
    return [seen[k] for k in sorted(seen)]


def domain_of(dns: dict[str, Any]) -> str | None:
    """dns.domain: a string up to FTL 6.0, {name, local} since 6.1."""
    d = dns.get("domain")
    if isinstance(d, dict):
        d = d.get("name")
    return dns_name(d) or None


def interfaces(c: Client) -> list[dict[str, Any]]:
    got = optional(lambda: c.get("/api/network/interfaces"), None) or {}
    return [i for i in got.get("interfaces") or [] if isinstance(i, dict)]


def addresses_of(iface: dict[str, Any]) -> list[str]:
    out = []
    for a in iface.get("addresses") or []:
        raw = a.get("address") if isinstance(a, dict) else a
        try:
            ip = ipaddress.ip_address(str(raw).split("/")[0])
        except ValueError:
            continue
        if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified):
            out.append(str(ip))
    return out


def identity(ifaces: list[dict[str, Any]], host: str) -> tuple[str | None, list[str]]:
    """The MAC of the interface Omini reaches Pi-hole on (else the first one
    with an address) and every address of the machine."""
    ips: list[str] = []
    chosen: str | None = None
    first: str | None = None
    for iface in ifaces:
        if iface.get("name") == "lo":
            continue
        addrs = addresses_of(iface)
        m = mac(iface.get("address")) or mac(iface.get("perm_address"))
        for a in addrs:
            if a not in ips:
                ips.append(a)
        if m and addrs:
            first = first or m
            if host in addrs:
                chosen = m
    with contextlib.suppress(ValueError):
        ip = ipaddress.ip_address(host)
        if not (ip.is_loopback or ip.is_unspecified) and host not in ips:
            ips.insert(0, host)
    return chosen or first, ips


def lease_rows(c: Client) -> list[DhcpLease]:
    got = optional(lambda: c.get("/api/dhcp/leases"), None) or {}
    out = []
    for row in got.get("leases") or []:
        m, ip = mac(row.get("hwaddr")), ipv4(row.get("ip"))
        if not m or not ip:
            continue
        name = row.get("name")
        expires = row.get("expires")
        out.append(
            DhcpLease(
                ip=ip,
                mac=m,
                hostname=name if name and name != "*" else None,
                expires_at=datetime.fromtimestamp(expires, timezone.utc)
                if isinstance(expires, (int, float)) and expires > 0
                else None,
            )
        )
    return out


def reservations(dhcp: dict[str, Any]) -> list[DhcpReservation]:
    """dhcp.hosts, in dnsmasq's dhcp-host form: "aa:bb:…,192.168.1.20,nas[,lease]"."""
    out = []
    for line in dhcp.get("hosts") or []:
        m = ip = name = None
        for token in str(line).split(","):
            token = token.strip()
            if not token:
                continue
            if len(token) == 17 and mac(token):
                m = m or mac(token)
            elif ipv4(token):
                ip = ip or ipv4(token)
            elif (
                not name
                and ":" not in token
                and token != "infinite"
                and not token[:-1].isdigit()
                and not token.isdigit()
            ):
                name = token
        if m and ip:
            out.append(DhcpReservation(mac=m, ip=ip, name=name))
    return out


def pool(dhcp: dict[str, Any], used: list[DhcpLease]) -> DhcpPool | None:
    start, end = ipv4(dhcp.get("start")), ipv4(dhcp.get("end"))
    if not start or not end:
        return None
    lo, hi = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
    if hi < lo:
        return None
    network = f"{start}-{end}"
    gw, mask = ipv4(dhcp.get("router")), ipv4(dhcp.get("netmask"))
    if gw and mask and mask != "0.0.0.0":
        with contextlib.suppress(ValueError):
            network = str(ipaddress.IPv4Network(f"{gw}/{mask}", strict=False))
    in_range = sum(1 for lease in used if lo <= ipaddress.IPv4Address(lease.ip) <= hi)
    return DhcpPool(network=network, total=int(hi) - int(lo) + 1, used=in_range)


def lookups(rows: list[Any]) -> list[Any]:
    """One lookup per client and name, newest first (the API's order),
    without blocked queries. Pi-hole does not log the answers' addresses:
    Omini resolves the names itself."""
    found: dict[tuple[str, str], None] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("status") or "").upper().startswith(BLOCKED):
            continue
        client = row.get("client")
        ip = str((client.get("ip") if isinstance(client, dict) else client) or "").strip()
        domain = dns_name(row.get("domain"))
        try:
            hidden = ipaddress.ip_address(ip).is_unspecified  # privacy level 2 and up
        except ValueError:
            continue
        if hidden or not domain or domain == "hidden":  # "hidden": privacy level 1
            continue
        found.setdefault((ip, domain), None)
        if len(found) >= MAX_LOOKUPS:
            break
    return [DnsLookup(client=ip, domain=d) for ip, d in found]


def recent_lookups(c: Client) -> list[Any] | None:
    """The last queries as lookups; none with an older Omini or a failed read
    (they only name where devices go)."""
    if DnsLookup is None or "dns_lookups" not in Device.model_fields:
        return None
    try:
        got = c.get(f"/api/queries?length={QUERIES_LIMIT}") or {}
        return lookups(got.get("queries") or []) or None
    except Exception as e:
        log.debug("queries not read: %s", e)
        return None


def config_of(c: Client) -> dict[str, Any]:
    got = c.get("/api/config") or {}
    conf = got.get("config") if isinstance(got, dict) else None
    if not isinstance(conf, dict):
        raise PluginError("the address did not answer like Pi-hole v6 (no /api/config)")
    return conf


def read(c: Client, host: str) -> Device:
    conf = config_of(c)
    dns = conf.get("dns") or {}
    dhcp = conf.get("dhcp") or {}
    vers = versions(optional(lambda: c.get("/api/info/version"), None) or {})
    info = (optional(lambda: c.get("/api/info/host"), None) or {}).get("host") or {}
    uname = info.get("uname") or {}
    m, ips = identity(interfaces(c), host)
    dhcp_on = bool(dhcp.get("active"))
    dev = Device(
        key=m or host,
        name=str(uname.get("nodename") or "Pi-hole"),
        host=host,
        role="server",
        vendor="Pi-hole",
        model="Pi-hole",
        os_version=vers.get("core"),
        macs=[m] if m else None,
        ips=ips or None,
        dns_records=records(dns.get("hosts")),
        dns_domain=domain_of(dns),
        services=[
            Service(
                name="pihole-FTL",
                description="Pi-hole DNS server"
                + (f" (FTL {vers['ftl']})" if "ftl" in vers else ""),
                running=True,
                enabled=True,
            ),
            Service(
                name="DHCP", description="Pi-hole DHCP server", running=dhcp_on, enabled=dhcp_on
            ),
        ],
    )
    if (seen := recent_lookups(c)) is not None:
        dev.dns_lookups = seen
    if dhcp_on:
        got = lease_rows(c)
        dev.dhcp_leases = got
        dev.dhcp_reservations = reservations(dhcp)
        p = pool(dhcp, got)
        dev.dhcp_pools = [p] if p else None
    return dev


def collect(cfg: Config) -> list[Device]:
    with client_from(cfg) as c:
        return [read(c, host_of(cfg))]


def test(cfg: Config) -> str:
    with client_from(cfg) as c:
        vers = versions(optional(lambda: c.get("/api/info/version"), None) or {})
        hosts = (config_of(c).get("dns") or {}).get("hosts")
    v = vers.get("core")
    return f"Connected to Pi-hole{' ' + v if v else ''}, {len(records(hosts))} local names"


# -- changes --


def value_of(change: Change) -> dict[str, Any]:
    v = change.value
    if not isinstance(v, dict):
        raise PluginError(f"{change.kind}: the value must be an object")
    return v


def wanted_name(v: dict[str, Any]) -> str:
    name = dns_name(v.get("name"))
    if not name or "*" in name or any(ch.isspace() for ch in name) or "," in name:
        raise PluginError("a local DNS name is required, e.g. nas.home.arpa")
    return name


def read_hosts(c: Client) -> list[str]:
    got = c.get(HOSTS) or {}
    hosts = ((got.get("config") or {}).get("dns") or {}).get("hosts")
    return [str(h) for h in hosts or []]


def item(line: str) -> str:
    return f"{HOSTS}/{quote(line, safe='')}"


def answers(hosts: list[str], name: str) -> list[str]:
    """The addresses of the lines that hold name."""
    return [ip for ip, names in hosts_lines(hosts) if name in names]


def replace_lines(c: Client, hosts: list[str], name: str, new: str | None) -> None:
    """Take name out of every line that holds it (keeping the line's other
    names) and add the line new; put everything back if Pi-hole refuses."""
    touched = [h for h in hosts if name in [dns_name(n) for n in h.split()[1:]]]
    done: list[tuple[str, str]] = []  # (method, line) applied, to undo
    try:
        for line in touched:
            c.delete(item(line))
            done.append(("DELETE", line))
            ip, *names = line.split()
            rest = [n for n in names if dns_name(n) != name]
            if rest:
                kept = " ".join([ip, *rest])
                c.put(item(kept))
                done.append(("PUT", kept))
        if new:
            c.put(item(new))
    except PluginError:
        for method, line in reversed(done):
            with contextlib.suppress(PluginError, NotFound):
                if method == "DELETE":
                    c.put(item(line))
                else:
                    c.delete(item(line))
        raise


def apply(cfg: Config, change: Change) -> list[Device]:
    kind = change.kind if isinstance(change.kind, str) else change.kind.value
    v = value_of(change)
    with client_from(cfg) as c:
        if kind == "dns.set":
            name, ip = wanted_name(v), ipv4(v.get("ip"))
            if not ip:
                raise PluginError("dns.set: the address must be an IPv4 address")
            hosts = read_hosts(c)
            if answers(hosts, name) != [ip]:
                replace_lines(c, hosts, name, f"{ip} {name}")
            if answers(read_hosts(c), name) != [ip]:
                raise PluginError(f"Pi-hole did not keep {name} → {ip}")
            log.info("Pi-hole: %s set", name)
        elif kind == "dns.delete":
            name = wanted_name(v)
            hosts = read_hosts(c)
            if answers(hosts, name):
                replace_lines(c, hosts, name, None)
            if answers(read_hosts(c), name):
                raise PluginError(f"Pi-hole still answers {name}")
            log.info("Pi-hole: %s deleted", name)
        else:
            raise PluginError(f"Pi-hole does not support the change {kind}")
        return [read(c, host_of(cfg))]


# -- backup --


def secret(key: str) -> bool:
    k = key.lower()
    return any(s in k for s in ("pwhash", "password", "secret", "totp"))


def scrub(value: Any) -> Any:
    """The configuration without passwords, hashes and secrets."""
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items() if not secret(k)}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def rows(c: Client, path: str, key: str, sort: tuple[str, ...]) -> list[dict[str, Any]] | None:
    got = optional(lambda: c.get(path), None)
    if not isinstance(got, dict):
        return None
    out = [
        {k: v for k, v in r.items() if k not in LIVE_ROW}
        for r in got.get(key) or []
        if isinstance(r, dict)
    ]
    return sorted(out, key=lambda r: tuple(str(r.get(k)) for k in sort))


def settings(c: Client) -> dict[str, Any]:
    out: dict[str, Any] = {"config": scrub(config_of(c))}
    groups = optional(lambda: c.get("/api/groups"), None)
    if isinstance(groups, dict):
        # Lists, domains and clients name their groups by id: keep the ids here.
        out["groups"] = sorted(
            (
                {k: v for k, v in g.items() if k not in {"date_added", "date_modified"}}
                for g in groups.get("groups") or []
                if isinstance(g, dict)
            ),
            key=lambda g: (str(g.get("id")), str(g.get("name"))),
        )
    for path, key, sort in (
        ("/api/lists", "lists", ("type", "address")),
        ("/api/domains", "domains", ("type", "kind", "domain")),
        ("/api/clients", "clients", ("client",)),
    ):
        got = rows(c, path, key, sort)
        if got is not None:
            out[key] = got
    return out


def backup(cfg: Config) -> list[ConfigBackup]:
    with client_from(cfg) as c:
        host = host_of(cfg)
        m, _ = identity(interfaces(c), host)
        data = settings(c)
    content = json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)
    return [ConfigBackup(device=m or host, format="json", content=content + "\n")]
