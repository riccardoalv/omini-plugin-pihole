"""Pi-hole v6: the server itself, its local DNS names (dns.hosts), its DHCP
server's leases and fixed addresses, and the dns.set / dns.delete changes."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import math
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
    Firmware,
    Interface,
    PluginError,
    Service,
    Temperature,
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


def extra(fn: Callable[[], T], default: T) -> T:
    """A read that only adds detail: its default when it is missing (404),
    refused (403) or fails, so the collection goes on."""
    try:
        return fn()
    except (NotFound, PluginError) as e:
        log.debug("not read: %s", e)
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


# Pi-hole's parts, in the order they are shown.
PARTS = (("core", "core"), ("web", "web"), ("ftl", "FTL"), ("docker", "Docker"))


def side(row: Any, which: str) -> dict[str, Any]:
    got = row.get(which) if isinstance(row, dict) else None
    return got if isinstance(got, dict) else {}


def firmware(info: dict[str, Any]) -> Firmware | None:
    """Installed and newest versions of Pi-hole's parts, from Pi-hole's own
    (cached) update check: "core 6.1.2, web 6.2.1, FTL 6.2.3"."""
    parts = info.get("version") if isinstance(info.get("version"), dict) else {}
    current: list[str] = []
    latest: list[str] = []
    newer = unknown = False
    for key, label in PARTS:
        local, remote = side(parts.get(key), "local"), side(parts.get(key), "remote")
        here, there = plain_version(local.get("version")), plain_version(remote.get("version"))
        if here is None:
            continue
        current.append(f"{label} {here}")
        if there is None:  # not checked (yet): the newest version is unknown
            unknown = True
            continue
        latest.append(f"{label} {there}")
        lh, rh = local.get("hash"), remote.get("hash")
        if local.get("branch") not in (None, "", "master") and lh and rh:
            newer |= str(lh) != str(rh)  # another branch: Pi-hole compares the commits
        else:
            newer |= here != there
    if not current:
        return None
    return Firmware(
        current=", ".join(current),
        latest=None if unknown else ", ".join(latest),
        update_available=True if newer else (None if unknown else False),
    )


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
    got = extra(lambda: c.get("/api/network/interfaces"), None) or {}
    if not isinstance(got, dict):
        return []
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


def prefixed(iface: dict[str, Any]) -> list[str]:
    """The interface's IPv4 and IPv6 addresses with their prefix length
    (192.168.1.53/24, 2001:db8::53/64); link-local ones are left out."""
    out = []
    for a in iface.get("addresses") or []:
        text = str((a.get("address") if isinstance(a, dict) else a) or "").strip()
        try:
            ip = ipaddress.ip_address(text.split("/")[0])
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            continue
        prefix: Any = text.split("/")[1] if "/" in text else None
        if prefix is None and isinstance(a, dict):
            prefix = a.get("prefixlen")
        if isinstance(prefix, str) and prefix.isdigit():
            prefix = int(prefix)
        # Without a known prefix: the address alone.
        known = number(prefix) and 0 <= prefix <= ip.max_prefixlen
        value = f"{ip}/{prefix}" if known else str(ip)
        if value not in out:
            out.append(value)
    return out


def number(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def counter(value: Any) -> int | None:
    """A byte counter as a plain integer. FTL gives a rounded {value, unit}
    instead, which is not a counter: left out."""
    return value if number(value) and value >= 0 else None


# netlink's link kind (IFLA_INFO_KIND), when FTL gives it.
KINDS = {"bridge": "bridge", "vlan": "vlan", "bond": "lag", "team": "lag", "wireguard": "tunnel"}


def kind_of(iface: dict[str, Any]) -> Any:
    kind = str(iface.get("kind") or "").lower()
    if kind:
        return KINDS.get(kind, "other")
    if str(iface.get("type") or "").lower() != "ether":
        return "other"
    # Linux names its Wi-Fi interfaces wlan0, wlp2s0…
    return "wireless" if str(iface.get("name") or "").startswith("wl") else "ethernet"


def port(iface: dict[str, Any]) -> Interface | None:
    name = str(iface.get("name") or "").strip()
    if not name or name == "lo" or str(iface.get("type") or "").lower() == "loopback":
        return None
    carrier, state = iface.get("carrier"), str(iface.get("state") or "").lower()
    up = carrier if isinstance(carrier, bool) else {"up": True, "down": False}.get(state)
    speed = iface.get("speed")  # Mbit/s; -1 when the driver does not know
    stats = iface.get("stats")
    stats = stats if isinstance(stats, dict) else {}
    return Interface(
        name=name,
        type=kind_of(iface),
        mac=mac(iface.get("address")) or mac(iface.get("perm_address")),
        ips=prefixed(iface) or None,
        up=up,
        speed_mbps=speed if number(speed) and speed > 0 else None,
        rx_bytes=counter(stats.get("rx_bytes")),
        tx_bytes=counter(stats.get("tx_bytes")),
    )


def ports(ifaces: list[dict[str, Any]]) -> list[Interface]:
    return [p for i in ifaces if (p := port(i))]


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


def real(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def pct(value: Any) -> float | None:
    v = real(value)
    return round(v, 2) if v is not None and 0 <= v <= 100 else None


def kib(value: Any) -> int | None:
    """FTL's memory sizes are in kB, as in /proc/meminfo."""
    v = real(value)
    return int(v * 1024) if v is not None and v >= 0 else None


def health(dev: Device, c: Client) -> None:
    """Uptime, CPU, memory, load and swap of the machine (GET /api/info/system)."""
    got = extra(lambda: c.get("/api/info/system"), None)
    system = got.get("system") if isinstance(got, dict) else None
    if not isinstance(system, dict):
        return
    up = real(system.get("uptime"))
    dev.uptime_s = int(up) if up is not None and up >= 0 else None
    cpu = system.get("cpu") if isinstance(system.get("cpu"), dict) else {}
    dev.cpu_pct = pct(cpu.get("%cpu"))
    n = cpu.get("nprocs")
    dev.cpu_count = n if number(n) and n >= 1 else None
    load = (cpu.get("load") or {}).get("raw") if isinstance(cpu.get("load"), dict) else None
    if isinstance(load, list) and len(load) == 3:
        vals = [real(v) for v in load]
        if all(v is not None and v >= 0 for v in vals):
            dev.load_avg = vals  # type: ignore[assignment]
    memory = system.get("memory") if isinstance(system.get("memory"), dict) else {}
    ram = memory.get("ram") if isinstance(memory.get("ram"), dict) else {}
    dev.mem_pct = pct(ram.get("%used"))
    dev.mem_total_bytes = kib(ram.get("total")) or None
    dev.mem_used_bytes = kib(ram.get("used"))
    swap = memory.get("swap") if isinstance(memory.get("swap"), dict) else {}
    if (real(swap.get("total")) or 0) > 0:  # without swap there is no swap use
        dev.swap_pct = pct(swap.get("%used"))


# hwmon drivers of a CPU's own sensor (a Raspberry Pi's SoC is its CPU).
CPU_SENSORS = {"coretemp", "k10temp", "k8temp", "zenpower", "cpu_thermal", "cpu-thermal"}


def celsius(value: Any, unit: str) -> float | None:
    v = real(value)
    if v is None:
        return None
    if unit == "F":
        v = (v - 32) * 5 / 9
    elif unit == "K":
        v -= 273.15
    elif unit not in ("C", ""):
        return None
    return round(v, 1)


def temperatures(c: Client) -> list[Temperature] | None:
    """The machine's temperature sensors (GET /api/info/sensors), in the unit
    Pi-hole is set to show (C, F or K)."""
    got = extra(lambda: c.get("/api/info/sensors"), None)
    sensors = got.get("sensors") if isinstance(got, dict) else None
    if not isinstance(sensors, dict):
        return None
    unit = str(sensors.get("unit") or "C").upper()
    out: list[Temperature] = []
    for chip in sensors.get("list") or []:
        if not isinstance(chip, dict):
            continue
        chip_name = str(chip.get("name") or "").strip()
        temps = [t for t in chip.get("temps") or [] if isinstance(t, dict)]
        for t in temps:
            if (deg := celsius(t.get("value"), unit)) is None:
                continue
            label = str(t.get("name") or t.get("sensor") or "").strip()
            name = chip_name if len(temps) == 1 or not label else f"{chip_name} {label}".strip()
            if not name:
                continue
            kind = "cpu" if chip_name.lower() in CPU_SENSORS else "other"
            out.append(Temperature(sensor=name, kind=kind, celsius=deg))
    if not out and (deg := celsius(sensors.get("cpu_temp"), unit)) is not None:
        out.append(Temperature(sensor="CPU", kind="cpu", celsius=deg))  # Pi-hole's own pick
    return out or None


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
    Omini asks the Pi-hole for them (a DNS query)."""
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
    version_info = extra(lambda: c.get("/api/info/version"), None)
    version_info = version_info if isinstance(version_info, dict) else {}
    vers = versions(version_info)
    info = (optional(lambda: c.get("/api/info/host"), None) or {}).get("host") or {}
    uname = info.get("uname") or {}
    ifaces = interfaces(c)
    m, ips = identity(ifaces, host)
    dhcp_on = bool(dhcp.get("active"))
    dev = Device(
        key=m or host,
        name=str(uname.get("nodename") or "Pi-hole"),
        host=host,
        role="server",
        vendor="Pi-hole",
        model="Pi-hole",
        os_version=vers.get("core"),
        firmware=firmware(version_info),
        macs=[m] if m else None,
        ips=ips or None,
        interfaces=ports(ifaces) or None,
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
    health(dev, c)
    dev.temperatures = temperatures(c)
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
    """The IPv4 addresses of the lines that hold name (Omini manages IPv4
    names only: IPv6 lines are never touched)."""
    return [ip for ip, names in hosts_lines(hosts) if name in names and ipv4(ip)]


def replace_lines(c: Client, hosts: list[str], name: str, new: str | None) -> None:
    """Take name out of every IPv4 line that holds it (keeping the line's other
    names) and add the line new; put everything back if Pi-hole refuses."""
    touched = [
        h
        for h in hosts
        if len(h.split()) >= 2
        and ipv4(h.split()[0])
        and name in [dns_name(n) for n in h.split()[1:]]
    ]
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
    except (PluginError, NotFound) as e:
        for method, line in reversed(done):
            with contextlib.suppress(PluginError, NotFound):
                if method == "DELETE":
                    c.put(item(line))
                else:
                    c.delete(item(line))
        if isinstance(e, NotFound):
            raise PluginError(f"Pi-hole did not find {e}; the lines changed were put back") from e
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
