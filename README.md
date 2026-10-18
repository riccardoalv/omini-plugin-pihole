# omini-plugin-pihole

[Omini](https://github.com/riccardoalv/omini) plugin for **Pi-hole v6**,
through its REST API (`/api/...`). Omini uses it as the DNS server of a
network: the local names Omini gives to devices with a fixed address go here
when the network's DHCP hands out Pi-hole as its DNS server. Pi-hole v5 and
older (the PHP API) are not supported.

## What it reads

| Data | Used for |
|---|---|
| Versions (core, FTL), host name, network interfaces | The server on the map (vendor Pi-hole), keyed by its MAC (else its address) so it merges with the machine it runs on |
| Network interfaces (`lo` left out): name, MAC, IPv4 and IPv6 addresses with their prefix, link (carrier), speed, type (ethernet, wireless, bridge, …) | The server's ports in the device panel |
| System: uptime, CPU use and count, load averages, memory (use, total, used), swap use | Health of the server in the device panel |
| Temperature sensors (CPU, disks, others) | Health of the server; a sensor of the CPU's own driver is marked as the CPU |
| Local DNS records (`dns.hosts`), IPv4 only | The network's local names (`nas.lan → 192.168.1.20`); a line with several names gives one name each |
| `dns.domain` | The network's local domain |
| DHCP server, when it is on: leases, `dhcp.hosts`, range | Clients and their addresses, fixed addresses, pool usage |
| The last 1000 queries: which client asked for which name | Naming where devices go in traffic flows (address → name) |

The queries give at most 500 lookups, one per client and name (newest first).
Blocked queries (gravity, regex, denylist, blocked upstream) are left out, as
are names and clients hidden by Pi-hole's privacy level. Pi-hole does not log
the addresses it answered, so Omini asks the Pi-hole for them (a DNS query to
it for each name). Omini uses the lookups only to name the destinations of
traffic flows and keeps them in memory, never on disk. When the queries
cannot be read, the rest is collected as usual; an Omini older than 1.6 does
not ask for them.

## What it changes

| Change | What it does |
|---|---|
| `dns.set` `{name, ip}` | Adds the record `ip name`; when the name is on another IPv4 line, takes it out of that line (the line's other names stay) first; IPv6 lines are never touched. Read again to check it took. If Pi-hole refuses a step, the lines already changed are put back. |
| `dns.delete` `{name}` | Takes the name out of every IPv4 line that holds it (IPv6 lines stay). Read again to check. |

Pi-hole saves its configuration (`pihole.toml`) by itself. Records have no
description field, so the ones Omini made are not marked.

## Backups

`GET /api/config` (the whole configuration) as sorted JSON, without any
password hash, TOTP secret or other field whose name holds "password",
"pwhash", "secret" or "totp"; plus the groups, block/allow lists, domains and
client assignments, without their ids, dates, counts and status. Leases and
query data are never included, so two backups differ only when the
configuration changed.

## Account

Use an **application password**: Settings → Web interface / API → Expert →
"Configure app password". It works with two-factor authentication on, and can
be revoked without changing your own password. It can read the query log
(`GET /api/queries`) and the system information (`GET /api/info/...`)
without `app_sudo`.

To let Omini change DNS names, the application password needs
`webserver.api.app_sudo` on (Settings → All settings → Webserver and API →
`webserver.api.app_sudo`, or `pihole-FTL --config webserver.api.app_sudo true`).
Without it Omini only reads, and a change is refused with that hint.

The plugin signs in (`POST /api/auth`) at the start of each run and signs out
(`DELETE /api/auth`) at the end, so it holds no session between runs.

## Endpoints

| Method | Path | For |
|---|---|---|
| POST / DELETE | `/api/auth` | Sign in (session id in `X-FTL-SID`) / out |
| GET | `/api/config` | `dns.hosts`, `dns.domain`, `dhcp`; backup |
| GET | `/api/config/dns/hosts` | Local names (checks after a change) |
| PUT / DELETE | `/api/config/dns/hosts/<"ip name", URL-encoded>` | `dns.set`, `dns.delete` |
| GET | `/api/info/version`, `/api/info/host` | Version, name |
| GET | `/api/network/interfaces` | MAC, addresses and interfaces |
| GET | `/api/info/system`, `/api/info/sensors` | Health and temperatures |
| GET | `/api/queries?length=1000` | Recent DNS lookups |
| GET | `/api/dhcp/leases` | DHCP leases (only when the DHCP server is on) |
| GET | `/api/groups`, `/api/lists`, `/api/domains`, `/api/clients` | Backup |

## Not verified on hardware

The plugin follows Pi-hole's API documentation (`/api/docs`, FTL 6.x) and was
tested against a fake API and the Omini devnet emulator only:

- `/api/network/interfaces`: the MAC in `address` (or `perm_address`), the
  IPs in `addresses[].address` with `prefixlen`, the link in `carrier` (else
  `state`), `speed` in Mbit/s (-1 when unknown), `type` (`ether`,
  `loopback`, …) and, when given, the link `kind` (`bridge`, `vlan`, `bond`).
  A Wi-Fi interface is told by its name (`wl…`). FTL gives the byte counters
  rounded (`{value, unit}`): they are left out, and read only when they come
  as plain numbers. Without the endpoint (or when it is refused), the address
  is the device's key and there are no interfaces.
- `/api/info/system`: `uptime` (seconds), `cpu.nprocs`, `cpu["%cpu"]`,
  `cpu.load.raw` (1, 5, 15 minutes), `memory.ram` and `memory.swap` with
  `total` and `used` in kB and `%used`. Swap use is left out when there is no
  swap; a field that is missing (older FTL) stays empty.
- `/api/info/sensors`: `list[].name` (the hwmon driver) and
  `list[].temps[]` with `name` (label), `sensor` and `value`, in `unit`
  (`C`, `F` or `K`, converted to Celsius). The CPU is the reading of
  `coretemp`, `k10temp`, `k8temp`, `zenpower` or `cpu_thermal`; with no chip
  listed, `cpu_temp` (Pi-hole's own pick) is the CPU's.
- `dns.domain` as a string (FTL 6.0) or `{name, local}` (6.1 and later).
- `dhcp.hosts` in dnsmasq's `mac,ip,name[,lease]` form.
- `/api/dhcp/leases` with `expires` (Unix time, 0 = never), `name` (`*` when
  unknown) and `hwaddr`.
- The 403 answer to a configuration change without `app_sudo`.
- `/api/queries` answering newest first, with `client.ip`, `domain` and
  `status`; the blocked statuses taken from FTL's list (`GRAVITY`, `REGEX`,
  `DENYLIST`, their `_CNAME` forms, `EXTERNAL_BLOCKED_*`, `SPECIAL_DOMAIN`),
  and `hidden` / `0.0.0.0` for what the privacy level hides.

## Development

```bash
uv run pytest -q          # tests (the SDK comes from ../omini/sdk/python)
uv run ruff check . && uv run ruff format --check .
```

## License

MIT
