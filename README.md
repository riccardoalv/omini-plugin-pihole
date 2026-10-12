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
| Local DNS records (`dns.hosts`), IPv4 only | The network's local names (`nas.lan → 192.168.1.20`); a line with several names gives one name each |
| `dns.domain` | The network's local domain |
| DHCP server, when it is on: leases, `dhcp.hosts`, range | Clients and their addresses, fixed addresses, pool usage |

## What it changes

| Change | What it does |
|---|---|
| `dns.set` `{name, ip}` | Adds the record `ip name`; when the name is on another line, takes it out of that line (the line's other names stay) first. Read again to check it took. If Pi-hole refuses a step, the lines already changed are put back. |
| `dns.delete` `{name}` | Takes the name out of every line that holds it. Read again to check. |

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
be revoked without changing your own password.

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
| GET | `/api/info/version`, `/api/info/host`, `/api/network/interfaces` | Version, name, MAC and addresses |
| GET | `/api/dhcp/leases` | DHCP leases (only when the DHCP server is on) |
| GET | `/api/groups`, `/api/lists`, `/api/domains`, `/api/clients` | Backup |

## Not verified on hardware

The plugin follows Pi-hole's API documentation (`/api/docs`, FTL 6.x) and was
tested against a fake API and the Omini devnet emulator only:

- `/api/network/interfaces`: the MAC in `address` (or `perm_address`) and the
  IPs in `addresses[].address`. Without it, the address is the device's key.
- `dns.domain` as a string (FTL 6.0) or `{name, local}` (6.1 and later).
- `dhcp.hosts` in dnsmasq's `mac,ip,name[,lease]` form.
- `/api/dhcp/leases` with `expires` (Unix time, 0 = never), `name` (`*` when
  unknown) and `hwaddr`.
- The 403 answer to a configuration change without `app_sudo`.

## Development

```bash
uv run pytest -q          # tests (the SDK comes from ../omini/sdk/python)
uv run ruff check . && uv run ruff format --check .
```

## License

MIT
