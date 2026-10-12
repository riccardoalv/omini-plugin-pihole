"""Minimal client for Pi-hole v6's REST API (``/api/...``).

Signing in: ``POST /api/auth {"password": ...}`` answers a session id
(``session.sid``) that every request carries in the ``X-FTL-SID`` header;
``DELETE /api/auth`` ends it (Pi-hole keeps a limited number of sessions, so
the plugin always signs out). Errors come as
``{"error": {"key", "message", "hint"}}``.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from omini_sdk import PluginError


class NotFound(Exception):
    """The endpoint (or item) does not exist on this version (404)."""


class Client:
    def __init__(
        self,
        url: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 10,
        transport: httpx.BaseTransport | None = None,
    ):
        url = url.strip().rstrip("/")
        if url.endswith("/admin"):
            url = url.removesuffix("/admin")
        if not url.startswith(("https://", "http://")):
            url = "http://" + url
        self.base = url
        self.password = password
        self.sid: str | None = None
        self.http = httpx.Client(
            base_url=url,
            verify=verify_tls,
            timeout=timeout,
            headers={"Accept": "application/json", "User-Agent": "omini-plugin-pihole"},
            transport=transport,
        )

    def __enter__(self) -> Client:
        self.login()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def login(self) -> None:
        r = self._send("POST", "/api/auth", {"password": self.password})
        if r.status_code == 404:
            raise PluginError(
                f"{self.base} has no /api/auth: is it Pi-hole v6 (v5 and older are not supported)?"
            )
        if r.status_code == 429:
            raise PluginError("Pi-hole has too many sessions open; try again in a few minutes")
        if r.status_code >= 500:
            raise PluginError(f"Pi-hole answered {r.status_code} when signing in")
        body = self._json(r, "/api/auth")
        session = body.get("session") if isinstance(body, dict) else None
        if not isinstance(session, dict) or not session.get("valid"):
            if isinstance(session, dict) and session.get("totp") and r.status_code != 401:
                raise PluginError(
                    "Pi-hole asks for a two-factor code: use an application password instead"
                )
            raise PluginError(
                "Pi-hole rejected the password (use an application password, see the plugin's "
                "README)"
            )
        self.sid = session.get("sid")  # None when Pi-hole has no password at all

    def close(self) -> None:
        try:
            if self.sid:
                self._send("DELETE", "/api/auth")
        except PluginError:
            pass  # the session expires by itself
        finally:
            self.sid = None
            self.http.close()

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def put(self, path: str, body: Any = None) -> Any:
        return self.request("PUT", path, body)

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)

    def _send(self, method: str, path: str, body: Any = None) -> httpx.Response:
        headers = {"X-FTL-SID": self.sid} if self.sid else {}
        try:
            return self.http.request(method, path, json=body, headers=headers)
        except httpx.ConnectError as e:
            raise PluginError(f"cannot connect to {self.base}: {e}") from e
        except httpx.TimeoutException as e:
            raise PluginError(f"{self.base} did not answer in time") from e
        except httpx.HTTPError as e:
            raise PluginError(f"request to {self.base} failed: {e}") from e

    def _json(self, r: httpx.Response, path: str) -> Any:
        if not r.content:
            return None
        try:
            return r.json()
        except json.JSONDecodeError as e:
            raise PluginError(
                f"{self.base} did not answer with JSON for {path}: is it Pi-hole v6?"
            ) from e

    def request(self, method: str, path: str, body: Any = None) -> Any:
        r = self._send(method, path, body)
        if r.status_code == 401:
            raise PluginError("Pi-hole ended the session (sign in again)")
        if r.status_code == 403:
            raise PluginError(
                f"Pi-hole refused {method} {path}: an application password may only change the "
                "configuration with 'webserver.api.app_sudo' on (see the plugin's README)"
            )
        if r.status_code == 404:
            raise NotFound(path)
        if r.status_code >= 400:
            raise PluginError(f"Pi-hole refused {method} {path}: {message(r)}")
        return self._json(r, path)


def message(r: httpx.Response) -> str:
    """Pi-hole's own words for an error."""
    try:
        body = r.json()
    except json.JSONDecodeError:
        return f"HTTP {r.status_code}"
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        parts = [str(err.get(k)) for k in ("message", "hint") if err.get(k)]
        if parts:
            return " — ".join(parts)
    return f"HTTP {r.status_code}"
