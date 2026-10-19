"""Client for Pi-hole v6's REST API (``/api/...``), on the SDK's HTTP client:
timeouts, retries, and errors that say what went wrong.

Signing in: ``POST /api/auth {"password": ...}`` answers a session id
(``session.sid``) that every request carries in the ``X-FTL-SID`` header;
``DELETE /api/auth`` ends it. Pi-hole keeps a limited number of sessions and
limits logins, so the session is kept in the plugin's state folder (the
SDK's ``Session``) and used again on the next run until Pi-hole forgets it
(401); without a state folder the plugin signs out at the end of each run,
as the connection test always does. After Pi-hole refuses the password the
plugin waits 10 minutes before signing in again (``LoginBackoff``). Errors
come as ``{"error": {"key", "message", "hint"}}``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from omini_sdk import PluginError, log
from omini_sdk.http import Client as HttpClient
from omini_sdk.http import (
    Forbidden,
    HttpError,
    LoginBackoff,
    NotFound,
    Session,
    Unauthorized,
)

__all__ = ["APP_SUDO", "Client", "NotFound", "message"]

APP_SUDO = "webserver.api.app_sudo"
SID = "X-FTL-SID"


class Client(HttpClient):
    def __init__(
        self,
        url: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 15,
        transport: httpx.BaseTransport | None = None,
        state_dir: Path | str | None = None,
    ):
        super().__init__(
            url,
            name="Pi-hole",
            scheme="http",
            strip=("/admin",),
            verify_tls=verify_tls,
            timeout=timeout,
            user_agent="omini-plugin-pihole",
            unauthorized="Pi-hole ended the session (sign in again)",
            transport=transport,
        )
        self.password = password
        self.sid: str | None = None
        self.session = Session(state_dir, self.base, password)
        self.backoff_login = LoginBackoff(state_dir, self.base, password, minutes=10)
        # Without a state folder the session cannot be kept: sign out at the end.
        self.keep = state_dir is not None
        self.reused = False  # the session came from the state folder
        self.logins = 0

    def __enter__(self) -> Client:
        self.login()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _use(self, sid: str | None) -> None:
        self.sid = sid
        if sid:
            self.http.headers[SID] = sid
        else:
            self.http.headers.pop(SID, None)

    def login(self) -> None:
        """Uses the saved session, else signs in."""
        saved = self.session.load().get("sid")
        if isinstance(saved, str) and saved:
            self._use(saved)
            self.reused = True
            return
        self.sign_in()

    def sign_in(self) -> None:
        self.backoff_login.check()
        self._use(None)
        self.reused = False
        r = self.send("POST", "/api/auth", json={"password": self.password})
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
            refused = (
                "Pi-hole rejected the password (use an application password, see the plugin's "
                "README)"
            )
            self.backoff_login.refused(refused)
            raise PluginError(refused)
        self.backoff_login.clear()
        self.logins += 1
        self._use(session.get("sid"))  # None when Pi-hole has no password at all
        if self.sid and self.keep:
            self.session.save({"sid": self.sid})

    def logout(self) -> None:
        """Ends the session on Pi-hole (it expires by itself otherwise)."""
        try:
            if self.sid:
                self.send("DELETE", "/api/auth")
        except PluginError as e:
            log.debug("could not sign out: %s", e)
        finally:
            self.session.clear()
            self._use(None)

    def close(self) -> None:
        try:
            if not self.keep:
                self.logout()
        finally:
            self.http.close()

    def get(self, path: str) -> Any:  # type: ignore[override]
        return self.request("GET", path)

    def put(self, path: str, body: Any = None) -> Any:  # type: ignore[override]
        return self.request("PUT", path, json=body)

    def delete(self, path: str) -> Any:  # type: ignore[override]
        return self.request("DELETE", path)

    def request(self, method: str, path: str, **kw: Any) -> Any:
        """A saved session Pi-hole forgot (401) signs in again, once."""
        try:
            return super().request(method, path, **kw)
        except Unauthorized:
            if not self.reused:
                raise
            log.info("the saved Pi-hole session expired, signing in again")
            self.session.clear()
            self.sign_in()
            return super().request(method, path, **kw)

    def json(self, r: httpx.Response, path: str = "") -> Any:
        return self._json(r, path)

    def _json(self, r: httpx.Response, path: str) -> Any:
        if not r.content:
            return None
        try:
            return r.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise PluginError(
                f"{self.base} did not answer with JSON for {path}: is it Pi-hole v6?"
            ) from e

    def check(self, r: httpx.Response, method: str, path: str) -> None:
        status = r.status_code
        where = {"status": status, "method": method, "resource": path}
        if status == 403:
            raise Forbidden(
                f"Pi-hole refused {method} {path}: an application password may only change the "
                f"configuration with '{APP_SUDO}' on (see the plugin's README)",
                privilege=APP_SUDO,
                **where,
            )
        if status == 404:
            raise NotFound(f"Pi-hole did not find {path}", **where)
        if 400 <= status < 500 and status not in (401, 410, 429):
            raise HttpError(f"Pi-hole refused {method} {path}: {message(r)}", **where)
        super().check(r, method, path)

    def detail(self, r: httpx.Response) -> str:
        return message(r)


def message(r: httpx.Response) -> str:
    """Pi-hole's own words for an error."""
    try:
        body = r.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return f"HTTP {r.status_code}"
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        parts = [str(err.get(k)) for k in ("message", "hint") if err.get(k)]
        if parts:
            return " — ".join(parts)
    return f"HTTP {r.status_code}"
