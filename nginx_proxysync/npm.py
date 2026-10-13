"""Small Nginx Proxy Manager API client with sanitized errors."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class NpmApiError(RuntimeError):
    """An API error that never contains response bodies or submitted secrets."""


class NpmClient:
    def __init__(self, base_url: str, username: str, password: str, timeout: int = 20):
        parsed = urllib.parse.urlsplit(base_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Instance URL must be an absolute http:// or https:// URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Instance URL must not include credentials, a query, or a fragment")
        self.base_url = base_url.strip().rstrip("/")
        self.timeout = timeout
        self.token = ""
        auth = self._request(
            "POST",
            "tokens",
            data=json.dumps({"identity": username, "secret": password}).encode(),
        )
        token = auth.get("token") if isinstance(auth, dict) else None
        if not isinstance(token, str) or not token:
            raise NpmApiError("NPM did not return an access token")
        self.token = token

    def _request(
        self,
        method: str,
        path: str,
        *,
        data: bytes | None = None,
        content_type: str = "application/json",
        timeout: int | None = None,
    ) -> Any:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if data is not None:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(
            f"{self.base_url}/api/{path.lstrip('/')}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            raise NpmApiError(f"NPM returned HTTP {exc.code} for {method} {path}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise NpmApiError(f"Could not connect to NPM for {method} {path}") from None
        if not body:
            return None
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise NpmApiError(f"NPM returned invalid JSON for {method} {path}") from None

    def get(self, path: str) -> Any:
        return self._request("GET", path)

    def post(self, path: str, value: dict[str, Any], *, timeout: int | None = None) -> Any:
        return self._request("POST", path, data=json.dumps(value).encode(), timeout=timeout)

    def put(self, path: str, value: dict[str, Any]) -> Any:
        return self._request("PUT", path, data=json.dumps(value).encode())
