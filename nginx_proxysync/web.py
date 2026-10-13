"""Protected web interface; instance credentials are request-scoped."""

from __future__ import annotations

import base64
import html
import json
import secrets
from typing import Callable
from urllib.parse import parse_qs

from .npm import NpmApiError, NpmClient
from .sync import synchronize


def _page(body: str) -> bytes:
    return (
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>NPM Sync</title><style>"
        "body{font:16px system-ui;max-width:760px;margin:3rem auto;padding:0 1rem;color:#202b35}"
        "label{display:block;margin:.8rem 0}input[type=url],input[type=text],input[type=password]"
        "{box-sizing:border-box;width:100%;padding:.55rem}fieldset{margin:1rem 0;padding:1rem}"
        "button{padding:.65rem 1rem;margin:.5rem .5rem .5rem 0}pre{white-space:pre-wrap;"
        "background:#f3f5f7;padding:1rem}small{color:#52606d}"
        "</style><body><h1>Nginx Proxy Manager Sync</h1>"
        f"{body}</body></html>"
    ).encode()


def create_app(ui_username: str, ui_password: str, sync_runner: Callable = synchronize):
    if not ui_username or not ui_password:
        raise ValueError("UI username and password are required")
    csrf_token = secrets.token_urlsafe(32)

    def application(environ, start_response):
        try:
            scheme, supplied = environ.get("HTTP_AUTHORIZATION", "").split(" ", 1)
            decoded = base64.b64decode(supplied, validate=True).decode()
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            scheme, username, password = "", "", ""
        if (
            scheme.lower() != "basic"
            or not secrets.compare_digest(username, ui_username)
            or not secrets.compare_digest(password, ui_password)
        ):
            start_response("401 Unauthorized", [("WWW-Authenticate", 'Basic realm="NPM Sync"')])
            return [b"Authentication required"]

        if environ.get("REQUEST_METHOD") == "GET":
            body = (
                "<p>Preview first. NPM credentials are used for this request only and are not saved.</p>"
                f'<form method="post"><input type="hidden" name="csrf" value="{csrf_token}">'
                "<fieldset><legend>Source instance</legend>"
                '<label>URL <input name="source_url" type="url" placeholder="https://npm-source.example" required></label>'
                '<label>Username <input name="source_user" type="text" required></label>'
                '<label>Password <input name="source_password" type="password" required></label></fieldset>'
                "<fieldset><legend>Destination instance</legend>"
                '<label>URL <input name="destination_url" type="url" placeholder="https://npm-destination.example" required></label>'
                '<label>Username <input name="destination_user" type="text" required></label>'
                '<label>Password <input name="destination_password" type="password" required></label></fieldset>'
                "<fieldset><legend>Sync settings</legend>"
                '<label><input type="checkbox" name="sync_hosts" value="yes" checked> '
                "Sync proxy hosts (create or update by domain)</label>"
                '<label><input type="checkbox" name="sync_certificates" value="yes" checked> '
                "Transfer supported source certificates and remap host references</label>"
                "<p>Preview is read-only. Apply re-reads the instances before writing. "
                "Destination-only records are always preserved.</p></fieldset>"
                '<button name="action" value="preview">Preview changes</button>'
                '<button name="action" value="apply">Apply changes</button></form>'
            )
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [_page(body)]

        if environ.get("REQUEST_METHOD") != "POST":
            start_response("405 Method Not Allowed", [("Allow", "GET, POST")])
            return [b"Method not allowed"]
        try:
            content_length = int(environ.get("CONTENT_LENGTH") or "0")
            if content_length < 0 or content_length > 1_000_000:
                raise ValueError
            raw = environ["wsgi.input"].read(content_length).decode("utf-8")
            values = {
                key: entries[0]
                for key, entries in parse_qs(raw, keep_blank_values=True).items()
                if entries
            }
        except (ValueError, UnicodeDecodeError, KeyError):
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Invalid form submission"]
        if not secrets.compare_digest(values.get("csrf", ""), csrf_token):
            start_response("403 Forbidden", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Invalid request token"]
        action = values.get("action")
        if action not in {"preview", "apply"}:
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Unknown action"]

        try:
            source = NpmClient(
                values.get("source_url", ""),
                values.get("source_user", ""),
                values.get("source_password", ""),
            )
            destination = NpmClient(
                values.get("destination_url", ""),
                values.get("destination_user", ""),
                values.get("destination_password", ""),
            )
            result = sync_runner(
                source,
                destination,
                dry_run=action == "preview",
                sync_hosts=values.get("sync_hosts") == "yes",
                sync_certificates=values.get("sync_certificates") == "yes",
            )
            title = "Preview" if result.dry_run else "Sync result"
            body = f"<h2>{title}</h2><pre>{html.escape(json.dumps(result.to_dict(), indent=2))}</pre>"
        except (NpmApiError, ValueError) as exc:
            body = f"<h2>Sync failed</h2><p>{html.escape(str(exc))}</p>"
        body += '<p><a href="/">Back to settings</a></p>'
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [_page(body)]

    return application
