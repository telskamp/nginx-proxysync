"""Protected web interface; instance credentials are request-scoped."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import secrets
from pathlib import Path
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


PASSWORD_ITERATIONS = 600_000
ADMIN_FILE = "admin.json"


def _password_record(password: str) -> dict[str, str | int]:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
    return {
        "salt": salt.hex(),
        "password_hash": digest.hex(),
        "iterations": PASSWORD_ITERATIONS,
    }


def _verify_password(password: str, record: dict) -> bool:
    try:
        iterations = record["iterations"]
        salt = bytes.fromhex(record["salt"])
        expected = bytes.fromhex(record["password_hash"])
        if not isinstance(iterations, int) or not 100_000 <= iterations <= 2_000_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return secrets.compare_digest(actual, expected)
    except (KeyError, TypeError, ValueError):
        return False


def _valid_username(username: str) -> bool:
    return (
        1 <= len(username) <= 64
        and username == username.strip()
        and ":" not in username
        and all(ord(character) >= 32 and ord(character) != 127 for character in username)
    )


def _parse_form(environ) -> dict[str, str]:
    content_length = int(environ.get("CONTENT_LENGTH") or "0")
    if content_length < 0 or content_length > 1_000_000:
        raise ValueError("Invalid form size")
    raw = environ["wsgi.input"].read(content_length).decode("utf-8")
    return {
        key: entries[0]
        for key, entries in parse_qs(raw, keep_blank_values=True).items()
        if entries
    }


def create_app(data_dir: str | os.PathLike = "data", sync_runner: Callable = synchronize):
    data_path = Path(data_dir)
    admin_file = data_path / ADMIN_FILE
    csrf_token = secrets.token_urlsafe(32)

    def application(environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        if path == "/setup":
            if admin_file.exists():
                start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"Setup is already complete"]
            if method == "GET":
                body = (
                    "<p>Create the local administrator account used to sign in to this app. "
                    "Choose a unique username and a strong password of at least 12 characters.</p>"
                    f'<form method="post"><input type="hidden" name="csrf" value="{csrf_token}">'
                    '<label>Admin username <input name="username" type="text" maxlength="64" required autocomplete="username"></label>'
                    '<label>Password <input name="password" type="password" minlength="12" required autocomplete="new-password"></label>'
                    '<label>Confirm password <input name="password_confirm" type="password" minlength="12" required autocomplete="new-password"></label>'
                    '<button type="submit">Create admin account</button></form>'
                )
                start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
                return [_page(body)]
            if method != "POST":
                start_response("405 Method Not Allowed", [("Allow", "GET, POST")])
                return [b"Method not allowed"]
            try:
                values = _parse_form(environ)
            except (ValueError, UnicodeDecodeError, KeyError):
                start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"Invalid form submission"]
            if not secrets.compare_digest(values.get("csrf", ""), csrf_token):
                start_response("403 Forbidden", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"Invalid request token"]
            username = values.get("username", "")
            password = values.get("password", "")
            if not _valid_username(username):
                return _error(start_response, "Username must be 1-64 characters, with no colon or control characters.")
            if len(password) < 12:
                return _error(start_response, "Password must be at least 12 characters.")
            if password != values.get("password_confirm"):
                return _error(start_response, "The passwords do not match.")

            data_created = False
            try:
                data_path.mkdir(mode=0o700, parents=True, exist_ok=True)
                record = {"username": username, **_password_record(password)}
                descriptor = os.open(
                    admin_file,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                data_created = True
                with os.fdopen(descriptor, "w", encoding="utf-8") as account_file:
                    json.dump(record, account_file)
                    account_file.flush()
                    os.fsync(account_file.fileno())
            except FileExistsError:
                start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"Setup is already complete"]
            except OSError:
                if data_created:
                    admin_file.unlink(missing_ok=True)
                start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"Could not save the admin account. Check the persistent data volume."]

            body = (
                "<h2>Admin account created</h2>"
                "<p>Your account is ready. Return to the home page and sign in with the username "
                "and password you just created.</p><p><a href=\"/\">Go to sign in</a></p>"
            )
            start_response("201 Created", [("Content-Type", "text/html; charset=utf-8")])
            return [_page(body)]

        if not admin_file.exists():
            body = (
                "<p>No administrator account exists yet. Create one to secure this application.</p>"
                '<p><a href="/setup">Create the admin account</a></p>'
            )
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [_page(body)]

        try:
            scheme, supplied = environ.get("HTTP_AUTHORIZATION", "").split(" ", 1)
            decoded = base64.b64decode(supplied, validate=True).decode()
            username, password = decoded.split(":", 1)
            with admin_file.open(encoding="utf-8") as account_file:
                account = json.load(account_file)
            authenticated = (
                scheme.lower() == "basic"
                and isinstance(account, dict)
                and isinstance(account.get("username"), str)
                and secrets.compare_digest(username, account.get("username", ""))
                and _verify_password(password, account)
            )
        except (ValueError, UnicodeDecodeError, KeyError, TypeError):
            authenticated = False
        except (OSError, json.JSONDecodeError):
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Could not read the admin account. Check the persistent data volume."]

        if not authenticated:
            start_response("401 Unauthorized", [("WWW-Authenticate", 'Basic realm="NPM Sync"')])
            return [b"Authentication required"]

        if path != "/":
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Not found"]

        if method == "GET":
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

        if method != "POST":
            start_response("405 Method Not Allowed", [("Allow", "GET, POST")])
            return [b"Method not allowed"]
        try:
            values = _parse_form(environ)
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


def _error(start_response, message: str):
    start_response("400 Bad Request", [("Content-Type", "text/html; charset=utf-8")])
    return [_page(f"<p>{html.escape(message)}</p><p><a href=\"/setup\">Back to setup</a></p>")]
