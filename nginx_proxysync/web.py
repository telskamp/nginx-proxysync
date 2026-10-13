"""Protected web interface with opt-in persistent scheduled credentials."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import secrets
import threading
import time
import uuid
from base64 import b64encode
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from .npm import NpmApiError, NpmClient
from .sync import synchronize, synchronize_bidirectional


def _page(body: str) -> bytes:
    logo = b64encode(LOGO_FILE.read_bytes()).decode("ascii")
    return (
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>NPM Sync</title><style>"
        "body{font:16px system-ui;max-width:760px;margin:3rem auto;padding:0 1rem;color:#202b35}"
        "header{display:flex;align-items:center;gap:1rem}header img{width:64px;height:64px}"
        "label{display:block;margin:.8rem 0}input[type=url],input[type=text],input[type=password]"
        "{box-sizing:border-box;width:100%;padding:.55rem}fieldset{margin:1rem 0;padding:1rem}"
        "button{padding:.65rem 1rem;margin:.5rem .5rem .5rem 0}pre{white-space:pre-wrap;"
        "background:#f3f5f7;padding:1rem}small{color:#52606d}"
        "</style><body><header>"
        f'<img src="data:image/svg+xml;base64,{logo}" alt="">'
        "<h1>Nginx Proxy Manager Sync</h1></header>"
        f"{body}</body></html>"
    ).encode()


PASSWORD_ITERATIONS = 600_000
ADMIN_FILE = "admin.json"
SCHEDULE_FILE = "schedule.json"
LOGO_FILE = Path(__file__).resolve().parent.parent / "assets" / "sync-mark.svg"


def _write_private_json(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary_path = path.with_suffix(".tmp")
    descriptor = os.open(
        temporary_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise


def _read_schedule(path: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8") as schedule_file:
            configuration = json.load(schedule_file)
    except FileNotFoundError:
        return None
    if not isinstance(configuration, dict):
        raise ValueError("Saved schedule has an invalid format")
    return configuration


def _sync_options(configuration: dict) -> dict[str, bool]:
    return {
        name: bool(configuration.get(name, True))
        for name in (
            "sync_hosts",
            "sync_certificates",
            "sync_access_lists",
            "sync_certificate_providers",
            "sync_settings",
        )
    }


def _sync_clients(configuration: dict):
    source = NpmClient(
        configuration.get("source_url", ""),
        configuration.get("source_user", ""),
        configuration.get("source_password", ""),
    )
    destination = NpmClient(
        configuration.get("destination_url", ""),
        configuration.get("destination_user", ""),
        configuration.get("destination_password", ""),
    )
    return source, destination


def _validate_schedule_config(configuration: dict) -> None:
    for prefix in ("source", "destination"):
        parsed = urlsplit(str(configuration.get(f"{prefix}_url", "")).strip())
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Instance URL must be an absolute http:// or https:// URL without credentials")
        _ = parsed.port
        if not configuration.get(f"{prefix}_user") or not configuration.get(f"{prefix}_password"):
            raise ValueError("Instance usernames and passwords are required")


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


def create_app(
    data_dir: str | os.PathLike = "data",
    sync_runner: Callable = synchronize,
    bidirectional_runner: Callable = synchronize_bidirectional,
    *,
    start_scheduler: bool = True,
    scheduler_poll_interval: float = 15,
):
    data_path = Path(data_dir)
    admin_file = data_path / ADMIN_FILE
    schedule_file = data_path / SCHEDULE_FILE
    csrf_token = secrets.token_urlsafe(32)
    schedule_lock = threading.Lock()
    run_lock = threading.Lock()
    scheduler_wakeup = threading.Event()
    scheduler_stop = threading.Event()

    def execute(configuration: dict, dry_run: bool = False):
        source, destination = _sync_clients(configuration)
        runner = (
            bidirectional_runner
            if configuration.get("sync_direction") == "bidirectional"
            else sync_runner
        )
        return runner(
            source,
            destination,
            dry_run=dry_run,
            **_sync_options(configuration),
        )

    def scheduled_sync_loop() -> None:
        while not scheduler_stop.is_set():
            scheduler_wakeup.wait(scheduler_poll_interval)
            scheduler_wakeup.clear()
            if scheduler_stop.is_set():
                break
            try:
                with schedule_lock:
                    configuration = _read_schedule(schedule_file)
            except (OSError, ValueError, json.JSONDecodeError):
                print("Scheduled sync could not read its saved configuration.", flush=True)
                continue
            if configuration is None or configuration.get("next_run_at", 0) > time.time():
                continue
            if not run_lock.acquire(blocking=False):
                continue
            try:
                with schedule_lock:
                    current = _read_schedule(schedule_file)
                if current is None or current.get("schedule_id") != configuration.get("schedule_id"):
                    continue
                configuration = current
                try:
                    result = execute(configuration)
                    status = {"last_result": result.to_dict(), "last_error": ""}
                except (NpmApiError, ValueError) as exc:
                    status = {"last_result": None, "last_error": str(exc)}
                try:
                    with schedule_lock:
                        current = _read_schedule(schedule_file)
                        if current is None or current.get("schedule_id") != configuration.get("schedule_id"):
                            continue
                        current.update(status)
                        current["last_run_at"] = int(time.time())
                        current["next_run_at"] = int(
                            time.time() + current["interval_minutes"] * 60
                        )
                        _write_private_json(schedule_file, current)
                except (OSError, ValueError, json.JSONDecodeError):
                    print("Scheduled sync could not update its saved status.", flush=True)
            finally:
                run_lock.release()

    if start_scheduler:
        threading.Thread(
            target=scheduled_sync_loop,
            name="npm-sync-scheduler",
            daemon=True,
        ).start()

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
            try:
                schedule = _read_schedule(schedule_file)
            except (OSError, ValueError, json.JSONDecodeError):
                start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"Could not read the saved schedule. Check the persistent data volume."]
            schedule_status = (
                "<p><strong>Scheduled sync is enabled.</strong> "
                f"Runs every {schedule.get('interval_minutes')} minutes. "
                f"Mode: {html.escape(schedule.get('sync_direction', 'one_way'))}. "
                "Saved credentials are stored in the protected app data volume.</p>"
                if schedule
                else "<p>No scheduled sync is enabled.</p>"
            )
            schedule_options = schedule or {}
            sync_hosts_checked = schedule_options.get("sync_hosts", True)
            sync_certificates_checked = schedule_options.get("sync_certificates", True)
            sync_access_lists_checked = schedule_options.get("sync_access_lists", True)
            sync_providers_checked = schedule_options.get("sync_certificate_providers", True)
            sync_settings_checked = schedule_options.get("sync_settings", True)
            direction = schedule_options.get("sync_direction", "one_way")
            if schedule and schedule.get("last_error"):
                schedule_status += f"<p>Last scheduled run failed: {html.escape(schedule['last_error'])}</p>"
            if schedule and schedule.get("last_result"):
                schedule_status += (
                    "<p>Last scheduled result:</p><pre>"
                    f"{html.escape(json.dumps(schedule['last_result'], indent=2))}</pre>"
                )
            body = (
                "<p>Preview first. Credentials entered for a manual run are not saved. "
                "Enabling unattended scheduling stores them in the protected persistent volume.</p>"
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
                f'<label><input type="checkbox" name="sync_hosts" value="yes"{" checked" if sync_hosts_checked else ""}> '
                "Sync proxy hosts (create or update by domain)</label>"
                f'<label><input type="checkbox" name="sync_certificates" value="yes"{" checked" if sync_certificates_checked else ""}> '
                "Transfer supported source certificates and remap host references</label>"
                f'<label><input type="checkbox" name="sync_access_lists" value="yes"{" checked" if sync_access_lists_checked else ""}> '
                "Sync access lists and remap host references (lists with masked passwords are skipped)</label>"
                f'<label><input type="checkbox" name="sync_certificate_providers" value="yes"{" checked" if sync_providers_checked else ""}> '
                "Sync supported certificate provider and DNS challenge settings (contains provider credentials)</label>"
                f'<label><input type="checkbox" name="sync_settings" value="yes"{" checked" if sync_settings_checked else ""}> '
                "Sync NPM settings that exist on both instances</label>"
                '<label>Direction <select name="sync_direction">'
                f'<option value="one_way"{" selected" if direction == "one_way" else ""}>One way (source to destination)</option>'
                f'<option value="bidirectional"{" selected" if direction == "bidirectional" else ""}>Bidirectional (copy missing items both ways)</option>'
                "</select></label>"
                "<p>Preview is read-only. Apply re-reads the instances before writing. "
                "Destination-only records are always preserved. Provider credentials are sent directly "
                "from source NPM to destination NPM and are not included in results. Bidirectional "
                "sync reports differing matching records as conflicts and leaves them unchanged.</p></fieldset>"
                '<button name="action" value="preview">Preview changes</button>'
                '<button name="action" value="apply">Apply changes</button>'
                "<fieldset><legend>Schedule</legend>"
                f"{schedule_status}"
                '<label><input type="checkbox" name="schedule_enabled" value="yes"'
                f'{" checked" if schedule else ""}> Enable recurring sync</label>'
                '<label>Run every (minutes) <input name="interval_minutes" type="number" '
                f'min="5" max="10080" value="{schedule.get("interval_minutes", 60) if schedule else 60}" required></label>'
                '<p>Enabling a schedule saves the NPM usernames and passwords in the protected '
                "persistent app data volume so runs can continue unattended. Scheduled runs apply "
                "changes without preview. Credentials are never displayed; re-enter them when saving "
                "a schedule change. Use the disable button to remove saved credentials.</p>"
                '<button name="action" value="save_schedule">Save schedule settings</button>'
                '<button name="action" value="disable_schedule" formnovalidate>Disable schedule and remove saved credentials</button>'
                "</fieldset></form>"
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
        if action not in {"preview", "apply", "save_schedule", "disable_schedule"}:
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Unknown action"]

        configuration = {
            "source_url": values.get("source_url", ""),
            "source_user": values.get("source_user", ""),
            "source_password": values.get("source_password", ""),
            "destination_url": values.get("destination_url", ""),
            "destination_user": values.get("destination_user", ""),
            "destination_password": values.get("destination_password", ""),
            "sync_direction": values.get("sync_direction", "one_way"),
            **{
                name: values.get(name) == "yes"
                for name in (
                    "sync_hosts",
                    "sync_certificates",
                    "sync_access_lists",
                    "sync_certificate_providers",
                    "sync_settings",
                )
            },
        }
        if configuration["sync_direction"] not in {"one_way", "bidirectional"}:
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            return [b"Unknown sync direction"]

        if action in {"save_schedule", "disable_schedule"}:
            if action == "disable_schedule" or values.get("schedule_enabled") != "yes":
                try:
                    with run_lock:
                        with schedule_lock:
                            schedule_file.unlink(missing_ok=True)
                            schedule_file.with_suffix(".tmp").unlink(missing_ok=True)
                            scheduler_wakeup.set()
                except OSError:
                    start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
                    return [b"Could not remove the saved schedule. Check the persistent data volume."]
                body = "<h2>Schedule disabled</h2><p>Saved NPM credentials were removed.</p>"
            else:
                try:
                    interval_minutes = int(values.get("interval_minutes", ""))
                    if not 5 <= interval_minutes <= 10080:
                        raise ValueError
                    _validate_schedule_config(configuration)
                    configuration.update(
                        {
                            "schedule_id": uuid.uuid4().hex,
                            "interval_minutes": interval_minutes,
                            "next_run_at": int(time.time() + interval_minutes * 60),
                            "last_run_at": None,
                            "last_result": None,
                            "last_error": "",
                        }
                    )
                    with schedule_lock:
                        _write_private_json(schedule_file, configuration)
                    scheduler_wakeup.set()
                except (NpmApiError, ValueError):
                    return _error(start_response, "Enter valid NPM URLs, credentials, and an interval from 5 to 10080 minutes.")
                except OSError:
                    start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
                    return [b"Could not save the schedule. Check the persistent data volume."]
                body = (
                    "<h2>Schedule saved</h2><p>Recurring sync is enabled. "
                    "The first run will start after the selected interval.</p>"
                )
            body += '<p><a href="/">Back to settings</a></p>'
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
            return [_page(body)]

        try:
            with run_lock:
                result = execute(configuration, dry_run=action == "preview")
            title = "Preview" if result.dry_run else "Sync result"
            body = f"<h2>{title}</h2><pre>{html.escape(json.dumps(result.to_dict(), indent=2))}</pre>"
        except (NpmApiError, ValueError) as exc:
            body = f"<h2>Sync failed</h2><p>{html.escape(str(exc))}</p>"
        body += '<p><a href="/">Back to settings</a></p>'
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [_page(body)]

    application.stop_scheduler = scheduler_stop.set
    return application


def _error(start_response, message: str):
    start_response("400 Bad Request", [("Content-Type", "text/html; charset=utf-8")])
    return [_page(f"<p>{html.escape(message)}</p><p><a href=\"/setup\">Back to setup</a></p>")]
