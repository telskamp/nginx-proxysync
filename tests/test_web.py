import base64
import io
import json
import os
import re
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode
from unittest.mock import patch

from nginx_proxysync.web import create_app


class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.data_dir = self.temp_dir.name

    def request(self, app, method="GET", path="/", body="", authorization=None):
        captured = {}
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body.encode())),
            "wsgi.input": io.BytesIO(body.encode()),
        }
        if authorization:
            environ["HTTP_AUTHORIZATION"] = authorization

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        response = b"".join(app(environ, start_response)).decode()
        return captured, response

    @staticmethod
    def basic_auth(username="operator", password="operator-password"):
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return f"Basic {token}"

    def create_admin(self, app, username="operator", password="operator-password"):
        response, page = self.request(app, path="/setup")
        self.assertEqual(response["status"], "200 OK")
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        response, result = self.request(
            app,
            "POST",
            "/setup",
            urlencode(
                {
                    "csrf": csrf,
                    "username": username,
                    "password": password,
                    "password_confirm": password,
                }
            ),
        )
        self.assertEqual(response["status"], "201 Created", result)

    def test_first_visit_offers_account_setup_without_authentication(self):
        app = create_app(self.data_dir, start_scheduler=False)
        response, page = self.request(app)
        self.assertEqual(response["status"], "200 OK")
        self.assertIn("Create the admin account", page)
        self.assertFalse(os.path.exists(os.path.join(self.data_dir, "admin.json")))

    def test_setup_persists_only_password_hash_and_is_one_time(self):
        app = create_app(self.data_dir, start_scheduler=False)
        self.create_admin(app)
        account_path = os.path.join(self.data_dir, "admin.json")
        with open(account_path, encoding="utf-8") as account_file:
            account = json.load(account_file)
        self.assertEqual(account["username"], "operator")
        self.assertNotIn("operator-password", str(account))
        self.assertEqual(os.stat(account_path).st_mode & 0o777, 0o600)

        response, _ = self.request(app, path="/setup")
        self.assertEqual(response["status"], "404 Not Found")
        response, _ = self.request(
            app,
            "POST",
            "/setup",
            urlencode({"username": "attacker"}),
        )
        self.assertEqual(response["status"], "404 Not Found")

    def test_admin_account_survives_app_restart_and_authenticates(self):
        self.create_admin(create_app(self.data_dir, start_scheduler=False))
        restarted_app = create_app(self.data_dir, start_scheduler=False)
        response, page = self.request(restarted_app, authorization=self.basic_auth())
        self.assertEqual(response["status"], "200 OK")
        self.assertIn("Sync proxy hosts", page)
        self.assertIn("Sync access lists", page)
        self.assertIn("certificate provider and DNS challenge settings", page)
        self.assertIn("Sync NPM settings", page)
        self.assertIn("Bidirectional", page)
        self.assertIn("Enable recurring sync", page)
        response, _ = self.request(
            restarted_app,
            authorization=self.basic_auth(password="wrong-password"),
        )
        self.assertEqual(response["status"], "401 Unauthorized")

    def test_setup_requires_strong_matching_password_and_valid_username(self):
        app = create_app(self.data_dir, start_scheduler=False)
        _, page = self.request(app, path="/setup")
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        for fields in (
            {"username": "admin", "password": "short", "password_confirm": "short"},
            {
                "username": "admin",
                "password": "long-enough-password",
                "password_confirm": "different-password",
            },
            {
                "username": "admin:root",
                "password": "long-enough-password",
                "password_confirm": "long-enough-password",
            },
        ):
            response, _ = self.request(
                app,
                "POST",
                "/setup",
                urlencode({"csrf": csrf, **fields}),
            )
            self.assertEqual(response["status"], "400 Bad Request")
        self.assertFalse(os.path.exists(os.path.join(self.data_dir, "admin.json")))

    def test_setup_rejects_invalid_csrf(self):
        app = create_app(self.data_dir, start_scheduler=False)
        response, _ = self.request(
            app,
            "POST",
            "/setup",
            urlencode(
                {
                    "csrf": "invalid",
                    "username": "operator",
                    "password": "operator-password",
                    "password_confirm": "operator-password",
                }
            ),
        )
        self.assertEqual(response["status"], "403 Forbidden")

    def test_sync_form_requires_admin_auth_and_csrf(self):
        calls = []

        def runner(source, destination, **kwargs):
            calls.append(kwargs)
            return type(
                "Result",
                (),
                {"dry_run": kwargs["dry_run"], "to_dict": lambda self: {"planned": []}},
            )()

        app = create_app(self.data_dir, sync_runner=runner, start_scheduler=False)
        self.create_admin(app)
        auth = self.basic_auth()
        response, page = self.request(app, authorization=auth)
        self.assertEqual(response["status"], "200 OK")
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        body = urlencode(
            {
                "csrf": csrf,
                "action": "preview",
                "source_url": "https://source.example",
                "source_user": "source-user",
                "source_password": "source-secret",
                "destination_url": "https://destination.example",
                "destination_user": "dest-user",
                "destination_password": "dest-secret",
                "sync_hosts": "yes",
                "sync_certificates": "yes",
                "sync_access_lists": "yes",
                "sync_certificate_providers": "yes",
                "sync_settings": "yes",
            }
        )
        with patch(
            "nginx_proxysync.web.NpmClient",
            side_effect=["source-client", "destination-client"],
        ):
            response, result = self.request(app, "POST", body=body, authorization=auth)
        self.assertEqual(response["status"], "200 OK")
        self.assertIn("Preview", result)
        self.assertNotIn("source-secret", result)
        self.assertEqual(
            calls,
            [
                {
                    "dry_run": True,
                    "sync_hosts": True,
                    "sync_certificates": True,
                    "sync_access_lists": True,
                    "sync_certificate_providers": True,
                    "sync_settings": True,
                }
            ],
        )
        response, _ = self.request(app, authorization=None)
        self.assertEqual(response["status"], "401 Unauthorized")
        response, _ = self.request(
            app,
            "POST",
            body=urlencode({"action": "apply"}),
            authorization=auth,
        )
        self.assertEqual(response["status"], "403 Forbidden")

    def test_scheduled_configuration_persists_credentials_with_private_permissions(self):
        app = create_app(self.data_dir, start_scheduler=False)
        self.create_admin(app)
        auth = self.basic_auth()
        _, page = self.request(app, authorization=auth)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        body = urlencode(
            {
                "csrf": csrf,
                "action": "save_schedule",
                "source_url": "https://source.example",
                "source_user": "source-user",
                "source_password": "source-secret",
                "destination_url": "https://destination.example",
                "destination_user": "destination-user",
                "destination_password": "destination-secret",
                "sync_direction": "bidirectional",
                "sync_hosts": "yes",
                "sync_certificates": "yes",
                "sync_access_lists": "yes",
                "sync_certificate_providers": "yes",
                "sync_settings": "yes",
                "schedule_enabled": "yes",
                "interval_minutes": "60",
            }
        )
        response, result = self.request(app, "POST", body=body, authorization=auth)
        self.assertEqual(response["status"], "200 OK")
        self.assertNotIn("source-secret", result)
        self.assertNotIn("destination-secret", result)
        schedule_path = os.path.join(self.data_dir, "schedule.json")
        self.assertEqual(os.stat(schedule_path).st_mode & 0o777, 0o600)
        with open(schedule_path, encoding="utf-8") as schedule_file:
            schedule = json.load(schedule_file)
        self.assertEqual(schedule["source_password"], "source-secret")
        self.assertEqual(schedule["destination_password"], "destination-secret")
        self.assertEqual(schedule["sync_direction"], "bidirectional")
        self.assertEqual(schedule["interval_minutes"], 60)

        response, page = self.request(app, authorization=auth)
        self.assertEqual(response["status"], "200 OK")
        self.assertIn("Scheduled sync is enabled", page)
        self.assertIn("Mode: bidirectional", page)
        self.assertIn("Disable schedule and remove saved credentials", page)
        self.assertNotIn("source-secret", page)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        response, result = self.request(
            app,
            "POST",
            body=urlencode({"csrf": csrf, "action": "disable_schedule"}),
            authorization=auth,
        )
        self.assertEqual(response["status"], "200 OK")
        self.assertIn("Saved NPM credentials were removed", result)
        self.assertFalse(os.path.exists(schedule_path))

    def test_due_schedule_runs_bidirectional_sync(self):
        called = threading.Event()
        invocations = []

        class Result:
            dry_run = False

            def to_dict(self):
                return {"completed": ["scheduled"]}

        def runner(source, destination, **kwargs):
            invocations.append(kwargs)
            called.set()
            return Result()

        app = create_app(
            self.data_dir,
            sync_runner=runner,
            bidirectional_runner=runner,
            scheduler_poll_interval=0.01,
        )
        self.create_admin(app)
        auth = self.basic_auth()
        _, page = self.request(app, authorization=auth)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        body = urlencode(
            {
                "csrf": csrf,
                "action": "save_schedule",
                "source_url": "https://source.example",
                "source_user": "source-user",
                "source_password": "source-secret",
                "destination_url": "https://destination.example",
                "destination_user": "destination-user",
                "destination_password": "destination-secret",
                "sync_direction": "bidirectional",
                "schedule_enabled": "yes",
                "interval_minutes": "5",
            }
        )
        response, _ = self.request(app, "POST", body=body, authorization=auth)
        self.assertEqual(response["status"], "200 OK")
        schedule_path = os.path.join(self.data_dir, "schedule.json")
        with open(schedule_path, encoding="utf-8") as schedule_file:
            schedule = json.load(schedule_file)
        schedule["next_run_at"] = 0
        with open(schedule_path, "w", encoding="utf-8") as schedule_file:
            json.dump(schedule, schedule_file)

        with patch(
            "nginx_proxysync.web.NpmClient",
            side_effect=["source-client", "destination-client"],
        ):
            self.assertTrue(called.wait(2), "scheduler did not run the due job")
        self.assertEqual(len(invocations), 1)
        self.assertFalse(invocations[0]["dry_run"])
        deadline = time.monotonic() + 2
        updated_schedule = {}
        while time.monotonic() < deadline:
            with open(schedule_path, encoding="utf-8") as schedule_file:
                updated_schedule = json.load(schedule_file)
            if updated_schedule.get("last_result"):
                break
            time.sleep(0.01)
        self.assertEqual(updated_schedule["last_result"], {"completed": ["scheduled"]})


if __name__ == "__main__":
    unittest.main()
