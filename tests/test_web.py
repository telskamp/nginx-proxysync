import base64
import io
import re
import unittest
from urllib.parse import urlencode
from unittest.mock import patch

from nginx_proxysync.web import create_app


class WebTests(unittest.TestCase):
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

    def test_ui_requires_basic_auth(self):
        app = create_app("operator", "secret")
        response, _ = self.request(app)
        self.assertEqual(response["status"], "401 Unauthorized")

    def test_settings_are_authenticated_and_post_has_csrf(self):
        calls = []

        def runner(source, destination, **kwargs):
            calls.append(kwargs)
            return type(
                "Result",
                (),
                {"dry_run": kwargs["dry_run"], "to_dict": lambda self: {"planned": []}},
            )()

        app = create_app("operator", "secret", sync_runner=runner)
        auth = "Basic " + base64.b64encode(b"operator:secret").decode()
        response, page = self.request(app, authorization=auth)
        self.assertEqual(response["status"], "200 OK")
        self.assertIn("Sync proxy hosts", page)
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
            }
        )
        with patch("nginx_proxysync.web.NpmClient", side_effect=["source-client", "destination-client"]):
            response, result = self.request(app, "POST", body=body, authorization=auth)
        self.assertEqual(response["status"], "200 OK")
        self.assertIn("Preview", result)
        self.assertNotIn("source-secret", result)
        self.assertEqual(calls, [{"dry_run": True, "sync_hosts": True, "sync_certificates": True}])

    def test_post_rejects_missing_csrf_token(self):
        app = create_app("operator", "secret")
        auth = "Basic " + base64.b64encode(b"operator:secret").decode()
        response, _ = self.request(
            app,
            "POST",
            body=urlencode({"action": "apply"}),
            authorization=auth,
        )
        self.assertEqual(response["status"], "403 Forbidden")


if __name__ == "__main__":
    unittest.main()
