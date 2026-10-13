import unittest

from nginx_proxysync.sync import synchronize


class FakeNpm:
    def __init__(self, hosts=None, certificates=None, details=None):
        self.hosts = hosts or []
        self.certificates = certificates or []
        self.details = details or {}
        self.calls = []

    def get(self, path):
        self.calls.append(("GET", path))
        if path == "nginx/proxy-hosts":
            return self.hosts
        if path == "nginx/certificates":
            return self.certificates
        if path.startswith("nginx/certificates/"):
            return self.details.get(path.rsplit("/", 1)[1], {})
        raise AssertionError(path)

    def post(self, path, value):
        self.calls.append(("POST", path, value))
        return {"id": 101}

    def put(self, path, value):
        self.calls.append(("PUT", path, value))
        return {}

    def upload_certificate(self, value):
        self.calls.append(("UPLOAD", value))
        return {"id": 100}


def host(domains, **extra):
    return {
        "id": extra.pop("id", 1),
        "domain_names": domains,
        "forward_scheme": "http",
        "forward_host": "app",
        "forward_port": 8080,
        "ssl_forced": False,
        **extra,
    }


class SyncTests(unittest.TestCase):
    def test_preview_is_read_only_and_preserves_destination_only(self):
        source = FakeNpm(hosts=[host(["source.example"])])
        destination = FakeNpm(hosts=[host(["destination-only.example"])])
        result = synchronize(source, destination)
        self.assertEqual(result.planned, ["Create proxy host source.example"])
        self.assertFalse(any(call[0] in {"POST", "PUT", "UPLOAD"} for call in destination.calls))

    def test_apply_creates_and_updates_matching_host(self):
        source = FakeNpm(
            hosts=[
                host(["new.example"]),
                host(["existing.example"], forward_host="new-app"),
            ]
        )
        destination = FakeNpm(hosts=[host(["existing.example"], forward_host="old-app")])
        result = synchronize(source, destination, dry_run=False, sync_certificates=False)
        writes = [call for call in destination.calls if call[0] in {"POST", "PUT"}]
        self.assertEqual([call[0] for call in writes], ["POST", "PUT"])
        self.assertEqual(len(result.completed), 2)

    def test_certificate_material_is_not_returned_in_result(self):
        certificate = {"id": 7, "nice_name": "secure", "domain_names": ["secure.example"]}
        detail = {
            **certificate,
            "certificate": "certificate-pem",
            "certificate_key": "private-key-content",
        }
        source = FakeNpm(
            hosts=[host(["secure.example"], certificate_id=7)],
            certificates=[certificate],
            details={"7": detail},
        )
        destination = FakeNpm()
        result = synchronize(source, destination, dry_run=False)
        self.assertIn("private-key-content", str(destination.calls))
        self.assertNotIn("private-key-content", str(result.to_dict()))
        host_write = next(call for call in destination.calls if call[0] == "POST")
        self.assertEqual(host_write[2]["certificate_id"], 100)

    def test_access_list_host_is_skipped(self):
        source = FakeNpm(hosts=[host(["private.example"], access_list_id=4)])
        destination = FakeNpm()
        result = synchronize(source, destination, dry_run=False, sync_certificates=False)
        self.assertIn("access-list transfer is not supported", result.skipped[0])
        self.assertFalse(any(call[0] == "POST" for call in destination.calls))

    def test_host_with_certificate_is_skipped_when_certificate_sync_disabled(self):
        source = FakeNpm(hosts=[host(["secure.example"], certificate_id=44)])
        destination = FakeNpm()
        result = synchronize(
            source,
            destination,
            dry_run=False,
            sync_certificates=False,
        )
        self.assertTrue(any("certificate sync is disabled" in message for message in result.skipped))
        self.assertFalse(any(call[0] in {"POST", "PUT"} for call in destination.calls))

    def test_host_and_certificate_options_can_be_disabled(self):
        source = FakeNpm(hosts=[host(["source.example"])])
        destination = FakeNpm()
        result = synchronize(
            source,
            destination,
            sync_hosts=False,
            sync_certificates=False,
        )
        self.assertEqual(result.planned, [])
        self.assertFalse(source.calls)


if __name__ == "__main__":
    unittest.main()
