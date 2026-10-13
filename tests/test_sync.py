import unittest

from nginx_proxysync.sync import synchronize, synchronize_bidirectional


class FakeNpm:
    def __init__(
        self,
        hosts=None,
        certificates=None,
        details=None,
        access_lists=None,
        settings=None,
        dns_providers=None,
    ):
        self.hosts = hosts or []
        self.certificates = certificates or []
        self.details = details or {}
        self.access_lists = access_lists or []
        self.settings = settings or []
        self.dns_providers = dns_providers or []
        self.calls = []

    def get(self, path):
        self.calls.append(("GET", path))
        if path == "nginx/proxy-hosts":
            return self.hosts
        if path == "nginx/access-lists?expand=items,clients":
            return self.access_lists
        if path == "nginx/certificates":
            return self.certificates
        if path == "settings":
            return self.settings
        if path == "nginx/certificates/dns-providers":
            return self.dns_providers
        if path.startswith("nginx/certificates/"):
            return self.details.get(path.rsplit("/", 1)[1], {})
        raise AssertionError(path)

    def post(self, path, value, **kwargs):
        self.calls.append(("POST", path, value, kwargs))
        return {"id": 101}

    def put(self, path, value):
        self.calls.append(("PUT", path, value))
        return {}

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
    def test_bidirectional_conflicts_preserve_access_lists_and_settings(self):
        source = FakeNpm(
            hosts=[host(["private.example"], access_list_id=1)],
            access_lists=[
                {
                    "id": 1,
                    "name": "trusted",
                    "items": [],
                    "clients": [{"address": "10.0.0.0/8", "directive": "allow"}],
                }
            ],
            settings=[{"id": "default-site", "value": "404", "meta": {}}],
        )
        destination = FakeNpm(
            access_lists=[
                {
                    "id": 2,
                    "name": "trusted",
                    "items": [],
                    "clients": [{"address": "192.168.0.0/16", "directive": "allow"}],
                }
            ],
            settings=[{"id": "default-site", "value": "html", "meta": {}}],
        )

        result = synchronize(
            source,
            destination,
            dry_run=False,
            sync_certificates=False,
            conflict_on_difference=True,
        )

        self.assertTrue(any("Access list trusted: conflicting changes" in item for item in result.skipped))
        self.assertTrue(any("Setting default-site: conflicting changes" in item for item in result.skipped))
        self.assertTrue(any("Proxy host private.example: access list trusted is unavailable" in item for item in result.skipped))
        self.assertFalse(any(call[0] in {"POST", "PUT"} for call in destination.calls))

    def test_bidirectional_copies_missing_hosts_and_preserves_divergent_matches(self):
        left = FakeNpm(
            hosts=[
                host(["left-only.example"]),
                host(["shared.example"], forward_host="left-app"),
            ]
        )
        right = FakeNpm(
            hosts=[
                host(["right-only.example"]),
                host(["shared.example"], forward_host="right-app"),
            ]
        )

        result = synchronize_bidirectional(
            left,
            right,
            dry_run=False,
            sync_certificates=False,
            sync_access_lists=False,
            sync_settings=False,
        )

        left_writes = [call for call in left.calls if call[0] in {"POST", "PUT"}]
        right_writes = [call for call in right.calls if call[0] in {"POST", "PUT"}]
        self.assertEqual([call[1] for call in left_writes], ["nginx/proxy-hosts"])
        self.assertEqual([call[1] for call in right_writes], ["nginx/proxy-hosts"])
        self.assertTrue(any("left-only.example" in str(call) for call in right_writes))
        self.assertTrue(any("right-only.example" in str(call) for call in left_writes))
        self.assertFalse(any(call[0] == "PUT" for call in left_writes + right_writes))
        self.assertEqual(
            sum("conflicting changes" in item for item in result.skipped),
            2,
        )
        self.assertFalse(any("left-app" in item or "right-app" in item for item in result.to_dict()["skipped"]))

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
        certificate = {
            "id": 7,
            "provider": "other",
            "nice_name": "secure",
            "domain_names": ["secure.example"],
        }
        detail = {
            **certificate,
            "meta": {
                "certificate": "certificate-pem",
                "certificate_key": "private-key-content",
                "intermediate_certificate": "intermediate-pem",
            },
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
        certificate_write = next(
            call for call in destination.calls
            if call[0] == "POST" and call[1] == "nginx/certificates"
        )
        self.assertEqual(
            certificate_write[2]["meta"]["certificate"],
            "certificate-pem\nintermediate-pem",
        )
        self.assertNotIn("intermediate_certificate", certificate_write[2]["meta"])
        host_write = next(
            call for call in destination.calls
            if call[0] == "POST" and call[1] == "nginx/proxy-hosts"
        )
        self.assertEqual(host_write[2]["certificate_id"], 101)

    def test_access_lists_are_created_and_remapped_for_hosts(self):
        access_list = {
            "id": 4,
            "name": "trusted networks",
            "satisfy_any": True,
            "pass_auth": False,
            "items": [],
            "clients": [{"address": "192.168.1.0/24", "directive": "allow", "id": 2}],
        }
        source = FakeNpm(
            hosts=[host(["private.example"], access_list_id=4)],
            access_lists=[access_list],
        )
        destination = FakeNpm()
        result = synchronize(
            source,
            destination,
            dry_run=False,
            sync_certificates=False,
            sync_settings=False,
        )
        writes = [call for call in destination.calls if call[0] == "POST"]
        self.assertEqual([call[1] for call in writes], ["nginx/access-lists", "nginx/proxy-hosts"])
        self.assertEqual(writes[1][2]["access_list_id"], 101)
        self.assertEqual(writes[0][2]["clients"], [{"address": "192.168.1.0/24", "directive": "allow"}])
        self.assertIn("Created access list trusted networks", result.completed)

    def test_masked_access_list_password_skips_list_and_dependent_host(self):
        access_list = {
            "id": 4,
            "name": "web users",
            "satisfy_any": False,
            "pass_auth": False,
            "items": [{"username": "operator", "password": "", "hint": "o******"}],
            "clients": [],
        }
        source = FakeNpm(
            hosts=[host(["private.example"], access_list_id=4)],
            access_lists=[access_list],
        )
        destination = FakeNpm()
        result = synchronize(
            source,
            destination,
            dry_run=False,
            sync_certificates=False,
            sync_settings=False,
        )
        self.assertTrue(any("masks auth passwords" in entry for entry in result.skipped))
        self.assertTrue(any("access list web users is unavailable" in entry for entry in result.skipped))
        self.assertFalse(any(call[0] in {"POST", "PUT"} for call in destination.calls))
        self.assertNotIn("o******", str(result.to_dict()))

    def test_matching_access_list_updates_and_remaps_location_references(self):
        source_list = {
            "id": 4,
            "name": "trusted networks",
            "satisfy_any": True,
            "pass_auth": False,
            "items": [],
            "clients": [{"address": "192.168.1.0/24", "directive": "allow"}],
        }
        destination_list = {
            **source_list,
            "id": 77,
            "satisfy_any": False,
            "clients": [],
        }
        source = FakeNpm(
            hosts=[
                host(
                    ["private.example"],
                    locations=[{"path": "/admin", "access_list_id": 4}],
                )
            ],
            access_lists=[source_list],
        )
        destination = FakeNpm(access_lists=[destination_list])
        result = synchronize(
            source,
            destination,
            dry_run=False,
            sync_certificates=False,
            sync_settings=False,
        )
        access_update = next(
            call for call in destination.calls
            if call[0] == "PUT" and call[1] == "nginx/access-lists/77"
        )
        host_create = next(
            call for call in destination.calls
            if call[0] == "POST" and call[1] == "nginx/proxy-hosts"
        )
        self.assertEqual(access_update[2]["satisfy_any"], True)
        self.assertEqual(host_create[2]["locations"][0]["access_list_id"], 77)
        self.assertIn("Updated access list trusted networks", result.completed)

    def test_settings_are_previewed_then_updated_without_showing_values(self):
        secret_html = "<p>private home page configuration</p>"
        source = FakeNpm(
            settings=[{"id": "default-site", "value": "html", "meta": {"html": secret_html}}]
        )
        destination = FakeNpm(settings=[{"id": "default-site", "value": "404", "meta": {}}])
        preview = synchronize(
            source,
            destination,
            sync_hosts=False,
            sync_certificates=False,
            sync_access_lists=False,
        )
        self.assertIn("Update setting default-site", preview.planned)
        self.assertFalse(any(call[0] == "PUT" for call in destination.calls))
        self.assertNotIn(secret_html, str(preview.to_dict()))

        destination.calls.clear()
        applied = synchronize(
            source,
            destination,
            dry_run=False,
            sync_hosts=False,
            sync_certificates=False,
            sync_access_lists=False,
        )
        setting_write = next(call for call in destination.calls if call[0] == "PUT")
        self.assertEqual(setting_write[1], "settings/default-site")
        self.assertEqual(setting_write[2], {"value": "html", "meta": {"html": secret_html}})
        self.assertIn("Updated setting default-site", applied.completed)
        self.assertNotIn(secret_html, str(applied.to_dict()))

    def test_letsencrypt_dns_provider_settings_are_applied_without_leaking_credentials(self):
        credentials = "dns_example_token = secret-value"
        certificate = {
            "id": 8,
            "provider": "letsencrypt",
            "nice_name": "dns.example",
            "domain_names": ["dns.example"],
            "meta": {"dns_challenge": True, "dns_provider": "example"},
        }
        details = {
            "8": {
                **certificate,
                "meta": {
                    "dns_challenge": True,
                    "dns_provider": "example",
                    "dns_provider_credentials": credentials,
                    "propagation_seconds": 60,
                    "key_type": "ecdsa",
                },
            }
        }
        source = FakeNpm(
            hosts=[host(["dns.example"], certificate_id=8)],
            certificates=[certificate],
            details=details,
        )
        destination = FakeNpm(dns_providers=[{"id": "example", "name": "Example"}])
        result = synchronize(
            source,
            destination,
            dry_run=False,
            sync_access_lists=False,
            sync_settings=False,
        )
        cert_write = next(
            call for call in destination.calls
            if call[0] == "POST" and call[1] == "nginx/certificates"
        )
        self.assertEqual(cert_write[2]["meta"]["dns_provider"], "example")
        self.assertEqual(cert_write[2]["meta"]["dns_provider_credentials"], credentials)
        self.assertEqual(cert_write[3], {"timeout": 900})
        host_write = next(
            call for call in destination.calls
            if call[0] == "POST" and call[1] == "nginx/proxy-hosts"
        )
        self.assertEqual(host_write[2]["certificate_id"], 101)
        self.assertNotIn(credentials, str(result.to_dict()))

    def test_letsencrypt_dns_provider_missing_at_destination_skips_certificate(self):
        certificate = {
            "id": 8,
            "provider": "letsencrypt",
            "nice_name": "dns.example",
            "domain_names": ["dns.example"],
            "meta": {"dns_challenge": True},
        }
        detail = {
            **certificate,
            "meta": {
                "dns_challenge": True,
                "dns_provider": "missing",
                "dns_provider_credentials": "private",
            },
        }
        source = FakeNpm(
            hosts=[host(["dns.example"], certificate_id=8)],
            certificates=[certificate],
            details={"8": detail},
        )
        destination = FakeNpm(dns_providers=[{"id": "other", "name": "Other"}])
        result = synchronize(
            source,
            destination,
            dry_run=False,
            sync_access_lists=False,
            sync_settings=False,
        )
        self.assertTrue(any("DNS provider is not available at destination" in item for item in result.skipped))
        self.assertFalse(any(call[0] == "POST" for call in destination.calls))

    def test_dns_provider_settings_can_be_disabled(self):
        certificate = {
            "id": 8,
            "provider": "letsencrypt",
            "nice_name": "dns.example",
            "domain_names": ["dns.example"],
            "meta": {"dns_challenge": True},
        }
        source = FakeNpm(
            hosts=[host(["dns.example"], certificate_id=8)],
            certificates=[certificate],
            details={
                "8": {
                    **certificate,
                    "meta": {
                        "dns_challenge": True,
                        "dns_provider": "example",
                        "dns_provider_credentials": "private",
                    },
                }
            },
        )
        destination = FakeNpm()
        result = synchronize(
            source,
            destination,
            dry_run=False,
            sync_access_lists=False,
            sync_certificate_providers=False,
            sync_settings=False,
        )
        self.assertTrue(any("DNS provider sync is disabled" in item for item in result.skipped))
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
            sync_access_lists=False,
            sync_settings=False,
        )
        self.assertEqual(result.planned, [])
        self.assertFalse(source.calls)


if __name__ == "__main__":
    unittest.main()
