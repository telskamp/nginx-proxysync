"""Preview and apply a conservative proxy-host/certificate synchronization."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import quote

from .npm import NpmApiError, NpmClient

HOST_FIELDS = (
    "domain_names",
    "forward_scheme",
    "forward_host",
    "forward_port",
    "access_list_id",
    "certificate_id",
    "ssl_forced",
    "caching_enabled",
    "block_exploits",
    "advanced_config",
    "allow_websocket_upgrade",
    "http2_support",
    "hsts_enabled",
    "hsts_subdomains",
    "trust_forwarded_proto",
    "enabled",
    "locations",
)


@dataclass
class SyncResult:
    dry_run: bool
    planned: list[str] = field(default_factory=list)
    completed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _domain_key(record: dict[str, Any]) -> tuple[str, ...]:
    domains = record.get("domain_names")
    if not isinstance(domains, list):
        return ()
    return tuple(sorted({str(domain).strip().lower() for domain in domains if str(domain).strip()}))


def _certificate_key(record: dict[str, Any]) -> tuple[str, ...]:
    domains = _domain_key(record)
    name = str(record.get("nice_name") or "").strip().lower()
    identity = domains or ((f"name:{name}",) if name else ())
    provider = str(record.get("provider") or "").strip().lower()
    if identity:
        return (f"provider:{provider}", *identity)
    return ()


def _label(record: dict[str, Any], kind: str) -> str:
    domains = _domain_key(record)
    return ", ".join(domains) or f"{kind} {record.get('id', '?')}"


def _read_items(value: Any, kind: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise NpmApiError(f"NPM returned an invalid {kind} list")
    return value


def _host_payload(source: dict[str, Any]) -> dict[str, Any]:
    return {field: source[field] for field in HOST_FIELDS if field in source}


def _access_list_payload(source: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(source.get("id"), int):
        return None
    items = source.get("items")
    clients = source.get("clients")
    if not isinstance(items, list) or not isinstance(clients, list):
        return None
    # NPM masks access-list passwords in API responses. Copying masked entries
    # would silently remove working credentials, so refuse lists with users.
    if items:
        return None
    clean_clients = []
    for client in clients:
        if not isinstance(client, dict) or not client.get("address"):
            return None
        clean_clients.append(
            {
                "address": client["address"],
                "directive": client.get("directive", "allow"),
            }
        )
    if not isinstance(source.get("name"), str) or not source["name"]:
        return None
    return {
        "name": source["name"],
        "satisfy_any": bool(source.get("satisfy_any", False)),
        "pass_auth": bool(source.get("pass_auth", False)),
        "items": [],
        "clients": clean_clients,
    }


def _setting_payload(setting: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(setting.get("id"), str) or not setting["id"]:
        return None
    if "value" not in setting or not isinstance(setting.get("meta"), dict):
        return None
    return {"value": setting["value"], "meta": setting["meta"]}


def _certificate_payload(
    source: dict[str, Any],
    detail: dict[str, Any],
    *,
    sync_certificate_providers: bool,
) -> dict[str, Any] | None:
    provider = detail.get("provider", source.get("provider"))
    domains = detail.get("domain_names", source.get("domain_names"))
    if provider not in {"letsencrypt", "other"} or not isinstance(domains, list):
        return None
    meta = detail.get("meta")
    if not isinstance(meta, dict):
        meta = source.get("meta")
    if not isinstance(meta, dict):
        meta = {}
    if provider == "letsencrypt":
        allowed_fields = {"dns_challenge", "propagation_seconds", "key_type"}
        if sync_certificate_providers:
            allowed_fields.update({"dns_provider", "dns_provider_credentials"})
        else:
            # DNS challenge issuance cannot work without its provider credentials.
            if meta.get("dns_challenge"):
                return None
        payload_meta = {key: meta[key] for key in allowed_fields if key in meta}
        if payload_meta.get("dns_challenge"):
            if not payload_meta.get("dns_provider") or not payload_meta.get("dns_provider_credentials"):
                return None
    else:
        certificate = meta.get("certificate", detail.get("certificate"))
        key = meta.get("certificate_key", detail.get("certificate_key"))
        intermediate = meta.get("intermediate_certificate", detail.get("intermediate_certificate"))
        if certificate and key:
            if intermediate and isinstance(certificate, str) and isinstance(intermediate, str):
                certificate = f"{certificate.rstrip()}\n{intermediate.lstrip()}"
            payload_meta = {"certificate": certificate, "certificate_key": key}
        else:
            payload_meta = {}
        if not payload_meta.get("certificate") or not payload_meta.get("certificate_key"):
            return None
    return {
        "provider": provider,
        "nice_name": detail.get("nice_name", source.get("nice_name", "")),
        "domain_names": domains,
        "meta": payload_meta,
    }


def _same_payload(current: dict[str, Any], desired: dict[str, Any]) -> bool:
    return all(
        json.dumps(current.get(key), sort_keys=True, separators=(",", ":"))
        == json.dumps(value, sort_keys=True, separators=(",", ":"))
        for key, value in desired.items()
    )


def synchronize(
    source: NpmClient,
    destination: NpmClient,
    *,
    dry_run: bool = True,
    sync_hosts: bool = True,
    sync_certificates: bool = True,
    sync_access_lists: bool = True,
    sync_certificate_providers: bool = True,
    sync_settings: bool = True,
) -> SyncResult:
    result = SyncResult(dry_run=dry_run)
    hosts_src = _read_items(source.get("nginx/proxy-hosts"), "proxy host") if sync_hosts else []
    hosts_dst = _read_items(destination.get("nginx/proxy-hosts"), "proxy host") if sync_hosts else []

    access_list_map: dict[Any, Any] = {}
    pending_access_list_ids: set[Any] = set()
    source_access_lists: list[dict[str, Any]] = []
    if sync_access_lists:
        try:
            source_access_lists = _read_items(
                source.get("nginx/access-lists?expand=items,clients"),
                "access list",
            )
            destination_access_lists = _read_items(
                destination.get("nginx/access-lists?expand=items,clients"),
                "access list",
            )
            destination_by_name = {
                str(item.get("name", "")).strip().casefold(): item
                for item in destination_access_lists
                if item.get("name")
            }
            for access_list in source_access_lists:
                source_id = access_list.get("id")
                label = str(access_list.get("name") or f"access list {source_id or '?'}")
                payload = _access_list_payload(access_list)
                if payload is None:
                    result.skipped.append(
                        f"Access list {label}: NPM masks auth passwords or omitted list entries; "
                        "the list cannot be copied safely"
                    )
                    continue
                current = destination_by_name.get(payload["name"].casefold())
                if current is not None:
                    if not isinstance(current.get("items"), list) or current["items"]:
                        result.skipped.append(
                            f"Access list {label}: destination contains masked auth passwords; "
                            "the list cannot be compared or updated safely"
                        )
                        continue
                    current_payload = _access_list_payload(current)
                    if current_payload is None:
                        result.skipped.append(
                            f"Access list {label}: destination entries were not returned by its API"
                        )
                        continue
                    if _same_payload(current_payload, payload):
                        access_list_map[source_id] = current.get("id")
                        result.unchanged.append(f"Access list {label}: already matches")
                        continue
                    result.planned.append(f"Update access list {label}")
                    if dry_run:
                        pending_access_list_ids.add(source_id)
                        continue
                    destination_id = current.get("id")
                    if destination_id is None:
                        result.errors.append(f"Access list {label}: destination record has no id")
                        continue
                    try:
                        destination.put(f"nginx/access-lists/{destination_id}", payload)
                        access_list_map[source_id] = destination_id
                        result.completed.append(f"Updated access list {label}")
                    except NpmApiError as exc:
                        result.errors.append(f"Access list {label}: {exc}")
                    continue

                result.planned.append(f"Create access list {label}")
                if dry_run:
                    pending_access_list_ids.add(source_id)
                    continue
                try:
                    created = destination.post("nginx/access-lists", payload)
                    destination_id = created.get("id") if isinstance(created, dict) else None
                    if destination_id is None:
                        result.errors.append(f"Access list {label}: create returned no identifiable record")
                        continue
                    access_list_map[source_id] = destination_id
                    result.completed.append(f"Created access list {label}")
                except NpmApiError as exc:
                    result.errors.append(f"Access list {label}: {exc}")
        except NpmApiError as exc:
            result.errors.append(f"Access lists: {exc}")

    certificates_src: list[dict[str, Any]] = []
    certificates_dst: list[dict[str, Any]] = []
    if sync_hosts and sync_certificates:
        certificates_src = _read_items(source.get("nginx/certificates"), "certificate")
        certificates_dst = _read_items(destination.get("nginx/certificates"), "certificate")

    destination_certs = {
        _certificate_key(certificate): certificate
        for certificate in certificates_dst
        if _certificate_key(certificate)
    }
    source_certs_by_id = {certificate.get("id"): certificate for certificate in certificates_src}
    cert_map: dict[Any, Any] = {}
    pending_cert_ids: set[Any] = set()
    destination_dns_providers: set[str] | None = None

    for certificate in certificates_src:
        source_id = certificate.get("id")
        label = _label(certificate, "certificate")
        key = _certificate_key(certificate)
        if not key:
            result.skipped.append(f"Certificate {label}: no domain name or certificate name to match")
            continue
        existing = destination_certs.get(key)
        if existing and existing.get("id") is not None:
            cert_map[source_id] = existing["id"]
            result.unchanged.append(f"Certificate {label}: matching destination certificate exists")
            if (
                sync_certificate_providers
                and certificate.get("provider") == "letsencrypt"
                and isinstance(certificate.get("meta"), dict)
                and certificate["meta"].get("dns_challenge")
            ):
                result.skipped.append(
                    f"Certificate {label}: existing certificate reused; DNS provider credentials "
                    "are not compared or replaced"
                )
            continue
        try:
            detail = source.get(f"nginx/certificates/{source_id}")
        except NpmApiError as exc:
            result.errors.append(f"Certificate {label}: {exc}")
            continue
        if not isinstance(detail, dict):
            result.skipped.append(
                f"Certificate {label}: source API did not return certificate details"
            )
            continue
        payload = _certificate_payload(
            certificate,
            detail,
            sync_certificate_providers=sync_certificate_providers,
        )
        if payload is None:
            source_meta = detail.get("meta")
            if not isinstance(source_meta, dict):
                source_meta = certificate.get("meta")
            if (
                certificate.get("provider") == "letsencrypt"
                and isinstance(source_meta, dict)
                and source_meta.get("dns_challenge")
                and not sync_certificate_providers
            ):
                reason = "DNS provider sync is disabled"
            else:
                reason = "required provider settings or certificate material were not exposed by the source API"
            result.skipped.append(f"Certificate {label}: {reason}")
            continue
        if payload["provider"] == "letsencrypt" and payload["meta"].get("dns_challenge"):
            if destination_dns_providers is None:
                try:
                    provider_list = _read_items(
                        destination.get("nginx/certificates/dns-providers"),
                        "DNS provider",
                    )
                    destination_dns_providers = {
                        str(provider.get("id"))
                        for provider in provider_list
                        if provider.get("id")
                    }
                except NpmApiError as exc:
                    result.errors.append(f"Certificate {label}: could not verify destination DNS provider: {exc}")
                    continue
            provider_id = str(payload["meta"].get("dns_provider") or "")
            if provider_id not in destination_dns_providers:
                result.skipped.append(
                    f"Certificate {label}: DNS provider is not available at destination"
                )
                continue
        if dry_run:
            result.planned.append(f"Create certificate {label}")
            pending_cert_ids.add(source_id)
            continue
        try:
            created = destination.post("nginx/certificates", payload, timeout=900)
            new_id = created.get("id") if isinstance(created, dict) else None
            if new_id is None:
                refreshed = _read_items(destination.get("nginx/certificates"), "certificate")
                match = next(
                    (item for item in refreshed if _certificate_key(item) == key),
                    None,
                )
                new_id = match.get("id") if match else None
            if new_id is None:
                result.errors.append(f"Certificate {label}: upload returned no identifiable record")
                continue
            cert_map[source_id] = new_id
            result.completed.append(f"Created certificate {label}")
        except NpmApiError as exc:
            result.errors.append(f"Certificate {label}: {exc}")

    if sync_settings:
        try:
            source_settings = _read_items(source.get("settings"), "setting")
            destination_settings = _read_items(destination.get("settings"), "setting")
            destination_by_id = {
                setting.get("id"): setting
                for setting in destination_settings
                if isinstance(setting.get("id"), str)
            }
            for setting in source_settings:
                setting_id = setting.get("id")
                label = str(setting_id or "unknown")
                payload = _setting_payload(setting)
                if payload is None:
                    result.skipped.append(f"Setting {label}: unsupported setting format")
                    continue
                current = destination_by_id.get(setting_id)
                if current is None:
                    result.skipped.append(f"Setting {label}: setting is not available at destination")
                    continue
                current_payload = _setting_payload(current)
                if current_payload == payload:
                    result.unchanged.append(f"Setting {label}: already matches")
                    continue
                result.planned.append(f"Update setting {label}")
                if not dry_run:
                    try:
                        destination.put(f"settings/{quote(setting_id, safe='')}", payload)
                        result.completed.append(f"Updated setting {label}")
                    except NpmApiError as exc:
                        result.errors.append(f"Setting {label}: {exc}")
        except NpmApiError as exc:
            result.errors.append(f"Settings: {exc}")

    destination_hosts = {
        _domain_key(host): host for host in hosts_dst if _domain_key(host)
    }
    for host in hosts_src:
        label = _label(host, "proxy host")
        key = _domain_key(host)
        if not key:
            result.skipped.append(f"Proxy host {label}: no domain names to match")
            continue
        payload = _host_payload(host)
        access_list_id = host.get("access_list_id")
        if access_list_id:
            mapped_access_list_id = access_list_map.get(access_list_id)
            if mapped_access_list_id is None and access_list_id in pending_access_list_ids and dry_run:
                payload["access_list_id"] = "<created from source access list>"
            elif mapped_access_list_id is None:
                source_list = next((item for item in source_access_lists if item.get("id") == access_list_id), None)
                list_label = source_list.get("name", access_list_id) if source_list else access_list_id
                result.skipped.append(
                    f"Proxy host {label}: access list {list_label} is unavailable at destination"
                )
                continue
            else:
                payload["access_list_id"] = mapped_access_list_id
        locations = payload.get("locations")
        location_blocked = False
        if isinstance(locations, list):
            remapped_locations = []
            for location in locations:
                if not isinstance(location, dict) or not location.get("access_list_id"):
                    remapped_locations.append(location)
                    continue
                location_copy = dict(location)
                source_list_id = location["access_list_id"]
                mapped_access_list_id = access_list_map.get(source_list_id)
                if mapped_access_list_id is None and source_list_id in pending_access_list_ids and dry_run:
                    location_copy["access_list_id"] = "<created from source access list>"
                elif mapped_access_list_id is None:
                    location_blocked = True
                    break
                else:
                    location_copy["access_list_id"] = mapped_access_list_id
                remapped_locations.append(location_copy)
            if location_blocked:
                result.skipped.append(
                    f"Proxy host {label}: a location access list is unavailable at destination"
                )
                continue
            payload["locations"] = remapped_locations
        source_cert_id = host.get("certificate_id")
        if source_cert_id:
            if not sync_certificates:
                result.skipped.append(
                    f"Proxy host {label}: certificate sync is disabled and the source certificate "
                    "ID cannot be used at the destination"
                )
                continue
            mapped_id = cert_map.get(source_cert_id)
            if mapped_id is not None:
                payload["certificate_id"] = mapped_id
            elif dry_run and source_cert_id in pending_cert_ids:
                payload["certificate_id"] = "<created from source certificate>"
            else:
                certificate = source_certs_by_id.get(source_cert_id)
                cert_label = _label(certificate, "certificate") if certificate else f"certificate {source_cert_id}"
                result.skipped.append(
                    f"Proxy host {label}: certificate {cert_label} is unavailable at destination"
                )
                continue

        current = destination_hosts.get(key)
        if current is None:
            result.planned.append(f"Create proxy host {label}")
            if not dry_run:
                try:
                    destination.post("nginx/proxy-hosts", payload)
                    result.completed.append(f"Created proxy host {label}")
                except NpmApiError as exc:
                    result.errors.append(f"Proxy host {label}: {exc}")
            continue
        if _same_payload(current, payload):
            result.unchanged.append(f"Proxy host {label}: already matches")
            continue
        result.planned.append(f"Update proxy host {label}")
        if not dry_run:
            destination_id = current.get("id")
            if destination_id is None:
                result.errors.append(f"Proxy host {label}: destination record has no id")
                continue
            try:
                destination.put(f"nginx/proxy-hosts/{destination_id}", payload)
                result.completed.append(f"Updated proxy host {label}")
            except NpmApiError as exc:
                result.errors.append(f"Proxy host {label}: {exc}")
    return result
