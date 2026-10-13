"""Preview and apply a conservative proxy-host/certificate synchronization."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

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
    "locations",
)
CERT_MATERIAL_FIELDS = ("certificate", "certificate_key", "intermediate_certificate")


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
    if domains:
        return domains
    name = record.get("nice_name")
    return (f"name:{str(name).strip().lower()}",) if name else ()


def _label(record: dict[str, Any], kind: str) -> str:
    domains = _domain_key(record)
    return ", ".join(domains) or f"{kind} {record.get('id', '?')}"


def _read_items(value: Any, kind: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise NpmApiError(f"NPM returned an invalid {kind} list")
    return value


def _host_payload(source: dict[str, Any]) -> dict[str, Any]:
    return {field: source[field] for field in HOST_FIELDS if field in source}


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
) -> SyncResult:
    result = SyncResult(dry_run=dry_run)
    hosts_src = _read_items(source.get("nginx/proxy-hosts"), "proxy host") if sync_hosts else []
    hosts_dst = _read_items(destination.get("nginx/proxy-hosts"), "proxy host") if sync_hosts else []

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
            continue
        try:
            detail = source.get(f"nginx/certificates/{source_id}")
        except NpmApiError as exc:
            result.errors.append(f"Certificate {label}: {exc}")
            continue
        if not isinstance(detail, dict) or not all(detail.get(field) for field in CERT_MATERIAL_FIELDS[:2]):
            result.skipped.append(
                f"Certificate {label}: source API did not expose certificate and private-key material"
            )
            continue
        if dry_run:
            result.planned.append(f"Create certificate {label}")
            pending_cert_ids.add(source_id)
            continue
        payload = {
            "nice_name": detail.get("nice_name", certificate.get("nice_name", "")),
            "provider": detail.get("provider", certificate.get("provider", "other")),
            "meta": detail.get("meta", certificate.get("meta") or {}),
            **{field: detail[field] for field in CERT_MATERIAL_FIELDS if detail.get(field)},
        }
        try:
            created = destination.upload_certificate(payload)
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

    destination_hosts = {
        _domain_key(host): host for host in hosts_dst if _domain_key(host)
    }
    for host in hosts_src:
        label = _label(host, "proxy host")
        key = _domain_key(host)
        if not key:
            result.skipped.append(f"Proxy host {label}: no domain names to match")
            continue
        if host.get("access_list_id"):
            result.skipped.append(f"Proxy host {label}: access-list transfer is not supported")
            continue
        payload = _host_payload(host)
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
