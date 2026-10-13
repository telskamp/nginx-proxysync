# Nginx Proxy Manager Sync

A Dockerized web app for previewing and applying configuration from one Nginx Proxy Manager (NPM) instance to another. This initial version transfers supported proxy hosts and their certificates. It preserves destination-only records and does not save source/destination NPM credentials.

## Install with Docker Compose

Install Docker Engine and the Docker Compose plugin, then run:

```sh
git clone https://github.com/telskamp/nginx-proxysync.git
cd nginx-proxysync
cp .env.example .env
```

Edit `.env` and set a unique UI username and strong password:

```dotenv
NPM_SYNC_UI_USER=sync-admin
NPM_SYNC_UI_PASSWORD=replace-with-a-long-random-password
NPM_SYNC_BIND_ADDRESS=127.0.0.1
```

Build and start:

```sh
docker compose up -d --build
docker compose ps
```

Open <http://127.0.0.1:8080> and sign in with the UI credentials from `.env`. The default host port is bound to localhost. For remote access, set `NPM_SYNC_BIND_ADDRESS=0.0.0.0` and protect access with HTTPS, firewall rules, and a trusted reverse proxy. Do not expose the app over plain HTTP on an untrusted network: Basic Auth and form submissions are not encrypted without TLS.

To update, pull the latest source and run `docker compose up -d --build`. To stop it, run `docker compose down`. View service output with `docker compose logs`.

## Use the web interface

1. Sign in using the local UI credentials configured in `.env`.
2. Enter the source and destination NPM base URLs and account credentials. Use URLs such as `https://npm.example.test`, without `/api`, URL credentials, query strings, or fragments.
3. Select proxy-host and certificate sync settings. Certificates are only processed along with proxy-host sync.
4. Click **Preview changes** first. Preview performs reads only. Review planned, unchanged, skipped, and failed entries.
5. Click **Apply changes** to re-read the current configurations and create or update supported records.

Passwords and API bearer tokens are not stored or shown in the result. Certificate private keys are sent directly from source NPM to destination NPM when the source API returns them; result output does not contain certificate contents.

## Supported scope and limitations

- Proxy hosts are matched using their normalized domain-name sets. Unmatched source hosts are created; matching hosts are updated.
- Domain, forwarding, SSL, location, and advanced configuration fields are copied where exposed by the API.
- Source certificates are reused at the destination by domain names (or name when domains are unavailable). Otherwise, the app attempts certificate upload if the source API returns certificate PEM and private-key material. Proxy hosts are updated to use the corresponding destination certificate IDs.
- A proxy host using an access list is skipped. Access-list IDs are instance-specific, and access-list transfer is not implemented.
- Destination-only proxy hosts and certificates are never deleted.
- Redirection/dead hosts, streams, access lists and their credentials, users, global settings, and arbitrary database state are not synced. Matching destination certificates are reused without comparing key material or expiration. If private key material is not available from the source API, the certificate and dependent proxy host are reported as skipped.
- NPM API behavior varies by release. The implementation assumes `POST /api/tokens` with `identity` and `secret`, bearer-token authentication, `/api/nginx/proxy-hosts`, and `/api/nginx/certificates`. Certificate upload uses the multipart fields supported by commonly deployed NPM versions. Test using your exact source and destination versions and check all errors/skips.

Use NPM accounts with only the permissions required for the sync. API errors are sanitized and omit response bodies, passwords, certificates, and private keys.

## Settings

Each run's URLs, NPM credentials, proxy-host toggle, certificate toggle, and preview/apply action are entered in the web interface. NPM credentials are intentionally not persisted. The local UI credentials and network binding are configured in `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `NPM_SYNC_UI_USER` | required | Local web UI username |
| `NPM_SYNC_UI_PASSWORD` | required | Local web UI password |
| `NPM_SYNC_BIND_ADDRESS` | `127.0.0.1` | Host interface for the published port |
The container web port is `8080`.

## Run tests without Docker

Requires Python 3.10 or newer. No third-party runtime dependencies are needed.

```sh
python -m unittest discover -s tests -v
```
