# Nginx Proxy Manager Sync

![Generic black-and-yellow configuration sync logo](assets/sync-mark.svg)

A self-hosted Docker web app for previewing, applying, scheduling, and bidirectionally syncing supported configuration between Nginx Proxy Manager (NPM) instances. The interface is protected by a local admin account created on first use.

## What it does

- **One-way sync:** copy supported items from the source instance to the destination. Existing matching proxy hosts and IP-only access lists are updated; destination-only items are preserved.
- **Bidirectional sync:** copy missing supported items in both directions. Matching proxy hosts, IP-only access lists, or shared settings that differ are reported as conflicts and left unchanged on both sides; the app does not guess which edit is newer.
- **Preview and apply:** preview is read-only. Apply rereads current NPM state and then creates or updates the selected records. Scheduled runs apply automatically without a preview.
- **Proxy hosts:** copy domain names, forwarding, SSL, locations, access-list references, and supported advanced options, remapping NPM IDs between instances.
- **Certificates:** reuse a matching destination certificate or create a supported Let’s Encrypt/custom certificate and remap host references. DNS challenge provider settings and credentials can be transferred for new certificate requests.
- **Access lists:** sync IP allow/deny lists and remap host/location references. Lists with username/password entries are skipped because NPM masks passwords in API responses.
- **NPM settings:** sync settings shared by ID. In bidirectional mode, divergent shared values are conflicts and are not changed.
- **Recurring schedule:** configure a run interval from 5 minutes to 7 days and review the latest run result in the UI. The first run occurs after the selected interval.
- **Secret handling:** manual NPM credentials are request-only. Scheduled credentials are persisted only when a schedule is explicitly enabled; details are in [Credential storage and security](#credential-storage-and-security).

This tool does not synchronize every NPM database entity. Check the [supported scope and limitations](#supported-scope-and-limitations) before using it with production instances.

## Install on CachyOS

Install Docker and Compose:

```sh
sudo pacman -Syu docker docker-compose
sudo systemctl enable --now docker
sudo docker info
```

Clone the repository and start the app:

```sh
git clone https://github.com/telskamp/nginx-proxysync.git
cd nginx-proxysync
cp .env.example .env
sudo docker compose up -d --build
sudo docker compose ps
```

Open <http://127.0.0.1:8080>. On first use, choose **Create the admin account**, then create a username and password of at least 12 characters. Sign in with that account afterward.

To stop the app, run `sudo docker compose down` in the project directory. Start it again with `sudo docker compose up -d`. Keep the `npm-sync-data` volume; it stores the admin account and optional schedule. Do not use `docker compose down -v` unless you intend to erase the volume and reset the app.

The `sudo` prefix avoids changing CachyOS user-group permissions. Adding your user to the `docker` group grants root-equivalent access.

## Install on other systems

Install Docker Engine and the Docker Compose plugin, then run:

```sh
git clone https://github.com/telskamp/nginx-proxysync.git
cd nginx-proxysync
cp .env.example .env
docker compose up -d --build
docker compose ps
```

Open <http://127.0.0.1:8080>. The default host binding is localhost. Keep it local until initial admin setup is complete. To update later, pull the repository and rebuild with `docker compose up -d --build`. Stop with `docker compose down`; view logs with `docker compose logs`.

For remote access, configure HTTPS through a trusted reverse proxy, firewall the service, and then set `NPM_SYNC_BIND_ADDRESS=0.0.0.0` in `.env`. Do not expose the web app over plain HTTP on an untrusted network: Basic Auth and form submissions are not encrypted without TLS.

## Use the web interface

1. Create the local admin account on first run and sign in.
2. Enter the source and destination NPM base URLs, usernames, and passwords. Use a base URL such as `https://npm.example.test`; do not append `/api` or include URL credentials, query strings, or fragments.
3. Choose **One way** or **Bidirectional**, and select which proxy host, certificate, access-list, certificate-provider, and shared-setting categories to sync.
4. Click **Preview changes** and review planned, unchanged, skipped, and failed items. Preview makes no NPM writes.
5. Click **Apply changes** to perform a manual sync. It reads the current NPM state again before writing.
6. For unattended runs, enable recurring sync, select an interval between 5 minutes and 7 days, and save the schedule. Re-enter the NPM credentials when saving a schedule; the UI never fills or displays saved passwords. Scheduled runs apply changes automatically. The UI shows the mode, interval, latest result, or the latest error. Use **Disable schedule and remove saved credentials** to turn it off.

For bidirectional sync, missing items are created on the other instance. Divergent matching proxy hosts, IP-only access lists, and settings are reported as conflicts and remain untouched on both instances. Existing matching certificates are reused by provider and domain/name; their private key, provider credentials, and expiry are not compared or replaced.

## Credential storage and security

- The admin password is stored as a salted PBKDF2 hash in the persistent Docker volume, not as plaintext. Initial account setup is disabled once an account exists.
- NPM credentials entered for a manual preview or apply are not saved by the app.
- Enabling a schedule stores the two NPM URLs, usernames, and passwords plus selected sync options in `/data/schedule.json`. The file is written with owner-only permissions (`0600`) inside an owner-only data directory (`0700`), but **the credentials are not encrypted**. Protect the Docker host, volume, and backups accordingly.
- The UI never displays stored NPM passwords. Disabling the schedule removes its configuration file and saved credentials.
- API tokens are used for the request and not persisted. Certificate private keys and DNS provider credentials may be sent directly to destination NPM when required; they are not included in result summaries.
- Use HTTPS to connect to NPM instances, use NPM accounts with only necessary permissions, and do not run multiple app replicas against the same schedule volume.

## Supported scope and limitations

- Proxy hosts are matched by normalized domain-name sets. Supported fields include domains, forwarding, SSL, location configuration, advanced configuration, and access-list/certificate references exposed by the NPM API.
- IP allow/deny access lists are matched by name. Password-auth lists are skipped because NPM masks their passwords in API responses. A host or location that requires an unavailable list is skipped rather than pointed at an incorrect ID.
- Certificates are matched by provider plus domain names (or name when domains are unavailable). Let’s Encrypt certificates are requested from destination NPM; DNS challenge configuration is included when enabled and the destination reports that provider as available. Issuance can take time and depends on DNS/domain validation and destination permissions. Custom certificates can be created only when the source API exposes certificate and private-key PEM material.
- Shared NPM settings are matched by setting ID. Settings absent at the destination are reported and not created. Review `default-site` changes carefully because it affects the destination's unknown-host response.
- Destination-only records are preserved; deletions are never propagated.
- Redirection/dead hosts, streams, password-auth access lists, users, certificate renewal history, and arbitrary database state are not synchronized. Matching destination certificates are reused without checking key material, provider credentials, or expiration. If required certificate material or provider data is unavailable, the certificate and dependent host are reported as skipped.
- NPM API behavior varies by version. The implementation assumes `POST /api/tokens` with `identity` and `secret`, bearer-token authentication, `/api/nginx/proxy-hosts`, `/api/nginx/access-lists`, `/api/nginx/certificates`, and `/api/settings`; access lists use `expand=items,clients`. DNS providers are queried at `/api/nginx/certificates/dns-providers`. Verify source and destination versions and review all skips/errors during preview and after applying.
- Scheduled execution runs in this app process. It requires the container to remain running and the persistent data volume to be mounted. Restarts retain the saved schedule and resume it.

## Configuration and data

| Setting | Default | Purpose |
|---|---|---|
| `NPM_SYNC_BIND_ADDRESS` | `127.0.0.1` | Host interface to which port 8080 is published |
| Container port | `8080` | Web interface |
| Docker volume | `npm-sync-data` mounted at `/data` | Admin account and optional schedule |

The app has no third-party Python runtime dependencies. To intentionally reset the admin account and schedule, stop the stack and remove the volume with `docker compose down -v`; this erases all app data and returns it to first-run setup.

## Run tests without Docker

Requires Python 3.10 or newer:

```sh
python -m unittest discover -s tests -v
```
