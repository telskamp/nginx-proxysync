# Nginx Proxy Manager Sync

A Dockerized web app for previewing and applying configuration from one Nginx Proxy Manager (NPM) instance to another. This initial version transfers supported proxy hosts and their certificates. It preserves destination-only records and does not save source/destination NPM credentials.

## Install on CachyOS

Open a terminal and install Docker and Docker Compose:

```sh
sudo pacman -Syu docker docker-compose
sudo systemctl enable --now docker
sudo docker info
```

The last command should display Docker server information. Clone this app and start it:

```sh
git clone https://github.com/telskamp/nginx-proxysync.git
cd nginx-proxysync
cp .env.example .env
sudo docker compose up -d --build
sudo docker compose ps
```

Now open <http://127.0.0.1:8080> in your browser. On first run, click **Create the admin account**, choose a username and a password at least 12 characters long, and submit the form. Then sign in with the account you just created.

To stop the app, run `sudo docker compose down` from the `nginx-proxysync` directory. To start it again later, run `sudo docker compose up -d`. Keep the Docker volume when updating; it stores the admin account. Do not run `docker compose down -v` unless you intend to delete that account and reset setup.

The `sudo` prefix avoids changing CachyOS user-group permissions. Alternatively, you can add your user to the `docker` group, but membership in that group grants root-equivalent access; log out and back in after changing groups.

## Install on other systems with Docker Compose

Install Docker Engine and the Docker Compose plugin, then run:

```sh
git clone https://github.com/telskamp/nginx-proxysync.git
cd nginx-proxysync
cp .env.example .env
```

The optional `.env` setting controls which host interface publishes the UI:

```dotenv
NPM_SYNC_BIND_ADDRESS=127.0.0.1
```

Build and start:

```sh
docker compose up -d --build
docker compose ps
```

Open <http://127.0.0.1:8080>. On first use, the web interface asks you to create an admin username and password. Use a password of at least 12 characters. The account is stored in the persistent `npm-sync-data` Docker volume; its password is stored as a salted PBKDF2 hash, not plaintext. After setup, the browser asks you to sign in with the account you created. The setup page is disabled after the account is created.

The default host port is bound to localhost. Keep it that way until the first admin account is created; anyone who can reach the app before setup can claim the initial account. For remote access, set `NPM_SYNC_BIND_ADDRESS=0.0.0.0` and protect access with HTTPS, firewall rules, and a trusted reverse proxy. Do not expose the app over plain HTTP on an untrusted network: Basic Auth and form submissions are not encrypted without TLS.

To update, pull the latest source and run `docker compose up -d --build`. To stop it, run `docker compose down`. View service output with `docker compose logs`.

## Use the web interface

1. On first run, create the local administrator account in the setup page. On later visits, sign in with that account.
2. Enter the source and destination NPM base URLs and account credentials. Use URLs such as `https://npm.example.test`, without `/api`, URL credentials, query strings, or fragments.
3. Select proxy-host and certificate sync settings. Certificates are only processed along with proxy-host sync.
4. Click **Preview changes** first. Preview performs reads only. Review planned, unchanged, skipped, and failed entries.
5. Click **Apply changes** to re-read the current configurations and create or update supported records.

The administrator password is stored only as a salted password hash in the persistent app data volume. NPM passwords and API bearer tokens are not stored or shown in results. Certificate private keys are sent directly from source NPM to destination NPM when the source API returns them; result output does not contain certificate contents.

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

Each run's URLs, NPM credentials, proxy-host toggle, certificate toggle, and preview/apply action are entered in the web interface. NPM credentials are intentionally not persisted. The admin password hash is stored in the `npm-sync-data` volume so it survives container replacement.

| Variable | Default | Purpose |
|---|---|---|
| `NPM_SYNC_BIND_ADDRESS` | `127.0.0.1` | Host interface for the published port |

The container web port is `8080`. The named volume is `npm-sync-data`, mounted at `/data` in the container. **Do not remove this volume when updating the app.** Removing it deletes the admin account and causes first-run setup to appear again. To reset the admin account deliberately, stop the stack and remove the named volume with `docker compose down -v`; this erases all app account data.

## Run tests without Docker

Requires Python 3.10 or newer. No third-party runtime dependencies are needed.

```sh
python -m unittest discover -s tests -v
```
