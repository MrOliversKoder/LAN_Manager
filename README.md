# LAN Manager

A small self-hosted inventory of the devices and services on your LAN, with a PIN-protected credentials store and a scheduled availability check.
Python (Flask) + SQLite + APScheduler. No external services, one container.

## How it fits `davidlor/python-git-app`

From the image's documentation: the container clones `GIT_REPOSITORY` (optionally `GIT_BRANCH`), pip-installs `requirements.txt`,
then runs the project root with `python .`, so this repo has `__main__.py` and `requirements.txt` at its top level.
Only `GIT_REPOSITORY` is required by the image; everything else below is this app's own configuration.

Things I could not verify from here (no Docker Hub access) - please check once:
1. **Container user and UID** for volume permissions: `docker run --rm --entrypoint id davidlor/python-git-app`
2. **Whether `ping` exists** in the image you pick: `docker run --rm --entrypoint which davidlor/python-git-app ping`. If not, use TCP checks for devices (the app records a clear error instead of crashing).
3. **Whether the image re-pulls the repo on restart.** Treat updates as "re-create the container" (see Update).

## Install

1. Push this folder to a Git repository the container can reach (HTTPS, or SSH key as per the image docs).
2. Generate an encryption key and store it in `.env` next to `docker-compose.yml`:
   `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` -> `LAN_ENCRYPTION_KEY=...`
3. Edit `GIT_REPOSITORY` and `TZ` in `docker-compose.yml`.
4. `mkdir data` and make it writable by the container user (UID from step 1 above, often 1000): `sudo chown 1000:1000 data`
5. `docker compose up -d`, then open `http://<host>:8080`. Logs: `docker compose logs -f`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `GIT_REPOSITORY`, `GIT_BRANCH` | - | Used by the base image |
| `LAN_DATA_DIR` | `./data` | Folder for the SQLite database (mount a volume here) |
| `LAN_ENCRYPTION_KEY` | - | Fernet key for stored passwords |
| `LAN_ENCRYPTION_KEY_FILE` | - | Alternative: path to a file with the key (Docker secret) |
| `LAN_PORT` / `LAN_HOST` | `8080` / `0.0.0.0` | Listen address |
| `LAN_LOG_LEVEL` | `INFO` | Logging level |
| `LAN_MAX_WORKERS` | `10` | Targets checked in parallel |
| `TZ` | system | Default timezone for the schedule (overridable in the UI) |

If no key is supplied, one is generated into `LAN_DATA_DIR/encryption.key` and a warning is logged. That works, but then the key sits beside the database;
set `LAN_ENCRYPTION_KEY` (or a secret file) for the separation you asked for.

## Update

Your data lives in the `./data` volume, so: `docker compose up -d --force-recreate` pulls the latest commit into a fresh container.
Schema changes are applied automatically on start (see Migrations).

## Using it

* **Devices / Services / Credentials** in the sidebar; the dashboard shows service tiles - click a name to open it in a new tab.
* **Monitoring** page: schedule (one or more times, weekdays, timezone), global timeouts/retries, "Run all checks now", overview.
  Per-device/service overrides (method, timeout, retries, retry delay, on/off) are on each edit page; blank = global default.
* **Device checks:** ICMP ping, or TCP port when the device blocks ping. **Service checks:** TCP connect; optionally also an HTTP request with an expected status (kept as a separate result).
  If the TCP check fails, the HTTP check is skipped and recorded as such. The online/offline dot reflects the ping/TCP result; HTTP shows next to it.
* **Retries:** the initial attempt plus N retries with the configured delay; every attempt is stored, the last is marked final and decides the status.
* **History** page lists all attempts with filters; entries older than the retention setting (default 90 days) are pruned after each run.

### Scheduler behaviour
* Runs inside the app process, independent of any browser. Jobs have fixed IDs and are rebuilt from SQLite on start, so restarts cannot create duplicates.
* Missed runs: if the app was down at a scheduled time, one catch-up run starts ~15 s after startup (not on a brand-new install).
* Only one run at a time; a manual click during a run is refused. On `docker stop`, pending retry waits are abandoned and the scheduler shuts down.

## Security model (be aware of what it does and does not do)
* Passwords: Fernet (AES-128-CBC + HMAC) encrypted before they reach SQLite. They are only returned by `POST /credentials/<id>/reveal`, which needs an unlocked session, and are never in lists, search, logs or HTML.
* PIN: hashed (Werkzeug scrypt/pbkdf2), 5 wrong tries = 60 s lockout, auto-lock after N minutes idle (Settings), manual "Lock credentials".
* The PIN gates the **UI**. Whoever holds both the database and the encryption key can decrypt everything, so back both up carefully and separately.
* Forgot the PIN? Stop the app and run `sqlite3 data/lan_manager.db "update settings set setting_value='' where setting_key='pin_hash'"`, then set a new PIN. Passwords stay readable because the key is unchanged.
* There is no login for the rest of the app (LAN-only, as specified). Do not expose port 8080 to the internet. POST requests are CSRF-protected.
* Plain HTTP on a LAN means the PIN and revealed passwords cross the network unencrypted; put it behind a reverse proxy with HTTPS if that matters.

## Backup and restore
Back up **both** `data/lan_manager.db` and the encryption key (env var or `data/encryption.key`).
* Backup (safe while running): `sqlite3 data/lan_manager.db ".backup 'backup-$(date +%F).db'"`
* Restore: `docker compose down`, replace `data/lan_manager.db` (delete any `-wal`/`-shm` files beside it), make sure `LAN_ENCRYPTION_KEY` is the same key, `docker compose up -d`.
  With a different key, everything works except revealing old passwords (the UI reports a decryption error).

## Migrations
`PRAGMA user_version` tracks the schema. New DB -> created at latest version. Existing DB -> before applying pending steps from `app/migrations.py` the file is copied to `lan_manager.db.bak-v<N>`.
To change the schema: edit `models.py` and append `(version, ["ALTER TABLE ..."])` to `MIGRATIONS`.

## Design decisions
* Service username/password fields from the spec are not stored on the service itself; they live in Credentials (encrypted, linked to the service and shown on its page behind the PIN), so no plaintext ever sits in the services table.
* Deleting a device deletes its services; credentials are kept and unlinked rather than destroyed. Deleting a managing service just clears the link.
* A single per-target "timeout" applies to whichever check type runs; global TCP and HTTP timeouts are separate.
* HTTPS certificates are not verified in health checks (typical for LAN self-signed certs).
* Timestamps are stored in UTC and displayed in the configured timezone.

## Layout
`__main__.py` (waitress server) - `app/` : `models`, `monitor` (checks + scheduler), `security`, `settings`, `validators`, `migrations`, `views_*`, `templates/`, `static/`.
