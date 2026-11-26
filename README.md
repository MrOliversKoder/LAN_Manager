# LAN Manager

Self-hosted inventory of the devices and services on your LAN, with logins and groups, a PIN-protected credentials store and scheduled availability checks.
Python (Flask) + SQLite + APScheduler, one container, only the web port exposed.

## Install (`davidlor/python-git-app`)
1. Push this folder to a Git repository the container can reach.
2. Put the repository URL in `docker-compose.yml` (`GIT_REPOSITORY`) and set `TZ`.
3. `docker compose up -d` and watch `docker compose logs -f` until you see `LAN Manager listening on http://0.0.0.0:8080`.
4. Open `http://<host>:8080`. The first page asks you to create the **administrator** account (or set `LAN_ADMIN_USER` / `LAN_ADMIN_PASSWORD` to create it at start-up).

The image clones the repo, installs `requirements.txt` and runs `python .`, so `__main__.py` and `requirements.txt` stay at the repo root.
All data (SQLite database and the generated encryption key) is stored in `/home/user/App/data` inside the container.

## Environment variables (all optional)
| Variable | Default | Purpose |
|---|---|---|
| `GIT_REPOSITORY`, `GIT_BRANCH` | - | Used by the base image |
| `LAN_ADMIN_USER`, `LAN_ADMIN_PASSWORD` | - | Create the first admin if no users exist |
| `LAN_ENCRYPTION_KEY` / `LAN_ENCRYPTION_KEY_FILE` | auto-generated file in the data folder | Key for stored passwords (Fernet) |
| `LAN_DATA_DIR` | `<app>/data` | Database folder |
| `LAN_PORT` / `LAN_HOST` | `8080` / `0.0.0.0` | Listen address |
| `LAN_SESSION_HOURS` | `12` | Login session length |
| `LAN_MAX_WORKERS` | `10` | Targets checked in parallel |
| `LAN_LOG_LEVEL` | `INFO` | Logging |
| `TZ` | system | Default schedule timezone |

## Users, groups and permissions
Everyone logs in. Each user belongs to one group; a group is a set of permissions. Only the **Administrator** group sees the **Admin** page (users and groups).

| Permission | Allows |
|---|---|
| View | Dashboard, devices, services, search |
| History | Monitoring history |
| Add | Create devices and services |
| Edit | Change devices and services |
| Delete | Delete devices and services |
| Run checks | "Run all checks now" |
| View credentials | Open the credentials section (PIN still needed) |
| Manage credentials | Add, edit, delete credentials |
| Settings | Monitoring/app settings, set or change the PIN |

Groups created on first start (editable or deletable by the admin; you can add your own):
Operator, Maintainer, Contributor, **Adder only** (can add but not edit or delete), Credentials manager, Credentials viewer, **History viewer** (history only), Read-only.
Safeguards: you cannot disable, demote or delete your own admin account; a group with users cannot be deleted; changing a user's password signs out their other sessions.
Forgot the admin password: set `LAN_ADMIN_USER`/`LAN_ADMIN_PASSWORD` on a copy with an empty data folder, or reset it via SQLite by deleting the row in `users` and restarting (the `/setup` page returns when no users exist).

## Test connection and check methods
On the Add/Edit forms, **Test connection** tries ping, TCP and HTTP with the values currently typed in (nothing is saved), shows what works and offers "Use this".
For devices with no port entered it also probes common ports (22, 80, 443, 445, 3389, 5000, 5001, 8006, 8080, 8123, 9000).
Methods: devices - ICMP ping, TCP port, HTTP request; services - TCP, TCP + HTTP, HTTP only, ping. Per-target timeout/retries/delay override the global ones.
Devices can have an optional web address (protocol/port/path or a custom URL) which gives them an **Open** button on the dashboard and lists.

## Credentials for devices, services and API keys
Each credential has a **type** (Login, SSH, Web login, API key, Other) and can belong to a **device**, a **service**, or both.
Fields: username, password, API key / token (both encrypted), port (e.g. 22 for SSH, 8080 for a web interface), URL, description, notes.
They show on the device or service page (behind the PIN) with Add SSH / Add web login / Add API key buttons, and in Credentials (filter by type).
Passwords and API keys are only fetched when you press Show or Copy. Deleting a device or service keeps its credentials, unlinked.

## Checking, and linking services to devices
* **Check now** on every device and service page runs that one check immediately (with its normal retries); the page refreshes until the result is in. Needs the *Run checks* permission.
* A service belongs to a device when you pick it in the service form, **or automatically when both share an IP address**: saving a device links existing unassigned services with that IP, and saving a service without a device links it to the device with the same IP.
* On a device page you can also **attach any existing service** from a list (unassigned ones first; a service on another device is moved), or press *Link services that have IP ...*.

## Export and import (Admin > Export & import)
Admin only. Tick any combination of: settings, groups, users, devices, services, credentials (with type, port, device and API key), monitoring history.
One item downloads as a `.csv`; several download as one `.zip` with a `.csv` per item. Files open in Excel (UTF-8).
* Relations are stored by name (a service has `device_name`, a credential `service_name`), so files can be imported into a fresh installation.
* **Users** include password hashes (not readable passwords); **credentials** include passwords in plain text and require an unlocked PIN session. Treat those files like a password list.
* Import accepts CSV or ZIP, recognises each file by its columns and imports parents before children. Choose to skip existing items or update them. Bad rows are skipped and listed with their row number.
* Cells that start with `= + @` are prefixed with `'` on export to stop spreadsheet formula injection, and the prefix is removed again on import.

## Scheduler
Runs inside the app, independent of browsers. Fixed job IDs mean restarts cannot duplicate jobs; one catch-up run happens after downtime if a run was missed; only one run at a time.

## Security notes
* Passwords are Fernet-encrypted before reaching SQLite and are only returned by the reveal call (needs the permission, an unlocked PIN session, CSRF token). Logins and the PIN have 5-try/60 s lockouts. POSTs are CSRF-protected.
* The PIN is a second gate on top of the group permission. It gates the UI; anyone with the database file and key can decrypt.
* With no `LAN_ENCRYPTION_KEY`, the key file sits next to the database inside the container.
* Traffic is plain HTTP: put a reverse proxy with HTTPS in front if you do not trust the network. Do not expose the port to the internet.
* "Test connection" lets users with Add/Edit rights probe hosts from the server; that is why it needs those permissions.

## Data lives in the container - backup before you re-create it
Data survives stop/start/restart and host reboots, but **not** removing or re-creating the container (including `docker compose down` or `up --force-recreate` to update the code).
```
docker stop lan-manager
docker cp lan-manager:/home/user/App/data ./lan-backup        # database + key (a copy only when you run this)
docker start lan-manager
```
Restore into a new container: `docker cp ./lan-backup/. lan-manager:/home/user/App/data/` then `docker restart lan-manager`.

## Migrations
`PRAGMA user_version` tracks the schema (now version 3). On start, an existing database is copied to `lan_manager.db.bak-v<N>` and pending steps in `app/migrations.py` run. To change the schema, edit `models.py` and append a step to `MIGRATIONS`.

## Layout
`__main__.py` - `app/`: `models`, `auth` (users/groups/permissions), `transfer` (CSV export/import), `monitor` (checks, test, scheduler), `security`, `settings`, `validators`, `migrations`, `views_*`, `templates/`, `static/`.
