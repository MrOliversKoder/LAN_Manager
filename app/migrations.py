"""Tiny schema-versioning scheme using SQLite's PRAGMA user_version.

* Fresh database: db.create_all() builds the latest schema and the version is set to the latest.
* Existing database: the DB file is copied to <db>.bak-v<old> and each pending migration runs in order.

To change the schema later: edit models.py AND append (version, [sql, ...]) to MIGRATIONS, e.g.
    (2, ["ALTER TABLE devices ADD COLUMN location VARCHAR(100)"]),
"""
import logging
import shutil

from sqlalchemy import inspect

from . import config
from .models import db

log = logging.getLogger(__name__)

MIGRATIONS = [
    (2, ["ALTER TABLE devices ADD COLUMN web_protocol VARCHAR(5)",
         "ALTER TABLE devices ADD COLUMN web_port INTEGER",
         "ALTER TABLE devices ADD COLUMN web_path VARCHAR(300)",
         "ALTER TABLE devices ADD COLUMN web_url VARCHAR(500)"]),  # users/groups tables come from create_all
    (3, ["ALTER TABLE credentials ADD COLUMN device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL",
         "ALTER TABLE credentials ADD COLUMN kind VARCHAR(12) NOT NULL DEFAULT 'login'",
         "ALTER TABLE credentials ADD COLUMN port INTEGER",
         "ALTER TABLE credentials ADD COLUMN encrypted_api_key TEXT DEFAULT ''"]),
]  # list of (version, [sql statements]); version 1 is the baseline
LATEST = 1 + len(MIGRATIONS)


def migrate():
    fresh = not inspect(db.engine).has_table("devices")
    db.create_all()  # only creates missing tables; never alters existing ones
    with db.engine.begin() as conn:
        current = conn.exec_driver_sql("PRAGMA user_version").scalar()
        if fresh:
            conn.exec_driver_sql(f"PRAGMA user_version = {LATEST}")
            return
        current = current or 1
    pending = [m for m in MIGRATIONS if m[0] > current]
    if not pending:
        return
    backup = f"{config.DB_PATH}.bak-v{current}"
    shutil.copy2(config.DB_PATH, backup)
    log.info("Backed up database to %s before migrating", backup)
    for version, statements in pending:
        with db.engine.begin() as conn:
            for sql in statements:
                conn.exec_driver_sql(sql)
            conn.exec_driver_sql(f"PRAGMA user_version = {version}")
        log.info("Applied migration %s", version)
