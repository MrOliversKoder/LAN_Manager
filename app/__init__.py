import logging
import sqlite3
from datetime import timezone

from flask import Flask, request
from sqlalchemy import event
from sqlalchemy.engine import Engine

from . import config, migrations, monitor, security
from .models import db

log = logging.getLogger("lan")


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(conn, _record):
    if isinstance(conn, sqlite3.Connection):
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()


def create_app():
    logging.basicConfig(level=config.LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        probe = config.DATA_DIR / ".write-test"
        probe.write_text("ok")
        probe.unlink()
    except OSError as e:
        raise SystemExit(f"Data directory {config.DATA_DIR} is not writable ({e}). Fix the volume permissions "
                         f"so the container user can write to it (see README).")
    key = security.load_key()

    app = Flask(__name__)
    app.config.update(SECRET_KEY=security.session_secret(key), SESSION_COOKIE_SAMESITE="Lax",
                      SQLALCHEMY_DATABASE_URI=f"sqlite:///{config.DB_PATH}",
                      SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 30}}, MAX_CONTENT_LENGTH=1 << 20)
    db.init_app(app)
    with app.app_context():
        migrations.migrate()

    @app.before_request
    def _csrf():
        security.check_csrf()

    @app.after_request
    def _no_store(resp):
        if request.path.startswith("/credentials"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def _ctx():
        return dict(csrf_token=security.csrf_token, unlocked=security.is_unlocked(),
                    pin_set=security.pin_is_set(), mon_running=monitor.is_running())

    @app.template_filter("localtime")
    def localtime(dt, fmt="%Y-%m-%d %H:%M"):
        if not dt:
            return "never"
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(monitor.get_tz()).strftime(fmt)

    @app.template_filter("ms")
    def ms(v):
        return "-" if v is None else f"{v:.0f} ms"

    app.jinja_env.filters["zip"] = lambda a, b: zip(a, b)

    from .views_inventory import bp as inventory
    from .views_credentials import bp as credentials
    from .views_monitoring import bp as monitoring
    for bp in (inventory, credentials, monitoring):
        app.register_blueprint(bp)

    monitor.init_scheduler(app)
    return app
