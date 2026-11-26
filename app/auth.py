"""Users, groups, permissions, login throttling and the request gate."""
import logging
import os
import re
import time

from flask import abort, g, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .models import db, Group, User

log = logging.getLogger(__name__)

PERMISSIONS = [
    ("view", "View dashboard, devices and services"),
    ("history", "View monitoring history"),
    ("add", "Add devices and services"),
    ("edit", "Edit devices and services"),
    ("delete", "Delete devices and services"),
    ("run_checks", "Run availability checks manually"),
    ("cred_view", "View credentials (PIN still required)"),
    ("cred_manage", "Add, edit and delete credentials"),
    ("settings", "Change monitoring and application settings, set the PIN"),
    ("admin", "Manage users and groups"),
]
ALL = {k for k, _ in PERMISSIONS}
ASSIGNABLE = [(k, v) for k, v in PERMISSIONS if k != "admin"]   # admin rights belong to the Administrator group only

# Created once on first start; the admin can edit or delete them afterwards.
DEFAULT_GROUPS = [
    ("Operator", "View everything, add and edit, run checks", {"view", "history", "add", "edit", "run_checks"}),
    ("Maintainer", "View, add, edit and delete devices and services", {"view", "add", "edit", "delete"}),
    ("Contributor", "View, add and edit - cannot delete", {"view", "add", "edit"}),
    ("Adder only", "View, and add new devices and services only", {"view", "add"}),
    ("Credentials manager", "View inventory, view and manage credentials", {"view", "cred_view", "cred_manage"}),
    ("Credentials viewer", "View inventory, read credentials only", {"view", "cred_view"}),
    ("History viewer", "Monitoring history only", {"history"}),
    ("Read-only", "View inventory and history", {"view", "history"}),
]

_USERNAME = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
_DUMMY = generate_password_hash("not-a-real-password")
_fails = {}


def valid_username(v):
    v = (v or "").strip()
    if not _USERNAME.match(v):
        raise ValueError("Username: 3-32 characters, letters, digits, . _ -")
    return v.lower()


def valid_password(v):
    if len(v or "") < 8:
        raise ValueError("Password must be at least 8 characters")
    return v


def stamp(user):
    return user.password_hash[-16:]     # changes whenever the password changes -> old sessions die


def current_user():
    if "user" not in g:
        u = db.session.get(User, session["uid"]) if session.get("uid") else None
        g.user = u if u and u.is_active and session.get("pv") == stamp(u) else None
    return g.user


def can(perm):
    u = current_user()
    return bool(u and perm in u.perms)


def require(*perms):
    """Abort with 403 unless the user holds at least one of the permissions."""
    if not any(can(p) for p in perms):
        abort(403)


def start_session(user):
    session.clear()
    session["uid"], session["pv"] = user.id, stamp(user)
    session.permanent = True


def attempt_login(username, password):
    """Returns (user|None, message). Five failures -> 60 s lockout per address+username."""
    key = (request.remote_addr, (username or "").strip().lower())
    count, until = _fails.get(key, (0, 0.0))
    if time.time() < until:
        return None, f"Too many attempts. Try again in {int(until - time.time()) + 1} seconds."
    user = User.query.filter_by(username=key[1]).first()
    ok = check_password_hash(user.password_hash if user else _DUMMY, password or "")
    if ok and user and user.is_active:
        _fails.pop(key, None)
        return user, ""
    count += 1
    _fails[key] = (0, time.time() + 60) if count >= 5 else (count, 0.0)
    if count >= 5:
        log.warning("Five failed logins for %r from %s", key[1], key[0])
    return None, "Wrong username or password." if not (ok and user) else "This account is disabled."


def gate():
    """Runs before every request: first-run setup, then login required everywhere except login/static."""
    ep = request.endpoint or ""
    if ep == "static":
        return None
    if User.query.count() == 0:
        return None if ep == "auth.setup" else redirect(url_for("auth.setup"))
    if ep in ("auth.login", "auth.setup"):
        return None
    if not current_user():
        if request.headers.get("X-CSRF"):            # fetch() calls from the page
            return jsonify(error="login required"), 401
        return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
    return None


def landing():
    for perm, endpoint in (("view", "inv.dashboard"), ("history", "mon.history"), ("cred_view", "cred.index")):
        if can(perm):
            return endpoint
    return "auth.account"


def safe_next(default):
    nxt = (request.values.get("next") or "").rstrip("?")
    return nxt if nxt.startswith("/") and not nxt.startswith("//") else default


def seed():
    """Make sure the Administrator group exists with every permission; seed the default groups once."""
    admin = Group.query.filter_by(name="Administrator").first()
    fresh = admin is None
    if fresh:
        admin = Group(name="Administrator", description="Full access, including users and groups", is_system=True)
        db.session.add(admin)
    admin.permissions = ",".join(sorted(ALL))
    if fresh:
        for name, desc, perms in DEFAULT_GROUPS:
            db.session.add(Group(name=name, description=desc, permissions=",".join(sorted(perms))))
    db.session.commit()
    user, pw = os.environ.get("LAN_ADMIN_USER"), os.environ.get("LAN_ADMIN_PASSWORD")
    if user and pw and User.query.count() == 0:
        try:
            db.session.add(User(username=valid_username(user), password_hash=generate_password_hash(valid_password(pw)),
                                group_id=admin.id))
            db.session.commit()
            log.info("Created admin user %r from environment variables", user)
        except ValueError as e:
            log.error("LAN_ADMIN_USER / LAN_ADMIN_PASSWORD ignored: %s", e)
