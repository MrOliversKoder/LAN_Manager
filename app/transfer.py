"""CSV export / import. One CSV per data set; several sets are bundled into one ZIP.

Relations are written by name (a service has device_name, a credential has service_name, ...) so a file
can be imported into a fresh installation. Import = create new rows, and either skip or update existing ones."""
import csv
import io
import logging
import zipfile
from datetime import datetime

from sqlalchemy import func
from werkzeug.security import generate_password_hash

from . import auth, monitor, security, settings as S, validators as V
from .models import db, Credential, Device, Group, MonitorHistory as H, Service, Setting, User

log = logging.getLogger(__name__)

ITEMS = [  # key, label, hint (also the import order)
    ("settings", "Settings", "Monitoring schedule, timeouts, retries, lock timeout (not the PIN)"),
    ("groups", "Groups", "Names and permissions"),
    ("users", "Users", "Includes password hashes so logins keep working"),
    ("devices", "Devices", "Including web address and monitoring options"),
    ("services", "Services", "Including management and monitoring options"),
    ("credentials", "Credentials", "Passwords are written in PLAIN TEXT - requires an unlocked PIN session"),
    ("history", "Monitoring history", "Every recorded check attempt"),
]
COLUMNS = {
    "settings": ["key", "value"],
    "groups": ["name", "description", "permissions"],
    "users": ["username", "group_name", "is_active", "password_hash", "created_at", "last_login"],
    "devices": ["name", "ip_address", "hostname", "description", "device_type", "notes", "check_method", "check_port",
                "mon_enabled", "timeout", "retries", "retry_delay", "web_protocol", "web_port", "web_path", "web_url",
                "created_at"],
    "services": ["name", "device_name", "ip_address", "port", "protocol", "access_path", "quick_access_url", "description",
                 "management_type", "management_service_name", "management_url", "ssh_host", "ssh_port", "ssh_username",
                 "management_notes", "notes", "check_method", "http_expected", "mon_enabled", "timeout", "retries",
                 "retry_delay", "created_at"],
    "credentials": ["service_name", "description", "username", "password", "login_url", "notes"],
    "history": ["checked_at", "target_type", "target_name", "check_type", "status", "response_time_ms", "http_status_code",
                "error_message", "attempt_number", "is_final", "target_host", "target_port", "run_id"],
}
SETTING_KEYS = ["monitoring_enabled", "check_times", "check_days", "timezone", "tcp_timeout", "http_timeout",
                "http_enabled", "retries", "retry_delay", "history_days", "cred_lock_minutes"]


# ---- cell encoding (CSV formula injection guard that round-trips) ----------------------------
def _cell(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, datetime):
        return v.isoformat(timespec="seconds")
    v = str(v)
    if v[:1] in ("=", "+", "@", "\t", "\r") or (v[:1] == "-" and v[1:2] and not v[1:2].isdigit()):
        return "'" + v
    return v


def _plain(v):
    v = (v or "").strip()
    return v[1:] if v[:1] == "'" and v[1:2] in ("=", "+", "@", "-", "\t", "\r") else v


def _s(row, key):
    return _plain(row.get(key)) or None


def _b(row, key, default=True):
    v = (row.get(key) or "").strip().lower()
    return default if v == "" else v in ("1", "true", "yes", "y", "on")


def _dt(v):
    v = (v or "").strip()
    if not v:
        return None
    d = datetime.fromisoformat(v)
    return d.astimezone(__import__("datetime").timezone.utc).replace(tzinfo=None) if d.tzinfo else d


# ---- export -----------------------------------------------------------------------------------
def _rows(key):
    if key == "settings":
        for k in SETTING_KEYS:
            yield {"key": k, "value": S.get(k)}
    elif key == "groups":
        for g in Group.query.filter_by(is_system=False).order_by(Group.name):
            yield dict(name=g.name, description=g.description, permissions=g.permissions)
    elif key == "users":
        for u in User.query.order_by(User.username):
            yield dict(username=u.username, group_name=u.group.name, is_active=u.is_active,
                       password_hash=u.password_hash, created_at=u.created_at, last_login=u.last_login)
    elif key == "devices":
        for d in Device.query.order_by(Device.name):
            yield {c: getattr(d, c, None) for c in COLUMNS["devices"]}
    elif key == "services":
        for s in Service.query.order_by(Service.name):
            row = {c: getattr(s, c, None) for c in COLUMNS["services"]}
            row["device_name"] = s.device.name if s.device else None
            row["management_service_name"] = s.management_service.name if s.management_service else None
            yield row
    elif key == "credentials":
        for c in Credential.query.order_by(Credential.id):
            yield dict(service_name=c.service.name if c.service else None, description=c.description,
                       username=c.username, password=security.decrypt(c.encrypted_password) or "",
                       login_url=c.login_url, notes=c.notes)
    elif key == "history":
        names = {"device": {d.id: d.name for d in Device.query}, "service": {s.id: s.name for s in Service.query}}
        for h in H.query.order_by(H.id).yield_per(1000):
            yield dict(checked_at=h.checked_at, target_type=h.target_type,
                       target_name=names[h.target_type].get(h.target_id, ""), check_type=h.check_type, status=h.status,
                       response_time_ms=None if h.response_time is None else round(h.response_time, 1),
                       http_status_code=h.http_status_code, error_message=h.error_message, attempt_number=h.attempt_number,
                       is_final=h.is_final, target_host=h.target_host, target_port=h.target_port, run_id=h.run_id)


def export_csv(key):
    out = io.StringIO(newline="")
    w = csv.writer(out)
    w.writerow(COLUMNS[key])
    for row in _rows(key):
        w.writerow([_cell(row.get(c)) for c in COLUMNS[key]])
    return out.getvalue().encode("utf-8-sig")      # BOM so Excel opens UTF-8 (æøå) correctly


def export_zip(keys, stamp):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for key in keys:
            z.writestr(f"lan-manager-{key}-{stamp}.csv", export_csv(key))
    return buf.getvalue()


# ---- import ------------------------------------------------------------------------------------
def detect(headers):
    h = set(headers)
    if {"key", "value"} <= h:
        return "settings"
    if "target_type" in h:
        return "history"
    if "device_name" in h:
        return "services"
    if "password_hash" in h or {"username", "group_name"} <= h:
        return "users"
    if {"service_name", "password"} <= h:
        return "credentials"
    if "permissions" in h:
        return "groups"
    if {"name", "ip_address"} <= h:
        return "devices"
    return None


def read_files(uploads):
    """Yield (filename, kind|None, rows|error) for every CSV in the uploads (ZIPs are unpacked)."""
    blobs = []
    for up in uploads:
        data = up.read()
        if up.filename.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    blobs += [(n, z.read(n)) for n in z.namelist() if n.lower().endswith(".csv") and not n.startswith("__")]
            except zipfile.BadZipFile:
                yield up.filename, None, "Not a valid ZIP file"
        else:
            blobs.append((up.filename, data))
    for name, data in blobs:
        try:
            reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline=""))
            rows = list(reader)
        except (UnicodeDecodeError, csv.Error) as e:
            yield name, None, f"Cannot read as UTF-8 CSV ({e})"
            continue
        kind = detect(reader.fieldnames or [])
        yield name, kind, rows if kind else "Unrecognised columns - was this file exported from LAN Manager?"


def _upsert(stats, existing, update, apply):
    """Shared create/skip/update bookkeeping."""
    if existing is not None and not update:
        stats["skipped"] += 1
        return False
    apply()
    stats["updated" if existing is not None else "created"] += 1
    return True


def _mon(row, is_device):
    return dict(mon_enabled=_b(row, "mon_enabled"), check_method=_s(row, "check_method") or ("ping" if is_device else "tcp"),
                timeout=V.number(row.get("timeout"), float, 0.5, 60, "timeout"),
                retries=V.number(row.get("retries"), int, 0, 10, "retries"),
                retry_delay=V.number(row.get("retry_delay"), int, 0, 3600, "retry_delay"))


def import_rows(kind, rows, update):
    stats = dict(created=0, updated=0, skipped=0, errors=[])
    me = auth.current_user()
    handler = globals()["_import_" + kind]
    for n, row in enumerate(rows, start=2):                     # row 1 is the header
        try:
            with db.session.begin_nested():
                handler(row, update, stats, me)
        except (ValueError, KeyError) as e:
            stats["errors"].append(f"row {n}: {e}")
    db.session.commit()
    if kind == "services":
        _second_pass_services(rows, update)
    if kind == "settings":
        monitor.reschedule()
    return stats


def _import_settings(row, update, stats, me):
    key, val = _plain(row.get("key")), (row.get("value") or "").strip()
    if key not in SETTING_KEYS:
        raise ValueError(f"unknown setting {key!r}")
    if key == "check_times":
        monitor.parse_times(val)
    elif key == "timezone" and val:
        __import__("zoneinfo").ZoneInfo(val)
    elif key not in ("check_days",):
        if key.endswith("_enabled"):
            val = "1" if val in ("1", "true", "True") else "0"
        else:
            float(val)
    exists = Setting.query.filter_by(setting_key=key).first()
    _upsert(stats, exists, update, lambda: S.set_many({key: val}, commit=False))


def _import_groups(row, update, stats, me):
    name = V.text(_plain(row.get("name")), "name", True, 60)
    if name == "Administrator":
        raise ValueError("the Administrator group is built in")
    perms = [p for p in (row.get("permissions") or "").split(",") if p in dict(auth.ASSIGNABLE)]
    if not perms:
        raise ValueError("no valid permissions")
    g = Group.query.filter_by(name=name).first()

    def apply():
        grp = g or Group(name=name)
        grp.description, grp.permissions = _s(row, "description"), ",".join(perms)
        db.session.add(grp)
    _upsert(stats, g, update, apply)


def _import_users(row, update, stats, me):
    name = auth.valid_username(row.get("username"))
    group = Group.query.filter_by(name=_plain(row.get("group_name"))).first()
    if not group:
        raise ValueError(f"unknown group {row.get('group_name')!r} (import groups first or in the same selection)")
    pw_hash = (row.get("password_hash") or "").strip()
    if not pw_hash.startswith(("scrypt:", "pbkdf2:")):
        pw_hash = generate_password_hash(auth.valid_password(row.get("password"))) if row.get("password") else None
    u = User.query.filter_by(username=name).first()
    if u and me and u.id == me.id:
        stats["skipped"] += 1                                   # never alter the account doing the import
        return
    if not u and not pw_hash:
        raise ValueError("needs password_hash or password")

    def apply():
        usr = u or User(username=name)
        usr.group_id, usr.is_active = group.id, _b(row, "is_active")
        if pw_hash:
            usr.password_hash = pw_hash
        db.session.add(usr)
    _upsert(stats, u, update, apply)


def _import_devices(row, update, stats, me):
    name = V.text(_plain(row.get("name")), "name", True, 120)
    vals = dict(ip_address=V.ip(row.get("ip_address")), hostname=V.host(row.get("hostname")),
                description=_s(row, "description"), device_type=_s(row, "device_type"), notes=_s(row, "notes"),
                check_port=V.port(row.get("check_port")), web_protocol=V.choice(_s(row, "web_protocol") or "", ("", "http", "https")) or None,
                web_port=V.port(row.get("web_port")), web_path=V.path(row.get("web_path")),
                web_url=V.url(row.get("web_url")), **_mon(row, True))
    V.choice(vals["check_method"], ("ping", "tcp", "http"))
    d = Device.query.filter(func.lower(Device.name) == name.lower()).first()

    def apply():
        dev = d or Device(name=name)
        for k, v in vals.items():
            setattr(dev, k, v)
        db.session.add(dev)
    _upsert(stats, d, update, apply)


def _import_services(row, update, stats, me):
    name = V.text(_plain(row.get("name")), "name", True, 120)
    dev_name = _s(row, "device_name")
    device = Device.query.filter(func.lower(Device.name) == dev_name.lower()).first() if dev_name else None
    if dev_name and not device:
        raise ValueError(f"unknown device {dev_name!r} (import devices first or in the same selection)")
    ip = V.ip(row.get("ip_address"), False)
    if not device and not ip:
        raise ValueError("needs a device_name or an ip_address")
    vals = dict(device_id=device.id if device else None, ip_address=ip, port=V.port(row.get("port")),
                protocol=V.choice(_s(row, "protocol") or "http", ("http", "https")), access_path=V.path(row.get("access_path")),
                quick_access_url=V.url(row.get("quick_access_url")), description=_s(row, "description"),
                management_type=V.choice(_s(row, "management_type") or "direct", ("direct", "external", "manual")),
                management_url=V.url(row.get("management_url")), ssh_host=V.host(row.get("ssh_host")),
                ssh_port=V.port(row.get("ssh_port")), ssh_username=_s(row, "ssh_username"),
                management_notes=_s(row, "management_notes"), notes=_s(row, "notes"),
                http_expected=V.expected_status(row.get("http_expected")), **_mon(row, False))
    V.choice(vals["check_method"], ("tcp", "tcp_http", "http", "ping"))
    sv = Service.query.filter(func.lower(Service.name) == name.lower(),
                              Service.device_id == vals["device_id"]).first()

    def apply():
        svc = sv or Service(name=name)
        for k, v in vals.items():
            setattr(svc, k, v)
        db.session.add(svc)
    _upsert(stats, sv, update, apply)


def _second_pass_services(rows, update):
    """management_service_name can point at a service defined later in the same file."""
    for row in rows:
        target = _s(row, "management_service_name")
        if not target:
            continue
        dev_name = _s(row, "device_name")
        device = Device.query.filter(func.lower(Device.name) == (dev_name or "").lower()).first()
        sv = Service.query.filter(func.lower(Service.name) == (_plain(row.get("name")) or "").lower(),
                                  Service.device_id == (device.id if device else None)).first()
        mgr = Service.query.filter(func.lower(Service.name) == target.lower()).first()
        if sv and mgr and mgr.id != sv.id and sv.management_type == "external" and (update or not sv.management_service_id):
            sv.management_service_id = mgr.id
    db.session.commit()


def _import_credentials(row, update, stats, me):
    if not security.is_unlocked():
        raise ValueError("unlock the credentials PIN first")
    svc_name = _s(row, "service_name")
    service = Service.query.filter(func.lower(Service.name) == svc_name.lower()).first() if svc_name else None
    if svc_name and not service:
        raise ValueError(f"unknown service {svc_name!r}")
    username, desc = _s(row, "username"), _s(row, "description")
    if not username and not row.get("password"):
        raise ValueError("needs a username or a password")
    c = Credential.query.filter_by(service_id=service.id if service else None, username=username, description=desc).first()

    def apply():
        cred = c or Credential()
        cred.service_id, cred.username, cred.description = (service.id if service else None), username, desc
        cred.login_url, cred.notes = V.url(row.get("login_url")), _s(row, "notes")
        if row.get("password") or not c:
            cred.encrypted_password = security.encrypt(row.get("password") or "")
        db.session.add(cred)
    _upsert(stats, c, update, apply)


def _import_history(row, update, stats, me):
    ttype = V.choice((row.get("target_type") or "").strip(), ("device", "service"))
    model = Device if ttype == "device" else Service
    target = model.query.filter(func.lower(model.name) == (_plain(row.get("target_name")) or "").lower()).first()
    if not target:
        raise ValueError(f"unknown {ttype} {row.get('target_name')!r}")
    when = _dt(row.get("checked_at"))
    if not when:
        raise ValueError("checked_at is required")
    ctype = V.choice((row.get("check_type") or "").strip(), ("ping", "tcp", "http", "web"))
    attempt = V.number(row.get("attempt_number"), int, 1, 99, "attempt_number") or 1
    if H.query.filter_by(target_type=ttype, target_id=target.id, check_type=ctype, checked_at=when,
                         attempt_number=attempt).first():
        stats["skipped"] += 1
        return
    ms = V.number(row.get("response_time_ms"), float, 0, 10**7, "response_time_ms")
    db.session.add(H(run_id=_s(row, "run_id"), target_type=ttype, target_id=target.id, check_type=ctype, checked_at=when,
                     status=V.choice((row.get("status") or "").strip(), ("online", "offline")), response_time=ms,
                     http_status_code=V.number(row.get("http_status_code"), int, 100, 599, "http_status_code"),
                     error_message=(_s(row, "error_message") or "")[:300] or None, attempt_number=attempt,
                     is_final=_b(row, "is_final"), target_host=_s(row, "target_host"),
                     target_port=V.port(row.get("target_port"))))
    stats["created"] += 1
