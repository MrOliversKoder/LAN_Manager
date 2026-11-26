"""Availability checks, retry logic and the APScheduler integration.

Workers are pure network code (no DB access). The run collects every attempt in memory and writes it
in a single transaction, so SQLite never sees concurrent writers.
"""
import atexit
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib import error as urlerror, request as urlrequest
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import func

from . import config, settings as S
from .models import db, Device, Service, MonitorHistory as H, build_url, utcnow

log = logging.getLogger(__name__)
DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
PRIMARY = ("ping", "tcp", "web")    # these decide online/offline ("web" = HTTP-only target); "http" is the extra check on top of TCP
UNKNOWN = {"status": "unknown", "checked_at": None, "response_time": None, "last_success": None,
           "fails": 0, "http": None}

_app = None
_scheduler = None
_run_lock = threading.Lock()
_stop = threading.Event()
_ssl_ctx = ssl.create_default_context()       # LAN services usually use self-signed certificates
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


# ---- timezone / schedule helpers -------------------------------------------
def tz_name():
    name = S.get("timezone")
    if name:
        return name
    env = os.environ.get("TZ", "")
    try:
        if env:
            ZoneInfo(env)
            return env
    except Exception:
        pass
    try:
        from tzlocal import get_localzone_name
        return get_localzone_name() or "UTC"
    except Exception:
        return "UTC"


def get_tz():
    try:
        return ZoneInfo(tz_name())
    except Exception:
        return ZoneInfo("UTC")


def parse_times(value):
    times = set()
    for part in (value or "").split(","):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", part)
        if not m:
            raise ValueError("Use 24-hour times like 00:00 or 08:30, separated by commas")
        times.add((int(m.group(1)), int(m.group(2))))
    if not times:
        raise ValueError("Enter at least one time")
    return sorted(times)


# ---- individual checks: each returns (ok, response_ms, http_status, error) --
def tcp_check(host, port, timeout):
    t = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return True, (time.perf_counter() - t) * 1000, None, None
    except OSError as e:  # includes timeouts and refused connections
        return False, None, None, f"{type(e).__name__}: {e}"[:300]


def ping_check(host, timeout):
    exe = shutil.which("ping")
    if not exe:
        return False, None, None, "ping is not installed in this container - use a TCP check for this device"
    if host.startswith("-"):
        return False, None, None, "Invalid host"
    t = time.perf_counter()
    try:
        p = subprocess.run([exe, "-c", "1", "-W", str(max(1, round(timeout))), host],
                           capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        return False, None, None, "ping timed out"
    if p.returncode == 0:
        m = re.search(r"time[=<]([\d.]+)", p.stdout)
        return True, float(m.group(1)) if m else (time.perf_counter() - t) * 1000, None, None
    out = (p.stderr or p.stdout).strip().splitlines()
    return False, None, None, (out[-1] if out else "No reply")[:300]


def status_ok(code, expected):
    if not expected:
        return 200 <= code <= 299
    for part in expected.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-")
            if int(lo) <= code <= int(hi):
                return True
        elif part and int(part) == code:
            return True
    return False


def http_check(url, timeout, expected):
    t = time.perf_counter()
    try:
        req = urlrequest.Request(url, headers={"User-Agent": "lan-manager/1.0"})
        with urlrequest.urlopen(req, timeout=timeout, context=_ssl_ctx) as r:
            code = r.status
    except urlerror.HTTPError as e:
        code = e.code
    except Exception as e:
        return False, None, None, f"{type(e).__name__}: {e}"[:300]
    ms = (time.perf_counter() - t) * 1000
    ok = status_ok(code, expected)
    return ok, ms, code, None if ok else f"Unexpected HTTP status {code}"


# ---- running a target ---------------------------------------------------------
def _execute(sp):
    rows = []

    def row(ctype, n, final, ok, ms, code, err, port):
        rows.append(dict(target_type=sp["type"], target_id=sp["id"], check_type=ctype, checked_at=utcnow(),
                         status="online" if ok else "offline", response_time=ms, http_status_code=code,
                         error_message=err, attempt_number=n, is_final=final, target_host=sp["host"],
                         target_port=port))

    def check(ctype, fn, port):
        total = sp["retries"] + 1
        for n in range(1, total + 1):
            try:
                ok, ms, code, err = fn()
            except Exception as e:  # a check must never crash the run
                ok, ms, code, err = False, None, None, f"{type(e).__name__}: {e}"[:300]
            final = ok or n == total
            row(ctype, n, final, ok, ms, code, err, port)
            if final:
                return ok
            if _stop.wait(sp["delay"]):      # shutting down: stop retrying
                rows[-1]["is_final"] = True
                return False

    host = sp["host"]
    if not host:
        row("tcp", 1, True, False, None, None, "No IP address configured", None)
        return rows
    method = sp["method"]
    if method == "ping":
        up = check("ping", lambda: ping_check(host, sp["timeout"]), None)
    elif method == "http":
        if not sp.get("url"):
            row("web", 1, True, False, None, None, "No web address configured", None)
            return rows
        up = check("web", lambda: http_check(sp["url"], sp["http_timeout"], sp["expected"]), sp["port"])
    elif not sp["port"]:
        row("tcp", 1, True, False, None, None, "No port configured", None)
        return rows
    else:
        up = check("tcp", lambda: tcp_check(host, sp["port"], sp["timeout"]), sp["port"])
    if sp.get("http"):
        if up:
            check("http", lambda: http_check(sp["url"], sp["http_timeout"], sp["expected"]), sp["port"])
        else:
            row("http", 1, True, False, None, None, "Skipped: TCP connection failed", sp["port"])
    return rows


def _pick(value, default):
    return default if value is None else value


def _build_specs(only=None):
    """Specs for all enabled targets, or for one (type, id) when a manual check is requested."""
    g = dict(tcp=S.get_float("tcp_timeout"), http=S.get_float("http_timeout"), http_on=S.get_bool("http_enabled"),
             retries=S.get_int("retries"), delay=S.get_int("retry_delay"))
    if only:
        g["http_on"] = True
    devices = Device.query.filter_by(id=only[1]) if only and only[0] == "device" else \
        ([] if only else Device.query.filter_by(mon_enabled=True))
    services = Service.query.filter_by(id=only[1]) if only and only[0] == "service" else \
        ([] if only else Service.query.filter_by(mon_enabled=True))
    specs = []
    for d in devices:
        if d.check_method == "http" and not g["http_on"]:
            continue                                   # HTTP checks switched off globally
        specs.append(dict(type="device", id=d.id, host=d.ip_address, method=d.check_method, port=d.check_port or d.web_port,
                          timeout=_pick(d.timeout, g["tcp"]), http_timeout=_pick(d.timeout, g["http"]),
                          retries=_pick(d.retries, g["retries"]), delay=_pick(d.retry_delay, g["delay"]),
                          url=d.open_url, expected=None))
    for sv in services:
        if sv.check_method == "http" and not g["http_on"]:
            continue
        specs.append(dict(type="service", id=sv.id, host=sv.host, method="tcp" if sv.check_method == "tcp_http" else sv.check_method,
                          port=sv.eff_port, timeout=_pick(sv.timeout, g["tcp"]), http_timeout=_pick(sv.timeout, g["http"]),
                          retries=_pick(sv.retries, g["retries"]), delay=_pick(sv.retry_delay, g["delay"]),
                          http=sv.check_method == "tcp_http" and g["http_on"], url=sv.base_url,
                          expected=sv.http_expected))
    return specs


def is_running():
    return _run_lock.locked()


def run_all(trigger="scheduled"):
    """Run every enabled check. Only one run at a time; overlapping requests are skipped."""
    if not _run_lock.acquire(blocking=False):
        log.warning("Monitoring run (%s) skipped: another run is still in progress", trigger)
        return False
    try:
        with _app.app_context():
            run_id = uuid.uuid4().hex[:12]
            specs = _build_specs()
            log.info("Monitoring run %s (%s): %d targets", run_id, trigger, len(specs))
            rows = []
            with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as pool:
                for result in pool.map(_execute, specs):
                    rows.extend(result)
            db.session.add_all(H(run_id=run_id, **r) for r in rows)
            S.set_many({"last_run_at": utcnow().isoformat(), "last_run_id": run_id,
                        "last_run_trigger": trigger}, commit=False)
            days = S.get_int("history_days")
            if days > 0:
                H.query.filter(H.checked_at < utcnow() - timedelta(days=days)).delete()
            db.session.commit()
            log.info("Monitoring run %s finished", run_id)
        return True
    except Exception:
        log.exception("Monitoring run failed")
        return False
    finally:
        _run_lock.release()


_target_running = set()
_target_lock = threading.Lock()


def target_running(target_type, target_id):
    return (target_type, target_id) in _target_running or is_running()


def _run_target(target_type, target_id):
    try:
        with _app.app_context():
            specs = _build_specs(only=(target_type, target_id))
            run_id = "m" + uuid.uuid4().hex[:11]
            rows = [r for sp in specs for r in _execute(sp)]
            db.session.add_all(H(run_id=run_id, **r) for r in rows)
            db.session.commit()
            log.info("Manual check of %s %s finished", target_type, target_id)
    except Exception:
        log.exception("Manual check failed")
    finally:
        with _target_lock:
            _target_running.discard((target_type, target_id))


def run_target_in_background(target_type, target_id):
    """Check one device/service now (uses its normal retry settings). Does not touch the overview of the last full run."""
    with _target_lock:
        if (target_type, target_id) in _target_running:
            return False
        _target_running.add((target_type, target_id))
    threading.Thread(target=_run_target, args=(target_type, target_id), daemon=True, name="target-check").start()
    return True


def run_in_background(trigger="manual"):
    if is_running():
        return False
    threading.Thread(target=run_all, args=(trigger,), daemon=True, name="manual-run").start()
    return True


# ---- scheduler ------------------------------------------------------------------
def reschedule():
    """(Re)build jobs from the saved settings. Job ids are fixed, so jobs can never be duplicated."""
    if not _scheduler:
        return
    for job in _scheduler.get_jobs():
        if job.id.startswith("check-"):
            _scheduler.remove_job(job.id)
    if not S.get_bool("monitoring_enabled"):
        log.info("Scheduled monitoring is disabled")
        return
    days = [DAYS[int(d)] for d in S.get("check_days").split(",") if d.strip().isdigit()]
    if not days:
        return
    for h, m in parse_times(S.get("check_times")):
        _scheduler.add_job(run_all, CronTrigger(hour=h, minute=m, day_of_week=",".join(days), timezone=tz_name()),
                           id=f"check-{h:02d}{m:02d}", replace_existing=True, name=f"Checks at {h:02d}:{m:02d}")
    log.info("Scheduled checks: %s on %s (%s)", S.get("check_times"), ",".join(days), tz_name())


def next_run():
    if not _scheduler:
        return None
    times = [j.next_run_time for j in _scheduler.get_jobs() if j.next_run_time]
    return min(times) if times else None


def _last_due(now):
    """Most recent scheduled moment that is already in the past."""
    times = parse_times(S.get("check_times"))
    days = {int(d) for d in S.get("check_days").split(",") if d.strip().isdigit()}
    for back in range(8):
        day = (now - timedelta(days=back)).date()
        if day.weekday() not in days:
            continue
        for h, m in sorted(times, reverse=True):
            due = datetime(day.year, day.month, day.day, h, m, tzinfo=now.tzinfo)
            if due <= now:
                return due
    return None


def _catch_up():
    """After downtime, run once (coalesced) if a scheduled run was missed. Skipped on a fresh install."""
    last = S.get("last_run_at")
    if not last or not S.get_bool("monitoring_enabled"):
        return
    due = _last_due(datetime.now(get_tz()))
    if due and datetime.fromisoformat(last).replace(tzinfo=timezone.utc) < due:
        log.info("Missed scheduled run from %s: running a catch-up in 15 seconds", due)
        t = threading.Timer(15, run_all, args=("catch-up",))
        t.daemon = True
        t.start()


def init_scheduler(app):
    global _app, _scheduler
    if _scheduler:
        return
    _app = app
    _scheduler = BackgroundScheduler(timezone="UTC",
                                     job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600})
    _scheduler.start()
    with app.app_context():
        try:
            reschedule()
            _catch_up()
        except Exception:
            log.exception("Could not initialise the schedule - check the monitoring settings")
    atexit.register(shutdown)


def shutdown():
    _stop.set()
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        log.info("Scheduler stopped")


# ---- read helpers for the UI -------------------------------------------------------
def summaries(target_type):
    """Latest result, last success, failed-check count and latest HTTP result per target."""
    final = (H.target_type == target_type, H.is_final.is_(True))
    ids = db.session.query(func.max(H.id)).filter(*final, H.check_type.in_(PRIMARY)).group_by(H.target_id)
    http_ids = db.session.query(func.max(H.id)).filter(*final, H.check_type == "http").group_by(H.target_id)
    out = defaultdict(lambda: UNKNOWN)
    for r in H.query.filter(H.id.in_(ids)):
        out[r.target_id] = dict(UNKNOWN, status=r.status, checked_at=r.checked_at, response_time=r.response_time)
    for tid, ts in db.session.query(H.target_id, func.max(H.checked_at)).filter(
            *final, H.check_type.in_(PRIMARY), H.status == "online").group_by(H.target_id):
        out[tid] = dict(out[tid], last_success=ts)
    for tid, n in db.session.query(H.target_id, func.count()).filter(
            *final, H.check_type.in_(PRIMARY), H.status == "offline").group_by(H.target_id):
        out[tid] = dict(out[tid], fails=n)
    for r in H.query.filter(H.id.in_(http_ids)):
        out[r.target_id] = dict(out[r.target_id], http=r)
    return out


def overview():
    run_id = S.get("last_run_id")
    info = dict(last_run=None, next_run=next_run(), running=is_running(), total=0, online=0, offline=0, failed=0,
                enabled=S.get_bool("monitoring_enabled"), trigger=S.get("last_run_trigger"))
    if S.get("last_run_at"):
        info["last_run"] = datetime.fromisoformat(S.get("last_run_at"))
    if run_id:
        rows = H.query.filter_by(run_id=run_id, is_final=True).all()
        primary = [r for r in rows if r.check_type in PRIMARY]
        info["total"] = len({(r.target_type, r.target_id) for r in primary})
        info["online"] = sum(r.status == "online" for r in primary)
        info["offline"] = sum(r.status == "offline" for r in primary)
        info["failed"] = sum(r.status == "offline" for r in rows)
    return info


def purge_history(target_type, ids):
    if ids:
        H.query.filter(H.target_type == target_type, H.target_id.in_(ids)).delete(synchronize_session=False)


# ---- "Test connection" from the forms ---------------------------------------------------
COMMON_PORTS = (22, 80, 443, 445, 3389, 5000, 5001, 8006, 8080, 8123, 9000)


def run_test(kind, host, port, url, timeout):
    """Try every available method against the values typed into the form (nothing is saved).
    Returns (results, recommended_check_method). Each result: key, label, ok, ms, code, error, apply."""
    results = []

    def add(key, label, res, apply):
        ok, ms, code, err = res
        results.append(dict(key=key, label=label, ok=ok, ms=ms, code=code, error=err, apply=apply))

    with ThreadPoolExecutor(max_workers=4) as pool:
        ping_f = pool.submit(ping_check, host, timeout)
        tcp_f = pool.submit(tcp_check, host, port, timeout) if port else None
        http_f = pool.submit(http_check, url, max(timeout, 3), None) if url else None
        scan = {} if (port or kind != "device") else {p: pool.submit(tcp_check, host, p, min(timeout, 1.5)) for p in COMMON_PORTS}
        add("ping", "ICMP ping", ping_f.result(), {"check_method": "ping"})
        if tcp_f:
            add("tcp", f"TCP connect to port {port}", tcp_f.result(), {"check_method": "tcp", "check_port": port})
        if http_f:
            add("http", "HTTP request", http_f.result(),
                {"check_method": "http" if kind == "device" else "tcp_http"})
        for p, fut in scan.items():
            res = fut.result()
            if res[0]:
                add("tcp", f"TCP port {p} is open", res, {"check_method": "tcp", "check_port": p})
    ok = {r["key"] for r in results if r["ok"]}
    if kind == "device":
        pick = "ping" if "ping" in ok else "tcp" if "tcp" in ok else "http" if "http" in ok else None
    else:
        pick = ("tcp_http" if {"tcp", "http"} <= ok else "tcp" if "tcp" in ok else "http" if "http" in ok
                else "ping" if "ping" in ok else None)
    return results, pick
