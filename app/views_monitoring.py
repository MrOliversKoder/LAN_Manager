from zoneinfo import ZoneInfo, available_timezones

from flask import Blueprint, flash, redirect, render_template, request, url_for

from . import auth, monitor, security, settings as S, validators as V
from .models import db, Device, MonitorHistory as H, Service

bp = Blueprint("mon", __name__)
DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def _schedule_data():
    keys = ("monitoring_enabled", "check_times", "check_days", "timezone", "tcp_timeout", "http_timeout",
            "http_enabled", "retries", "retry_delay")
    return {k: S.get(k) for k in keys}


@bp.route("/monitoring", methods=["GET", "POST"])
def monitoring():
    auth.require("view", "history", "settings", "run_checks")
    if request.method == "POST":
        auth.require("settings")
    data, errors = _schedule_data(), {}
    if request.method == "POST":
        f = V.Form(request.form)
        days = sorted({d for d in request.form.getlist("days") if d in "0123456"})
        vals = dict(monitoring_enabled="monitoring_enabled" in request.form,
                    http_enabled="http_enabled" in request.form, check_days=",".join(days),
                    tcp_timeout=f.get("tcp_timeout", V.number, float, 0.5, 60, "TCP timeout"),
                    http_timeout=f.get("http_timeout", V.number, float, 0.5, 120, "HTTP timeout"),
                    retries=f.get("retries", V.number, int, 0, 10, "Retries"),
                    retry_delay=f.get("retry_delay", V.number, int, 0, 3600, "Retry delay"))
        try:
            vals["check_times"] = ", ".join(f"{h:02d}:{m:02d}" for h, m in monitor.parse_times(request.form.get("check_times")))
        except ValueError as e:
            errors["check_times"] = str(e)
        if not days:
            errors["days"] = "Select at least one day"
        tz = (request.form.get("timezone") or "").strip()
        try:
            tz and ZoneInfo(tz)
        except Exception:
            errors["timezone"] = "Unknown timezone (example: Europe/Oslo)"
        errors.update(f.errors)
        data = {**data, **request.form.to_dict(), "check_days": ",".join(days),
                "monitoring_enabled": vals["monitoring_enabled"], "http_enabled": vals["http_enabled"]}
        if not errors:
            vals["timezone"] = tz
            S.set_many({k: v for k, v in vals.items() if v is not None})
            monitor.reschedule()
            flash("Monitoring settings saved", "ok")
            return redirect(url_for("mon.monitoring"))
    return render_template("monitoring.html", data=data, errors=errors, mon=monitor.overview(),
                           tz=monitor.tz_name(), zones=sorted(available_timezones()), day_labels=DAY_LABELS,
                           on_days=set(str(data["check_days"]).split(",")))


@bp.route("/monitoring/run", methods=["POST"])
def run_now():
    auth.require("run_checks")
    if monitor.run_in_background("manual"):
        flash("Checks started. This page refreshes while they run.", "ok")
    else:
        flash("A monitoring run is already in progress", "err")
    return redirect(url_for("mon.monitoring"))


@bp.route("/history")
def history():
    auth.require("history")
    a = request.args
    q = H.query
    if a.get("target_type") in ("device", "service"):
        q = q.filter(H.target_type == a["target_type"])
    if a.get("target_id", type=int):
        q = q.filter(H.target_id == a.get("target_id", type=int))
    if a.get("status") in ("online", "offline"):
        q = q.filter(H.status == a["status"])
    if a.get("check") in ("ping", "tcp", "http", "web"):
        q = q.filter(H.check_type == a["check"])
    if a.get("final") == "1":
        q = q.filter(H.is_final.is_(True))
    page, per = max(a.get("page", 1, type=int), 1), 100
    rows = q.order_by(H.id.desc()).offset((page - 1) * per).limit(per + 1).all()
    names = {"device": {d.id: d.name for d in Device.query}, "service": {s.id: s.name for s in Service.query}}
    return render_template("history.html", rows=rows[:per], more=len(rows) > per, page=page, names=names, args=a)


@bp.route("/settings", methods=["GET", "POST"])
def settings():
    auth.require("settings")
    if request.method == "POST":
        f = V.Form(request.form)
        lock = f.get("cred_lock_minutes", V.number, int, 0, 1440, "Lock timeout")
        keep = f.get("history_days", V.number, int, 0, 3650, "History retention")
        if f.errors:
            for msg in f.errors.values():
                flash(msg, "err")
        else:
            S.set_many({"cred_lock_minutes": 5 if lock is None else lock, "history_days": 90 if keep is None else keep})
            flash("Settings saved", "ok")
            return redirect(url_for("mon.settings"))
    return render_template("settings.html", lock=S.get("cred_lock_minutes"), keep=S.get("history_days"))


@bp.route("/settings/pin", methods=["POST"])
def change_pin():
    auth.require("settings")
    new, confirm = request.form.get("new", ""), request.form.get("confirm", "")
    if security.pin_is_set():
        ok, msg = security.verify_pin(request.form.get("current", ""))
        if not ok:
            flash(msg or "Current PIN is wrong", "err")
            return redirect(url_for("mon.settings"))
    if not 4 <= len(new) <= 32 or new != confirm:
        flash("New PIN must be 4-32 characters and match its confirmation", "err")
    else:
        security.set_pin(new)
        flash("PIN changed", "ok")
    return redirect(url_for("mon.settings"))
