from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for
from sqlalchemy import or_

from . import auth, monitor, security, settings as S, validators as V
from .models import db, Credential, Device, MonitorHistory as H, Service, build_url

bp = Blueprint("inv", __name__)

DEVICE_TYPES = ["Server", "NAS", "Desktop", "Raspberry Pi", "Network equipment", "Virtual machine", "Other"]
MON_KEYS = ["mon_enabled", "check_method", "timeout", "retries", "retry_delay"]
DEVICE_KEYS = ["name", "ip_address", "hostname", "description", "device_type", "notes", "check_port",
               "web_protocol", "web_port", "web_path", "web_url"] + MON_KEYS
SERVICE_KEYS = ["name", "description", "device_id", "ip_address", "port", "protocol", "access_path",
                "quick_access_url", "management_type", "management_service_id", "management_url",
                "ssh_host", "ssh_port", "ssh_username", "management_notes", "notes",
                "http_expected"] + MON_KEYS


def _data(obj, keys):
    data = {k: getattr(obj, k, None) for k in keys} if obj else {"mon_enabled": True, "protocol": "http",
                                                                   "management_type": "direct"}
    if request.method == "POST":
        data.update(request.form.to_dict())
        data["mon_enabled"] = "mon_enabled" in request.form
    return data


def _mon_fields(f, is_device):
    return dict(
        mon_enabled="mon_enabled" in request.form,
        check_method=f.get("check_method", V.choice, ("ping", "tcp", "http") if is_device else ("tcp", "tcp_http", "http", "ping")),
        timeout=f.get("timeout", V.number, float, 0.5, 60, "Timeout"),
        retries=f.get("retries", V.number, int, 0, 10, "Retries"),
        retry_delay=f.get("retry_delay", V.number, int, 0, 3600, "Retry delay"))


def _status_filter(items, st, wanted):
    return [i for i in items if wanted in ("", None) or st[i.id]["status"] == wanted]


def link_services_by_ip(device):
    """Unassigned services whose IP equals the device IP belong to that device."""
    found = Service.query.filter(Service.device_id.is_(None), Service.ip_address == device.ip_address).all()
    for sv in found:
        sv.device_id = device.id
    return len(found)


# ---- dashboard & search ------------------------------------------------------------
@bp.route("/")
def dashboard():
    if not auth.can("view"):
        return redirect(url_for(auth.landing()))
    devices = Device.query.order_by(Device.name).all()
    services = Service.query.order_by(Service.name).all()
    dst, sst = monitor.summaries("device"), monitor.summaries("service")
    counts = {}
    for name, items, st in (("devices", devices, dst), ("services", services, sst)):
        statuses = [st[i.id]["status"] for i in items]
        counts[name] = dict(total=len(items), online=statuses.count("online"), offline=statuses.count("offline"),
                            unknown=statuses.count("unknown"))
    return render_template("dashboard.html", devices=devices, services=services, dst=dst, sst=sst,
                           mon=monitor.overview(), counts=counts)


@bp.route("/search")
def search():
    auth.require("view")
    q = request.args.get("q", "").strip()
    devices = services = creds = []
    if q:
        like = f"%{q}%"
        devices = Device.query.filter(or_(Device.name.ilike(like), Device.ip_address.ilike(like),
                                          Device.hostname.ilike(like), Device.description.ilike(like),
                                          Device.device_type.ilike(like))).order_by(Device.name).all()
        services = Service.query.outerjoin(Device).filter(or_(
            Service.name.ilike(like), Service.description.ilike(like), Service.ip_address.ilike(like),
            Device.ip_address.ilike(like), Device.name.ilike(like))).order_by(Service.name).all()
        if auth.can("cred_view") and security.is_unlocked():
            creds = Credential.query.outerjoin(Service).filter(or_(
                Credential.description.ilike(like), Credential.username.ilike(like),
                Credential.login_url.ilike(like), Service.name.ilike(like))).all()
    return render_template("search.html", q=q, devices=devices, services=services, creds=creds,
                           dst=monitor.summaries("device"), sst=monitor.summaries("service"))


# ---- devices -------------------------------------------------------------------------
@bp.route("/devices")
def devices():
    auth.require("view")
    q, status = request.args.get("q", "").strip(), request.args.get("status", "")
    query = Device.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Device.name.ilike(like), Device.ip_address.ilike(like),
                                 Device.hostname.ilike(like), Device.description.ilike(like)))
    st = monitor.summaries("device")
    items = _status_filter(query.order_by(Device.name).all(), st, status)
    return render_template("devices.html", devices=items, st=st, q=q, status=status)


@bp.route("/devices/<int:id>")
def device_detail(id):
    auth.require("view")
    d = db.get_or_404(Device, id)
    hist = H.query.filter_by(target_type="device", target_id=id).order_by(H.id.desc()).limit(15).all()
    movable = Service.query.filter(or_(Service.device_id.is_(None), Service.device_id != id)).order_by(
        Service.device_id.is_(None).desc(), Service.name).all()
    return render_template("device_detail.html", d=d, s=monitor.summaries("device")[id], sst=monitor.summaries("service"),
                           hist=hist, movable=movable, checking=monitor.target_running("device", id))


@bp.route("/devices/new", methods=["GET", "POST"])
@bp.route("/devices/<int:id>/edit", methods=["GET", "POST"])
def device_form(id=None):
    auth.require("edit" if id else "add")
    d = db.get_or_404(Device, id) if id else None
    errors = {}
    if request.method == "POST":
        f = V.Form(request.form)
        vals = dict(name=f.get("name", V.text, "Name", True, 120), ip_address=f.get("ip_address", V.ip),
                    hostname=f.get("hostname", V.host), description=f.get("description", V.text, "Description"),
                    device_type=f.get("device_type", V.text, "Type", False, 60),
                    notes=f.get("notes", V.text, "Notes", False, 5000), check_port=f.get("check_port", V.port),
                    web_protocol=f.get("web_protocol", V.choice, ("", "http", "https")) or None,
                    web_port=f.get("web_port", V.port), web_path=V.path(request.form.get("web_path")),
                    web_url=f.get("web_url", V.url))
        vals.update(_mon_fields(f, True))
        if vals["check_method"] == "http" and not (vals["web_url"] or vals["web_port"] or vals["web_protocol"]) \
                and "web_url" not in f.errors:
            f.errors["web_url"] = "Set a web address (protocol/port or a custom URL) to use HTTP checks"
        if vals["check_method"] == "tcp" and not vals["check_port"] and "check_port" not in f.errors:
            f.errors["check_port"] = "A port is required for TCP checks"
        errors = f.errors
        if not errors:
            d = d or Device()
            for k, v in vals.items():
                setattr(d, k, v)
            db.session.add(d)
            db.session.flush()
            linked = link_services_by_ip(d)
            db.session.commit()
            flash("Device saved" + (f". {linked} existing service(s) with the same IP were linked to it." if linked else ""), "ok")
            return redirect(url_for("inv.device_detail", id=d.id))
    return render_template("device_form.html", d=d, data=_data(d, DEVICE_KEYS), errors=errors, types=DEVICE_TYPES)


@bp.route("/devices/<int:id>/delete", methods=["POST"])
def device_delete(id):
    auth.require("delete")
    d = db.get_or_404(Device, id)
    monitor.purge_history("service", [s.id for s in d.services])
    monitor.purge_history("device", [id])
    db.session.delete(d)  # services are deleted with it; their credentials are kept, unlinked
    db.session.commit()
    flash("Device deleted", "ok")
    return redirect(url_for("inv.devices"))


# ---- services ------------------------------------------------------------------------
@bp.route("/services")
def services():
    auth.require("view")
    q, dev, mt = request.args.get("q", "").strip(), request.args.get("device", type=int), request.args.get("mtype", "")
    query = Service.query.outerjoin(Device)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Service.name.ilike(like), Service.description.ilike(like),
                                 Service.ip_address.ilike(like), Device.ip_address.ilike(like)))
    if dev:
        query = query.filter(Service.device_id == dev)
    if mt:
        query = query.filter(Service.management_type == mt)
    return render_template("services.html", services=query.order_by(Service.name).all(), sst=monitor.summaries("service"),
                           devices=Device.query.order_by(Device.name).all(), q=q, dev=dev, mt=mt)


@bp.route("/services/<int:id>")
def service_detail(id):
    auth.require("view")
    s = db.get_or_404(Service, id)
    hist = H.query.filter_by(target_type="service", target_id=id).order_by(H.id.desc()).limit(15).all()
    return render_template("service_detail.html", s=s, st=monitor.summaries("service")[id], hist=hist,
                           checking=monitor.target_running("service", id))


@bp.route("/services/new", methods=["GET", "POST"])
@bp.route("/services/<int:id>/edit", methods=["GET", "POST"])
def service_form(id=None):
    auth.require("edit" if id else "add")
    s = db.get_or_404(Service, id) if id else None
    errors = {}
    if request.method == "POST":
        f = V.Form(request.form)
        device_id = f.get("device_id", V.number, int, 1, 10**9, "Device")
        if device_id and not db.session.get(Device, device_id):
            f.errors["device_id"] = "Unknown device"
        vals = dict(
            name=f.get("name", V.text, "Name", True, 120), description=f.get("description", V.text, "Description"),
            device_id=device_id, ip_address=f.get("ip_address", V.ip, False), port=f.get("port", V.port),
            protocol=f.get("protocol", V.choice, ("http", "https")), access_path=V.path(request.form.get("access_path")),
            quick_access_url=f.get("quick_access_url", V.url),
            management_type=f.get("management_type", V.choice, ("direct", "external", "manual")),
            management_service_id=f.get("management_service_id", V.number, int, 1, 10**9, "Management service"),
            management_url=f.get("management_url", V.url), ssh_host=f.get("ssh_host", V.host),
            ssh_port=f.get("ssh_port", V.port), ssh_username=f.get("ssh_username", V.text, "Username", False, 120),
            management_notes=f.get("management_notes", V.text, "Notes", False, 5000),
            notes=f.get("notes", V.text, "Notes", False, 5000),
            http_expected=f.get("http_expected", V.expected_status))
        vals.update(_mon_fields(f, False))
        if not vals["device_id"] and not vals["ip_address"] and not f.errors:
            f.errors["ip_address"] = "Choose a device or enter an IP address"
        if vals["management_service_id"] and s and vals["management_service_id"] == s.id:
            f.errors["management_service_id"] = "A service cannot manage itself"
        if vals["management_type"] != "external":
            vals["management_service_id"] = vals["management_url"] = None
        if vals["management_type"] != "manual":
            vals["ssh_host"] = vals["ssh_port"] = vals["ssh_username"] = None
        errors = f.errors
        if not errors:
            s = s or Service()
            for k, v in vals.items():
                setattr(s, k, v)
            note = ""
            if not s.device_id and s.ip_address:          # same IP as a known device -> it belongs to that device
                match = Device.query.filter_by(ip_address=s.ip_address).order_by(Device.id).first()
                if match:
                    s.device_id, note = match.id, f". Linked to {match.name} (same IP address)."
            db.session.add(s)
            db.session.commit()
            flash("Service saved" + note, "ok")
            return redirect(url_for("inv.service_detail", id=s.id))
    data = _data(s, SERVICE_KEYS)
    if not s and request.method == "GET":
        data["device_id"] = request.args.get("device_id", type=int)
    others = Service.query.filter(Service.id != (s.id if s else 0)).order_by(Service.name).all()
    return render_template("service_form.html", s=s, data=data, errors=errors, others=others,
                           devices=Device.query.order_by(Device.name).all())


@bp.route("/services/<int:id>/delete", methods=["POST"])
def service_delete(id):
    auth.require("delete")
    s = db.get_or_404(Service, id)
    monitor.purge_history("service", [id])
    db.session.delete(s)  # linked credentials are kept (unlinked), never silently destroyed
    db.session.commit()
    flash("Service deleted", "ok")
    return redirect(url_for("inv.services"))


# ---- "Test connection" (used by the Add/Edit forms; nothing is saved) --------------------
@bp.route("/api/test-check", methods=["POST"])
def test_check():
    auth.require("add", "edit")
    kind = "device" if request.args.get("kind") == "device" else "service"
    f = V.Form(request.form)
    timeout = f.get("timeout", V.number, float, 0.5, 10, "Timeout") or S.get_float("tcp_timeout")
    if kind == "device":
        host = f.get("ip_address", V.ip)
        port = f.get("check_port", V.port) or f.get("web_port", V.port)
        url = f.get("web_url", V.url) or (build_url(request.form.get("web_protocol") or "http", host,
                                                    port if request.form.get("web_port") else None,
                                                    V.path(request.form.get("web_path")))
                                         if request.form.get("web_port") or request.form.get("web_protocol") else None)
    else:
        dev = db.session.get(Device, request.form.get("device_id", type=int)) if request.form.get("device_id") else None
        host = f.get("ip_address", V.ip, False) or (dev.ip_address if dev else None)
        proto = request.form.get("protocol") if request.form.get("protocol") in ("http", "https") else "http"
        port = f.get("port", V.port) or (443 if proto == "https" else 80)
        url = build_url(proto, host, f.get("port", V.port), V.path(request.form.get("access_path")))
        if not host and "ip_address" not in f.errors:
            f.errors["ip_address"] = "Choose a device or enter an IP address first"
    if f.errors or not host:
        return jsonify(error=" ".join(f.errors.values()) or "Enter an IP address first"), 400
    results, pick = monitor.run_test(kind, host, port, url, timeout)
    return jsonify(results=results, recommended=pick, host=host)


# ---- attach services to a device / manual check --------------------------------------
@bp.route("/devices/<int:id>/attach", methods=["POST"])
def device_attach(id):
    auth.require("edit")
    d = db.get_or_404(Device, id)
    sv = db.session.get(Service, request.form.get("service_id", type=int) or 0)
    if not sv:
        flash("Choose a service to attach", "err")
    else:
        sv.device_id = d.id
        db.session.commit()
        flash(f"{sv.name} now belongs to {d.name}", "ok")
    return redirect(url_for("inv.device_detail", id=id))


@bp.route("/devices/<int:id>/link-by-ip", methods=["POST"])
def device_link_by_ip(id):
    auth.require("edit")
    d = db.get_or_404(Device, id)
    n = link_services_by_ip(d)
    db.session.commit()
    flash(f"{n} service(s) with IP {d.ip_address} were linked" if n else f"No unassigned service has IP {d.ip_address}", "ok" if n else "err")
    return redirect(url_for("inv.device_detail", id=id))


@bp.route("/<kind>/<int:id>/check", methods=["POST"])
def check_now(kind, id):
    auth.require("run_checks")
    if kind not in ("devices", "services"):
        abort(404)
    target = "device" if kind == "devices" else "service"
    db.get_or_404(Device if target == "device" else Service, id)
    if monitor.run_target_in_background(target, id):
        flash("Check started. This page refreshes until it finishes.", "ok")
    else:
        flash("A check of this item is already running", "err")
    return redirect(url_for("inv.device_detail" if target == "device" else "inv.service_detail", id=id))
