from functools import wraps

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from sqlalchemy import or_

from . import auth, security, validators as V
from .models import db, CRED_KINDS, Credential, Device, Service

bp = Blueprint("cred", __name__, url_prefix="/credentials")


def _safe_next(default="cred.index"):
    nxt = (request.values.get("next") or "").rstrip("?")
    return nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for(default)


def guard(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        auth.require("cred_view")
        if not security.pin_is_set():
            if not auth.can("settings"):
                return render_template("pin.html", mode="wait")
            return redirect(url_for("cred.setup", next=request.full_path))
        if not security.is_unlocked():
            if request.path.endswith("/reveal"):
                return jsonify(error="locked"), 403
            return redirect(url_for("cred.unlock", next=request.full_path))
        security.touch()
        return fn(*a, **kw)
    return wrapper


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    auth.require("settings")
    if security.pin_is_set():
        return redirect(url_for("cred.unlock"))
    if request.method == "POST":
        pin, confirm = request.form.get("pin", ""), request.form.get("confirm", "")
        if len(pin) < 4 or len(pin) > 32:
            flash("Use a PIN of 4 to 32 characters", "err")
        elif pin != confirm:
            flash("The PINs do not match", "err")
        else:
            security.set_pin(pin)
            security.unlock()
            flash("PIN set. Credentials are unlocked.", "ok")
            return redirect(_safe_next())
    return render_template("pin.html", mode="setup", next=request.values.get("next", ""))


@bp.route("/unlock", methods=["GET", "POST"])
def unlock():
    auth.require("cred_view")
    if not security.pin_is_set():
        return redirect(url_for("cred.setup", next=request.values.get("next", "")))
    if request.method == "POST":
        ok, msg = security.verify_pin(request.form.get("pin", ""))
        if ok:
            security.unlock()
            return redirect(_safe_next())
        flash(msg, "err")
    return render_template("pin.html", mode="unlock", next=request.values.get("next", ""))


@bp.route("/lock", methods=["POST"])
def lock():
    security.lock()
    flash("Credentials locked", "ok")
    return redirect(url_for("inv.dashboard"))


@bp.route("/")
@guard
def index():
    q, kind = request.args.get("q", "").strip(), request.args.get("kind", "")
    query = Credential.query.outerjoin(Service, Credential.service_id == Service.id).outerjoin(
        Device, Credential.device_id == Device.id)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Credential.description.ilike(like), Credential.username.ilike(like),
                                 Credential.login_url.ilike(like), Service.name.ilike(like), Device.name.ilike(like)))
    if kind in dict(CRED_KINDS):
        query = query.filter(Credential.kind == kind)
    return render_template("credentials.html", creds=query.order_by(Credential.description, Credential.id).all(),
                           q=q, kind=kind, kinds=CRED_KINDS)


@bp.route("/new", methods=["GET", "POST"])
@bp.route("/<int:id>/edit", methods=["GET", "POST"])
@guard
def form(id=None):
    auth.require("cred_manage")
    c = db.get_or_404(Credential, id) if id else None
    errors = {}
    if request.method == "POST":
        f = V.Form(request.form)
        service_id = f.get("service_id", V.number, int, 1, 10**9, "Service")
        device_id = f.get("device_id", V.number, int, 1, 10**9, "Device")
        if service_id and not db.session.get(Service, service_id):
            f.errors["service_id"] = "Unknown service"
        if device_id and not db.session.get(Device, device_id):
            f.errors["device_id"] = "Unknown device"
        username = f.get("username", V.text, "Username", False, 200)
        password, api_key = request.form.get("password", ""), request.form.get("api_key", "")
        vals = dict(service_id=service_id, device_id=device_id, username=username,
                    kind=f.get("kind", lambda v: V.choice(v or "login", tuple(k for k, _ in CRED_KINDS))), port=f.get("port", V.port),
                    login_url=f.get("login_url", V.url), description=f.get("description", V.text, "Description", False, 500),
                    notes=f.get("notes", V.text, "Notes", False, 5000))
        if not c and not (username or password or api_key):
            f.errors["username"] = "Enter a username, a password or an API key"
        errors = f.errors
        if not errors:
            c = c or Credential()
            for k, v in vals.items():
                setattr(c, k, v)
            for field, value, attr in (("password", password, "encrypted_password"), ("api_key", api_key, "encrypted_api_key")):
                if value:                                  # blank on edit = keep what is stored
                    setattr(c, attr, security.encrypt(value))
                elif "clear_" + field in request.form:
                    setattr(c, attr, "")
            db.session.add(c)
            db.session.commit()
            flash("Credential saved", "ok")
            return redirect(_safe_next())
    data = {k: getattr(c, k, None) for k in ("service_id", "device_id", "kind", "port", "username", "login_url", "description", "notes")}
    if not c and request.method == "GET":
        data.update(service_id=request.args.get("service_id", type=int), device_id=request.args.get("device_id", type=int),
                    kind=request.args.get("kind") if request.args.get("kind") in dict(CRED_KINDS) else "login")
    if request.method == "POST":
        data.update({k: v for k, v in request.form.to_dict().items() if k not in ("password", "api_key")})
    return render_template("credential_form.html", c=c, data=data, errors=errors, kinds=CRED_KINDS,
                           services=Service.query.order_by(Service.name).all(), devices=Device.query.order_by(Device.name).all())


@bp.route("/<int:id>/delete", methods=["POST"])
@guard
def delete(id):
    auth.require("cred_manage")
    db.session.delete(db.get_or_404(Credential, id))
    db.session.commit()
    flash("Credential deleted", "ok")
    return redirect(_safe_next())


@bp.route("/<int:id>/reveal", methods=["POST"])
@guard
def reveal(id):
    """The only endpoint that ever returns a secret; requires an unlocked session. ?field=password|api_key"""
    c = db.get_or_404(Credential, id)
    token = c.encrypted_api_key if request.args.get("field") == "api_key" else c.encrypted_password
    value = security.decrypt(token)
    if value is None:
        return jsonify(error="Could not decrypt: is this the same encryption key that was used when it was saved?"), 500
    return jsonify(password=value)
