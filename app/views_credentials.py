from functools import wraps

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from sqlalchemy import or_

from . import security, validators as V
from .models import db, Credential, Service

bp = Blueprint("cred", __name__, url_prefix="/credentials")


def _safe_next(default="cred.index"):
    nxt = (request.values.get("next") or "").rstrip("?")
    return nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for(default)


def guard(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not security.pin_is_set():
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
    q = request.args.get("q", "").strip()
    query = Credential.query.outerjoin(Service)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Credential.description.ilike(like), Credential.username.ilike(like),
                                 Credential.login_url.ilike(like), Service.name.ilike(like)))
    return render_template("credentials.html", creds=query.order_by(Credential.description, Credential.id).all(), q=q)


@bp.route("/new", methods=["GET", "POST"])
@bp.route("/<int:id>/edit", methods=["GET", "POST"])
@guard
def form(id=None):
    c = db.get_or_404(Credential, id) if id else None
    errors = {}
    if request.method == "POST":
        f = V.Form(request.form)
        service_id = f.get("service_id", V.number, int, 1, 10**9, "Service")
        if service_id and not db.session.get(Service, service_id):
            f.errors["service_id"] = "Unknown service"
        username = f.get("username", V.text, "Username", False, 200)
        password = request.form.get("password", "")
        vals = dict(service_id=service_id, username=username, login_url=f.get("login_url", V.url),
                    description=f.get("description", V.text, "Description", False, 500),
                    notes=f.get("notes", V.text, "Notes", False, 5000))
        if not username and not password and not c:
            f.errors["username"] = "Enter a username or a password"
        errors = f.errors
        if not errors:
            c = c or Credential()
            for k, v in vals.items():
                setattr(c, k, v)
            if password:                       # blank on edit = keep the stored password
                c.encrypted_password = security.encrypt(password)
            db.session.add(c)
            db.session.commit()
            flash("Credential saved", "ok")
            return redirect(_safe_next())
    data = {k: getattr(c, k, None) for k in ("service_id", "username", "login_url", "description", "notes")}
    if not c and request.method == "GET":
        data["service_id"] = request.args.get("service_id", type=int)
    if request.method == "POST":
        data.update({k: v for k, v in request.form.to_dict().items() if k != "password"})
    return render_template("credential_form.html", c=c, data=data, errors=errors,
                           services=Service.query.order_by(Service.name).all())


@bp.route("/<int:id>/delete", methods=["POST"])
@guard
def delete(id):
    db.session.delete(db.get_or_404(Credential, id))
    db.session.commit()
    flash("Credential deleted", "ok")
    return redirect(_safe_next())


@bp.route("/<int:id>/reveal", methods=["POST"])
@guard
def reveal(id):
    """The only endpoint that ever returns a password; requires an unlocked session."""
    pw = security.decrypt(db.get_or_404(Credential, id).encrypted_password)
    if pw is None:
        return jsonify(error="Could not decrypt: is LAN_ENCRYPTION_KEY the same key used when this was saved?"), 500
    return jsonify(password=pw)
