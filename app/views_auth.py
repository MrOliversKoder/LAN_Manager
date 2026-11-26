from flask import Blueprint, flash, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import auth
from .models import db, Group, User, utcnow

bp = Blueprint("auth", __name__)


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    """First run only: create the administrator account."""
    if User.query.count():
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        try:
            name = auth.valid_username(request.form.get("username"))
            pw = auth.valid_password(request.form.get("password"))
            if pw != request.form.get("confirm"):
                raise ValueError("The passwords do not match")
        except ValueError as e:
            flash(str(e), "err")
        else:
            admin = Group.query.filter_by(name="Administrator").first()
            user = User(username=name, password_hash=generate_password_hash(pw), group_id=admin.id, last_login=utcnow())
            db.session.add(user)
            db.session.commit()
            auth.start_session(user)
            flash("Administrator account created", "ok")
            return redirect(url_for("inv.dashboard"))
    return render_template("login.html", mode="setup")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if auth.current_user():
        return redirect(url_for(auth.landing()))
    if request.method == "POST":
        user, msg = auth.attempt_login(request.form.get("username"), request.form.get("password"))
        if user:
            nxt = auth.safe_next(None)
            user.last_login = utcnow()
            db.session.commit()
            auth.start_session(user)
            return redirect(nxt or url_for(auth.landing()))
        flash(msg, "err")
    return render_template("login.html", mode="login", next=request.values.get("next", ""))


@bp.route("/logout", methods=["POST"])
def logout():
    from flask import session
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/account", methods=["GET", "POST"])
def account():
    user = auth.current_user()
    if request.method == "POST":
        try:
            if not check_password_hash(user.password_hash, request.form.get("current", "")):
                raise ValueError("Current password is wrong")
            pw = auth.valid_password(request.form.get("new"))
            if pw != request.form.get("confirm"):
                raise ValueError("The new passwords do not match")
        except ValueError as e:
            flash(str(e), "err")
        else:
            user.password_hash = generate_password_hash(pw)
            db.session.commit()
            auth.start_session(user)       # other sessions of this user are signed out
            flash("Password changed", "ok")
            return redirect(url_for("auth.account"))
    return render_template("account.html")
