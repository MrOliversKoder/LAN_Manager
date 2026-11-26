from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from . import auth, validators as V
from .models import db, Group, User

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
def _admin_only():
    auth.require("admin")


@bp.route("/")
def index():
    return redirect(url_for("admin.users"))


@bp.route("/users")
def users():
    return render_template("admin_users.html", users=User.query.order_by(User.username).all())


@bp.route("/users/new", methods=["GET", "POST"])
@bp.route("/users/<int:id>/edit", methods=["GET", "POST"])
def user_form(id=None):
    u = db.get_or_404(User, id) if id else None
    me = auth.current_user()
    errors = {}
    if request.method == "POST":
        f = V.Form(request.form)
        name = u.username if u else f.get("username", auth.valid_username)
        group_id = f.get("group_id", V.number, int, 1, 10**9, "Group")
        group = db.session.get(Group, group_id) if group_id else None
        if not group:
            errors["group_id"] = "Choose a group"
        active = "is_active" in request.form
        pw = request.form.get("password", "")
        if not u or pw:
            try:
                auth.valid_password(pw)
            except ValueError as e:
                errors["password"] = str(e)
        if name and not u and User.query.filter_by(username=name).first():
            errors["username"] = "That username is taken"
        if u and u.id == me.id and (not active or (group and "admin" not in group.perm_set)):
            errors["group_id"] = "You cannot disable yourself or remove your own admin rights"
        errors.update(f.errors)
        if not errors:
            u = u or User(username=name)
            u.group_id, u.is_active = group.id, active
            if pw:
                u.password_hash = generate_password_hash(pw)
            db.session.add(u)
            db.session.commit()
            if u.id == me.id and pw:
                auth.start_session(u)
            flash("User saved", "ok")
            return redirect(url_for("admin.users"))
    data = {"username": u.username if u else "", "group_id": u.group_id if u else None,
            "is_active": u.is_active if u else True}
    if request.method == "POST":
        data.update(request.form.to_dict())
        data["is_active"] = "is_active" in request.form
    return render_template("admin_user_form.html", u=u, data=data, errors=errors,
                           groups=Group.query.order_by(Group.name).all())


@bp.route("/users/<int:id>/delete", methods=["POST"])
def user_delete(id):
    u = db.get_or_404(User, id)
    if u.id == auth.current_user().id:
        flash("You cannot delete your own account", "err")
    else:
        db.session.delete(u)
        db.session.commit()
        flash("User deleted", "ok")
    return redirect(url_for("admin.users"))


@bp.route("/groups")
def groups():
    return render_template("admin_groups.html", groups=Group.query.order_by(Group.name).all(), perms=dict(auth.PERMISSIONS))


@bp.route("/groups/new", methods=["GET", "POST"])
@bp.route("/groups/<int:id>/edit", methods=["GET", "POST"])
def group_form(id=None):
    g = db.get_or_404(Group, id) if id else None
    if g and g.is_system:
        flash("The Administrator group is built in and cannot be changed", "err")
        return redirect(url_for("admin.groups"))
    errors = {}
    if request.method == "POST":
        f = V.Form(request.form)
        name = f.get("name", V.text, "Name", True, 60)
        perms = [k for k, _ in auth.ASSIGNABLE if k in request.form.getlist("perms")]
        clash = Group.query.filter(Group.name == name, Group.id != (g.id if g else 0)).first() if name else None
        if clash:
            f.errors["name"] = "A group with that name exists"
        if not perms:
            f.errors["perms"] = "Select at least one permission"
        errors = f.errors
        if not errors:
            g = g or Group()
            g.name, g.permissions = name, ",".join(perms)
            g.description = V.text(request.form.get("description"), "Description", False, 300)
            db.session.add(g)
            db.session.commit()
            flash("Group saved", "ok")
            return redirect(url_for("admin.groups"))
    data = {"name": g.name if g else "", "description": g.description if g else ""}
    chosen = set(request.form.getlist("perms")) if request.method == "POST" else (g.perm_set if g else set())
    if request.method == "POST":
        data.update(request.form.to_dict())
    return render_template("admin_group_form.html", g=g, data=data, errors=errors, chosen=chosen, perms=auth.ASSIGNABLE)


@bp.route("/groups/<int:id>/delete", methods=["POST"])
def group_delete(id):
    g = db.get_or_404(Group, id)
    if g.is_system:
        abort(403)
    if g.users:
        flash(f"{len(g.users)} user(s) are in this group. Move them to another group first.", "err")
    else:
        db.session.delete(g)
        db.session.commit()
        flash("Group deleted", "ok")
    return redirect(url_for("admin.groups"))
