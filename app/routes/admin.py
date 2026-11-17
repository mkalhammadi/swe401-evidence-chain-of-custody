from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from .. import db
from ..models import Role, User
from ..services.audit import Action, log_event
from . import roles_required

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/users", methods=["GET", "POST"])
@login_required
@roles_required(Role.ADMIN)
def users():
    if request.method == "POST":
        f = request.form
        username, email = f.get("username", "").strip(), f.get("email", "").strip()
        password, role = f.get("password", ""), f.get("role", Role.INVESTIGATOR)
        error = None
        if not username or not email or not f.get("full_name", "").strip():
            error = "Username, full name and email are required."
        elif len(password) < 10 or password.isalpha() or password.isdigit():
            error = "Password must be at least 10 characters and mix letters with numbers or symbols."
        elif role not in Role.ALL:
            error = "Unknown role."
        elif User.query.filter((User.username == username) | (User.email == email)).first():
            error = "That username or email is already in use."
        if error:
            flash(error, "danger")
        else:
            u = User(username=username, full_name=f.get("full_name").strip(), email=email, role=role)
            u.set_password(password)
            db.session.add(u)
            db.session.flush()
            log_event(Action.USER_CREATED, user=current_user, details=f"username={username}; role={role}")
            flash(f"User {username} created.", "success")
            return redirect(url_for("admin.users"))
    return render_template("admin/users.html", users=User.query.order_by(User.id).all(), roles=Role.ALL)


@bp.route("/users/<int:user_id>", methods=["POST"])
@login_required
@roles_required(Role.ADMIN)
def update_user(user_id):
    u = db.get_or_404(User, user_id)
    role = request.form.get("role")
    active = request.form.get("active") == "1"
    if u.id == current_user.id and (not active or role != Role.ADMIN):
        flash("You cannot remove your own admin access.", "danger")
        return redirect(url_for("admin.users"))
    if role in Role.ALL:
        u.role = role
    u.active = active
    db.session.flush()
    log_event(Action.USER_UPDATED, user=current_user, details=f"username={u.username}; role={u.role}; active={u.active}")
    flash(f"User {u.username} updated.", "success")
    return redirect(url_for("admin.users"))
