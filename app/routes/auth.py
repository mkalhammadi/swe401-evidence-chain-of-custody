from datetime import timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .. import db
from ..models import User, utcnow
from ..services.audit import Action, log_event

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        cfg = current_app.config

        if user and user.locked_until and user.locked_until > utcnow():
            flash("This account is temporarily locked after too many failed attempts. Try again later.", "danger")
            return render_template("login.html"), 423

        if user is None or not user.check_password(password) or not user.active:
            if user is not None:
                user.failed_logins += 1
                if user.failed_logins >= cfg["FAILED_LOGIN_LIMIT"]:
                    user.locked_until = utcnow() + timedelta(minutes=cfg["LOCKOUT_MINUTES"])
                    user.failed_logins = 0
                db.session.commit()
                log_event(Action.LOGIN_FAILED, user=user, details="wrong password or inactive account")
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401

        user.failed_logins = 0
        user.locked_until = None
        db.session.commit()
        session.permanent = True
        login_user(user)
        log_event(Action.LOGIN, user=user)
        return redirect(request.args.get("next") or url_for("main.dashboard"))
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event(Action.LOGOUT, user=current_user)
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
