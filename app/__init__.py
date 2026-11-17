"""Digital Evidence Chain-of-Custody System - application factory."""
import os
import secrets

from flask import Flask, abort, request, session
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"


def _csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def create_app(config_object="config.Config"):
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_object)

    os.makedirs(app.config["EVIDENCE_STORE"], exist_ok=True)
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:///") and ":memory:" not in app.config["SQLALCHEMY_DATABASE_URI"]:
        os.makedirs(os.path.dirname(app.config["SQLALCHEMY_DATABASE_URI"][10:]), exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Simple CSRF protection for every POST form
    @app.before_request
    def csrf_protect():
        if request.method == "POST" and app.config.get("WTF_CSRF_ENABLED", True):
            token = session.get("_csrf")
            if not token or token != request.form.get("csrf_token"):
                abort(400, "Invalid or missing CSRF token")

    app.jinja_env.globals["csrf_token"] = _csrf_token

    from .routes.auth import bp as auth_bp
    from .routes.main import bp as main_bp
    from .routes.cases import bp as cases_bp
    from .routes.evidence import bp as evidence_bp
    from .routes.transfers import bp as transfers_bp
    from .routes.admin import bp as admin_bp

    for bp in (auth_bp, main_bp, cases_bp, evidence_bp, transfers_bp, admin_bp):
        app.register_blueprint(bp)

    @app.template_filter("dt")
    def fmt_dt(value):
        return value.strftime("%Y-%m-%d %H:%M") if value else "-"

    @app.template_filter("size")
    def fmt_size(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    with app.app_context():
        db.create_all()

    from .cli import register_cli
    register_cli(app)

    if app.config["INTEGRITY_CHECK_INTERVAL_MIN"] > 0 and not app.config.get("TESTING"):
        from .services.integrity import start_scheduler
        start_scheduler(app)

    return app
