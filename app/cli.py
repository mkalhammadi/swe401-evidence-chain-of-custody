"""Flask CLI commands: init-db, seed-demo, verify-all, verify-chain."""
import io

import click

from . import db
from .models import Role, User


def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        """Create all tables."""
        db.create_all()
        click.echo("Database tables created.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--email", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def create_admin(username, email, password):
        u = User(username=username, full_name="System Administrator", email=email, role=Role.ADMIN)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        click.echo(f"Admin {username} created.")

    @app.cli.command("seed-demo")
    def seed_demo():
        """Create demo users, cases and evidence for the live demo."""
        from .seed import seed
        seed()
        click.echo("Demo data created. All demo passwords: Demo@12345")

    @app.cli.command("verify-all")
    def verify_all_cmd():
        """Run the integrity check on every evidence item now."""
        from .services.integrity import verify_all
        click.echo(verify_all())

    @app.cli.command("verify-chain")
    def verify_chain_cmd():
        """Check that the audit log hash chain is intact."""
        from .services.audit import verify_chain
        ok, n, bad = verify_chain()
        click.echo(f"Chain intact ({n} entries)" if ok else f"Chain BROKEN at entry #{bad}")
