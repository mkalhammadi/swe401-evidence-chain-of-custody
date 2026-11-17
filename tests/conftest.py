import io
import os
import shutil
import tempfile

import pytest

from app import create_app, db
from app.models import Case, Role, User
from config import TestConfig


@pytest.fixture
def app():
    store = tempfile.mkdtemp(prefix="coc-test-")

    class Cfg(TestConfig):
        EVIDENCE_STORE = store

    app = create_app(Cfg)
    with app.app_context():
        for username, role in [("admin", Role.ADMIN), ("sup", Role.SUPERVISOR), ("inv", Role.INVESTIGATOR),
                               ("inv2", Role.INVESTIGATOR), ("aud", Role.AUDITOR)]:
            u = User(username=username, full_name=username.title(), email=f"{username}@t.local", role=role)
            u.set_password("Passw0rd!x")
            db.session.add(u)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()
    shutil.rmtree(store, ignore_errors=True)


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, username, password="Passw0rd!x"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def make_case(client, title="Test case"):
    resp = client.post("/cases/new", data={"title": title, "description": "d"})
    assert resp.status_code == 302
    return Case.query.order_by(Case.id.desc()).first()


def upload(client, case, content=b"hello evidence", name="file.txt"):
    return client.post(f"/evidence/upload/{case.id}",
                       data={"file": (io.BytesIO(content), name), "description": "test"},
                       content_type="multipart/form-data")


def user(username):
    return User.query.filter_by(username=username).first()
