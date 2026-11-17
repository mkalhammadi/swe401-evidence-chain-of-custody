"""Demo data for the live presentation."""
import io

from werkzeug.datastructures import FileStorage

from . import db
from .models import Case, Role, User
from .services.audit import Action, log_event
from .services.evidence_service import store_evidence
from .services.transfer_service import request_transfer

DEMO_PASSWORD = "Demo@12345"

USERS = [
    ("admin", "Aisha Admin", "admin@coc.local", Role.ADMIN),
    ("supervisor", "Sara Supervisor", "supervisor@coc.local", Role.SUPERVISOR),
    ("investigator", "Omar Investigator", "investigator@coc.local", Role.INVESTIGATOR),
    ("investigator2", "Layla Investigator", "investigator2@coc.local", Role.INVESTIGATOR),
    ("auditor", "Khalid Auditor", "auditor@coc.local", Role.AUDITOR),
]


def seed():
    if User.query.first():
        return
    users = {}
    for username, name, email, role in USERS:
        u = User(username=username, full_name=name, email=email, role=role)
        u.set_password(DEMO_PASSWORD)
        db.session.add(u)
        users[username] = u
    db.session.commit()

    inv, inv2 = users["investigator"], users["investigator2"]
    c1 = Case(case_number="CASE-2026-0001", title="Finance department data leak",
              description="Possible leak of payroll spreadsheets by email.", lead_investigator_id=inv.id,
              created_by_id=users["supervisor"].id)
    c2 = Case(case_number="CASE-2026-0002", title="Phishing email investigation",
              description="Staff received a fake password-reset email.", lead_investigator_id=inv2.id,
              created_by_id=users["supervisor"].id)
    db.session.add_all([c1, c2])
    db.session.flush()
    log_event(Action.CASE_CREATED, user=users["supervisor"], case=c1, details=f"title={c1.title}")
    log_event(Action.CASE_CREATED, user=users["supervisor"], case=c2, details=f"title={c2.title}")

    files = [
        (c1, inv, "payroll_export_march.csv", b"employee_id,name,salary\n1001,A. Khan,15000\n" * 200, "Export found on shared drive"),
        (c1, inv, "email_headers.txt", b"Received: from mail.example.com\nFrom: hr@example.com\n" * 50, "Headers of the suspicious email"),
        (c1, inv, "usb_image_notes.txt", b"USB serial 4C530001; imaged with dd; 16GB\n" * 20, "Imaging notes"),
        (c2, inv2, "phishing_sample.eml", b"Subject: Reset your password now\nFrom: it-support@examp1e.com\n" * 40, "Original phishing email"),
        (c2, inv2, "proxy_log_extract.log", b"2026-11-02 09:14:22 GET http://examp1e.com/login 200\n" * 120, "Proxy log extract"),
    ]
    items = []
    for case, owner, name, data, desc in files:
        fs = FileStorage(stream=io.BytesIO(data), filename=name, content_type="text/plain")
        items.append(store_evidence(case, fs, desc, owner))
    request_transfer(items[1], inv, inv2.id, "Second opinion on email headers")
    db.session.commit()
