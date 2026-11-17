"""System tests. Each test name starts with the test-case ID used in the project report."""
import hashlib
import io
import os
import time
from datetime import timedelta

from app import db
from app.models import Alert, CustodyEvent, Evidence, Transfer, utcnow
from app.services.audit import log_event, verify_chain
from app.services.evidence_service import evidence_path
from app.services.hashing import sha256_stream
from app.services.integrity import verify_all

from conftest import login, make_case, upload, user


# ---------- Authentication and roles (FR-01, FR-02, FR-03) ----------

def test_tc01_valid_login_redirects_to_dashboard(client):
    resp = login(client, "inv")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/")
    assert CustodyEvent.query.filter_by(action="LOGIN").count() == 1


def test_tc02_invalid_login_rejected_and_logged(client):
    resp = login(client, "inv", "wrong-password")
    assert resp.status_code == 401
    assert CustodyEvent.query.filter_by(action="LOGIN_FAILED").count() == 1


def test_tc03_account_locks_after_five_failures(client, app):
    for _ in range(5):
        login(client, "inv", "bad")
    assert login(client, "inv").status_code == 423  # locked even with correct password
    assert Alert.query.filter_by(rule="REPEATED_LOGIN_FAILURE").count() == 1


def test_tc04_role_access_control(client):
    login(client, "inv")
    assert client.get("/admin/users").status_code == 403
    assert client.get("/audit").status_code == 403
    client.post("/logout")
    login(client, "aud")
    assert client.get("/audit").status_code == 200


# ---------- Case management (FR-04, FR-05) ----------

def test_tc05_create_case_assigns_number(client):
    login(client, "inv")
    case = make_case(client, "Laptop seizure")
    assert case.case_number.startswith("CASE-") and case.status == "Open"
    assert case.lead_investigator_id == user("inv").id


def test_tc06_close_case_blocks_new_uploads(client):
    login(client, "sup")
    case = make_case(client)
    assert client.post(f"/cases/{case.id}/close").status_code == 302
    upload(client, case)
    assert Evidence.query.count() == 0


# ---------- Upload and hashing (FR-06, FR-07) ----------

def test_tc07_upload_stores_correct_sha256(client):
    login(client, "inv")
    case = make_case(client)
    data = os.urandom(300_000)
    upload(client, case, data, "disk.img")
    item = Evidence.query.one()
    assert item.sha256 == hashlib.sha256(data).hexdigest()
    assert item.size_bytes == len(data)
    assert CustodyEvent.query.filter_by(action="UPLOAD", evidence_id=item.id).count() == 1


def test_tc08_empty_file_rejected(client):
    login(client, "inv")
    case = make_case(client)
    upload(client, case, b"", "empty.txt")
    assert Evidence.query.count() == 0


def test_tc09_streaming_hash_matches_hashlib_for_large_input():
    data = os.urandom(5 * 1024 * 1024 + 123)
    digest, size = sha256_stream(io.BytesIO(data), 64 * 1024)
    assert digest == hashlib.sha256(data).hexdigest() and size == len(data)


# ---------- Activity tracking (FR-08) ----------

def test_tc10_view_and_download_are_logged(client):
    login(client, "inv")
    case = make_case(client)
    upload(client, case, b"abc")
    item = Evidence.query.one()
    client.get(f"/evidence/{item.id}")
    r = client.get(f"/evidence/{item.id}/download")
    assert r.status_code == 200 and r.data == b"abc"
    actions = [e.action for e in CustodyEvent.query.filter_by(evidence_id=item.id)]
    assert "VIEW" in actions and "DOWNLOAD" in actions


# ---------- Integrity verification (FR-11, FR-12) ----------

def test_tc11_verify_passes_for_unchanged_file(client):
    login(client, "inv")
    case = make_case(client)
    upload(client, case, b"original")
    item = Evidence.query.one()
    client.post(f"/evidence/{item.id}/verify")
    db.session.refresh(item)
    assert item.integrity_status == "Verified"


def test_tc12_verify_detects_tampering_and_alerts(client):
    login(client, "inv")
    case = make_case(client)
    upload(client, case, b"original")
    item = Evidence.query.one()
    path = evidence_path(item)
    os.chmod(path, 0o640)
    with open(path, "ab") as fh:
        fh.write(b"tampered")
    client.post(f"/evidence/{item.id}/verify")
    db.session.refresh(item)
    assert item.integrity_status == "Mismatch"
    assert Alert.query.filter_by(rule="INTEGRITY_FAILURE", severity="High").count() == 1


def test_tc13_scheduled_check_covers_all_items(client):
    login(client, "inv")
    case = make_case(client)
    for i in range(3):
        upload(client, case, f"item {i}".encode(), f"f{i}.txt")
    os.remove(evidence_path(Evidence.query.first()))
    result = verify_all()
    assert result == {"checked": 3, "passed": 2, "failed": 1}


# ---------- Transfers (FR-09) ----------

def _setup_item(client):
    login(client, "inv")
    case = make_case(client)
    upload(client, case, b"evidence")
    return Evidence.query.one()


def test_tc14_custody_changes_only_after_acceptance(client):
    item = _setup_item(client)
    client.post(f"/transfers/request/{item.id}", data={"to_user_id": user("inv2").id, "reason": "analysis"})
    db.session.refresh(item)
    assert item.custodian_id == user("inv").id  # still the sender
    t = Transfer.query.one()
    client.post("/logout")
    login(client, "inv2")
    client.post(f"/transfers/{t.id}/respond", data={"decision": "accept"})
    db.session.refresh(item)
    assert item.custodian_id == user("inv2").id and t.status == "Accepted"


def test_tc15_rejected_transfer_keeps_custodian(client):
    item = _setup_item(client)
    client.post(f"/transfers/request/{item.id}", data={"to_user_id": user("inv2").id, "reason": "x"})
    t = Transfer.query.one()
    client.post("/logout")
    login(client, "inv2")
    client.post(f"/transfers/{t.id}/respond", data={"decision": "reject", "note": "not my case"})
    db.session.refresh(item)
    assert item.custodian_id == user("inv").id and t.status == "Rejected"


def test_tc16_only_receiver_can_accept(client):
    item = _setup_item(client)
    client.post(f"/transfers/request/{item.id}", data={"to_user_id": user("inv2").id, "reason": "x"})
    t = Transfer.query.one()
    client.post(f"/transfers/{t.id}/respond", data={"decision": "accept"})  # sender tries
    assert Transfer.query.one().status == "Pending"


# ---------- Tamper-evident audit log (FR-10) ----------

def test_tc17_audit_chain_valid_then_detects_edit(client):
    item = _setup_item(client)
    client.get(f"/evidence/{item.id}")
    ok, n, _ = verify_chain()
    assert ok and n >= 4
    ev = CustodyEvent.query.filter_by(action="UPLOAD").one()
    ev.details = "file=other.txt"  # someone edits history directly in the database
    db.session.commit()
    ok, _, broken = verify_chain()
    assert not ok and broken == ev.id


def test_tc18_audit_chain_detects_deleted_entry(client):
    item = _setup_item(client)
    client.get(f"/evidence/{item.id}")
    db.session.delete(CustodyEvent.query.filter_by(action="UPLOAD").one())
    db.session.commit()
    assert verify_chain()[0] is False


# ---------- Anomaly rules (FR-13) ----------

def test_tc19_bulk_download_raises_alert(client):
    item = _setup_item(client)
    for _ in range(6):
        client.get(f"/evidence/{item.id}/download")
    assert Alert.query.filter_by(rule="BULK_DOWNLOAD").count() == 1


def test_tc20_after_hours_access_raises_alert(client, app):
    item = _setup_item(client)
    app.config["WORK_HOURS_START"] = 25  # every hour is now "outside working hours"
    client.get(f"/evidence/{item.id}")
    assert Alert.query.filter_by(rule="AFTER_HOURS_ACCESS").count() >= 1


# ---------- PDF report (FR-14) ----------

def test_tc21_pdf_custody_report(client):
    item = _setup_item(client)
    r = client.get(f"/evidence/{item.id}/report.pdf")
    assert r.status_code == 200 and r.data[:4] == b"%PDF"
    assert CustodyEvent.query.filter_by(action="REPORT_EXPORTED").count() == 1


# ---------- Non-functional checks ----------

def test_tc22_auditor_cannot_download_content(client):
    item = _setup_item(client)
    client.post("/logout")
    login(client, "aud")
    assert client.get(f"/evidence/{item.id}/download").status_code == 403


def test_tc23_hash_throughput_50mb_under_5s():
    data = io.BytesIO(os.urandom(50 * 1024 * 1024))
    start = time.perf_counter()
    sha256_stream(data, 64 * 1024)
    assert time.perf_counter() - start < 5.0


def test_tc24_passwords_are_hashed(app):
    u = user("inv")
    assert u.password_hash != "Passw0rd!x" and u.password_hash.startswith(("scrypt:", "pbkdf2:"))
