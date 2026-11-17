"""AuditService - append-only, hash-chained custody log.

Every entry stores the hash of the entry before it. Changing, inserting or
deleting a past entry makes verify_chain() fail from that point on.
"""
import threading

from flask import has_request_context, request

from .. import db
from ..models import CustodyEvent, utcnow
from .hashing import sha256_text

GENESIS_HASH = "0" * 64
_chain_lock = threading.Lock()  # stops two writers from linking to the same previous entry


class Action:
    LOGIN = "LOGIN"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    CASE_CREATED = "CASE_CREATED"
    CASE_CLOSED = "CASE_CLOSED"
    UPLOAD = "UPLOAD"
    VIEW = "VIEW"
    DOWNLOAD = "DOWNLOAD"
    TRANSFER_REQUESTED = "TRANSFER_REQUESTED"
    TRANSFER_ACCEPTED = "TRANSFER_ACCEPTED"
    TRANSFER_REJECTED = "TRANSFER_REJECTED"
    TRANSFER_CANCELLED = "TRANSFER_CANCELLED"
    VERIFY_PASSED = "VERIFY_PASSED"
    VERIFY_FAILED = "VERIFY_FAILED"
    REPORT_EXPORTED = "REPORT_EXPORTED"
    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"


def compute_entry_hash(prev_hash, timestamp, user_id, action, evidence_id, case_id, details):
    payload = "|".join([
        prev_hash,
        timestamp.isoformat(timespec="microseconds"),
        str(user_id or ""),
        action,
        str(evidence_id or ""),
        str(case_id or ""),
        details or "",
    ])
    return sha256_text(payload)


def log_event(action, user=None, evidence=None, case=None, details="", commit=True):
    """Append one event to the chain and return it."""
    with _chain_lock:
        last = CustodyEvent.query.order_by(CustodyEvent.id.desc()).with_for_update().first()
        prev_hash = last.entry_hash if last else GENESIS_HASH
        ts = utcnow()
        user_id = getattr(user, "id", user)
        evidence_id = getattr(evidence, "id", evidence)
        if case is None and evidence is not None and hasattr(evidence, "case_id"):
            case = evidence.case_id
        case_id = getattr(case, "id", case)
        entry = CustodyEvent(
            timestamp=ts,
            user_id=user_id,
            action=action,
            evidence_id=evidence_id,
            case_id=case_id,
            details=details or "",
            ip_address=request.remote_addr if has_request_context() else "system",
            prev_hash=prev_hash,
            entry_hash=compute_entry_hash(prev_hash, ts, user_id, action, evidence_id, case_id, details),
        )
        db.session.add(entry)
        if commit:
            db.session.commit()
        else:
            db.session.flush()
    # anomaly rules look at the new event (imported here to avoid a circular import)
    from .anomaly import evaluate_event
    evaluate_event(entry)
    return entry


def verify_chain():
    """Re-compute every hash. Returns (ok, checked_count, first_broken_event_id)."""
    prev = GENESIS_HASH
    count = 0
    for ev in CustodyEvent.query.order_by(CustodyEvent.id.asc()).yield_per(500):
        expected = compute_entry_hash(prev, ev.timestamp, ev.user_id, ev.action,
                                      ev.evidence_id, ev.case_id, ev.details)
        if ev.prev_hash != prev or ev.entry_hash != expected:
            return False, count, ev.id
        prev = ev.entry_hash
        count += 1
    return True, count, None
