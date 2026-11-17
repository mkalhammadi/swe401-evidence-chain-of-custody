"""AnomalyService - simple rule-based alerts for unusual activity.

Alerts are warnings only; a supervisor or auditor reviews and acknowledges them.
"""
from datetime import timedelta

from flask import current_app

from .. import db
from ..models import Alert, CustodyEvent

WATCHED_ACCESS = {"VIEW", "DOWNLOAD", "UPLOAD", "TRANSFER_REQUESTED", "TRANSFER_ACCEPTED"}


def raise_alert(rule, severity, message, evidence_id=None, user_id=None):
    alert = Alert(rule=rule, severity=severity, message=message,
                  evidence_id=evidence_id, user_id=user_id)
    db.session.add(alert)
    db.session.commit()
    return alert


def evaluate_event(ev):
    cfg = current_app.config

    # Rule 1: access to evidence outside working hours
    if ev.action in WATCHED_ACCESS and ev.user_id:
        local = ev.timestamp + timedelta(hours=cfg["LOCAL_UTC_OFFSET_HOURS"])
        if local.hour < cfg["WORK_HOURS_START"] or local.hour >= cfg["WORK_HOURS_END"]:
            raise_alert("AFTER_HOURS_ACCESS", "Medium",
                        f"{ev.action} at {local:%H:%M} local time is outside working hours "
                        f"({cfg['WORK_HOURS_START']:02d}:00-{cfg['WORK_HOURS_END']:02d}:00).",
                        evidence_id=ev.evidence_id, user_id=ev.user_id)

    # Rule 2: many downloads by one user in a short window
    if ev.action == "DOWNLOAD" and ev.user_id:
        window_start = ev.timestamp - timedelta(minutes=cfg["BULK_DOWNLOAD_WINDOW_MIN"])
        n = CustodyEvent.query.filter(CustodyEvent.user_id == ev.user_id,
                                      CustodyEvent.action == "DOWNLOAD",
                                      CustodyEvent.timestamp >= window_start).count()
        if n == cfg["BULK_DOWNLOAD_LIMIT"] + 1:  # alert once when the limit is first passed
            raise_alert("BULK_DOWNLOAD", "High",
                        f"{n} downloads within {cfg['BULK_DOWNLOAD_WINDOW_MIN']} minutes.",
                        user_id=ev.user_id)

    # Rule 3: failed integrity check (always High)
    if ev.action == "VERIFY_FAILED":
        fails = CustodyEvent.query.filter_by(evidence_id=ev.evidence_id, action="VERIFY_FAILED").count()
        raise_alert("INTEGRITY_FAILURE", "High",
                    f"Hash mismatch detected (failure #{fails} for this item). {ev.details}",
                    evidence_id=ev.evidence_id, user_id=ev.user_id)

    # Rule 4: repeated failed logins for one account
    if ev.action == "LOGIN_FAILED" and ev.user_id:
        window_start = ev.timestamp - timedelta(minutes=cfg["LOCKOUT_MINUTES"])
        n = CustodyEvent.query.filter(CustodyEvent.user_id == ev.user_id,
                                      CustodyEvent.action == "LOGIN_FAILED",
                                      CustodyEvent.timestamp >= window_start).count()
        if n == cfg["FAILED_LOGIN_LIMIT"]:
            raise_alert("REPEATED_LOGIN_FAILURE", "Medium",
                        f"{n} failed logins in {cfg['LOCKOUT_MINUTES']} minutes; account locked.",
                        user_id=ev.user_id)
