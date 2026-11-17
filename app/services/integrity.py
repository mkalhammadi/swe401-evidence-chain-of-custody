"""IntegrityService - compares the current file hash with the hash stored at upload."""
import os
import threading

from .. import db
from ..models import Evidence, utcnow
from .audit import Action, log_event
from .hashing import sha256_file


def verify_evidence(item, user=None):
    """Re-hash one item. Returns (ok, current_hash_or_None)."""
    from .evidence_service import evidence_path
    path = evidence_path(item)
    who = user.username if user is not None else "scheduler"
    if not os.path.exists(path):
        item.integrity_status = "Missing"
        item.last_verified_at = utcnow()
        db.session.commit()
        log_event(Action.VERIFY_FAILED, user=user, evidence=item,
                  details=f"by={who}; stored file is missing")
        return False, None

    current = sha256_file(path)
    item.last_verified_at = utcnow()
    if current == item.sha256:
        item.integrity_status = "Verified"
        db.session.commit()
        log_event(Action.VERIFY_PASSED, user=user, evidence=item, details=f"by={who}; sha256={current}")
        return True, current

    item.integrity_status = "Mismatch"
    db.session.commit()
    log_event(Action.VERIFY_FAILED, user=user, evidence=item,
              details=f"by={who}; expected={item.sha256}; found={current}")
    return False, current


def verify_all():
    """Check every evidence item (used by the scheduler and `flask verify-all`)."""
    results = {"checked": 0, "passed": 0, "failed": 0}
    for item in Evidence.query.order_by(Evidence.id).all():
        ok, _ = verify_evidence(item)
        results["checked"] += 1
        results["passed" if ok else "failed"] += 1
    return results


def start_scheduler(app):
    """Run verify_all() every INTEGRITY_CHECK_INTERVAL_MIN minutes in a daemon thread."""
    interval = app.config["INTEGRITY_CHECK_INTERVAL_MIN"] * 60
    stop = threading.Event()

    def loop():
        while not stop.wait(interval):
            with app.app_context():
                try:
                    verify_all()
                except Exception as exc:  # keep the scheduler alive
                    app.logger.exception("Scheduled integrity check failed: %s", exc)

    t = threading.Thread(target=loop, name="integrity-scheduler", daemon=True)
    t.start()
    app.extensions["integrity_scheduler_stop"] = stop
    return t
