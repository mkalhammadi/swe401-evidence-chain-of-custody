"""EvidenceService - storing evidence files and access rules."""
import os
import uuid

from flask import current_app
from werkzeug.utils import secure_filename

from .. import db
from ..models import Case, Evidence, Role
from .audit import Action, log_event
from .hashing import sha256_stream


class EvidenceError(Exception):
    pass


def next_evidence_code(case):
    n = case.evidence_items.count() + 1
    return f"{case.case_number}-E{n:03d}"


def store_evidence(case, file_storage, description, user):
    """Save an uploaded file, hash it in one pass and record the upload."""
    if case.status != "Open":
        raise EvidenceError("Evidence can only be added to an open case.")
    original = secure_filename(file_storage.filename or "")
    if not original:
        raise EvidenceError("Please choose a file to upload.")

    stored_name = f"{uuid.uuid4().hex}.bin"
    path = os.path.join(current_app.config["EVIDENCE_STORE"], stored_name)
    with open(path, "wb") as out:
        digest, size = sha256_stream(file_storage.stream, current_app.config["HASH_CHUNK_SIZE"], sink=out)
    if size == 0:
        os.remove(path)
        raise EvidenceError("The uploaded file is empty.")
    os.chmod(path, 0o440)  # read-only on disk

    item = Evidence(
        evidence_code=next_evidence_code(case),
        case_id=case.id,
        original_filename=original,
        stored_filename=stored_name,
        mime_type=file_storage.mimetype or "application/octet-stream",
        size_bytes=size,
        sha256=digest,
        description=description,
        uploaded_by_id=user.id,
        custodian_id=user.id,
    )
    db.session.add(item)
    db.session.flush()
    log_event(Action.UPLOAD, user=user, evidence=item,
              details=f"file={original}; size={size}; sha256={digest}")
    return item


def evidence_path(item):
    return os.path.join(current_app.config["EVIDENCE_STORE"], item.stored_filename)


# ---------- access rules (role-based) ----------

def can_view_case(user, case):
    if user.has_role(Role.ADMIN, Role.SUPERVISOR, Role.AUDITOR):
        return True
    if case.lead_investigator_id == user.id or case.created_by_id == user.id:
        return True
    return case.evidence_items.filter(Evidence.custodian_id == user.id).count() > 0


def can_view_evidence(user, item):
    if user.has_role(Role.ADMIN, Role.SUPERVISOR, Role.AUDITOR):
        return True
    return item.custodian_id == user.id or item.case.lead_investigator_id == user.id


def can_upload(user, case):
    if user.has_role(Role.ADMIN, Role.SUPERVISOR):
        return True
    return user.has_role(Role.INVESTIGATOR) and case.lead_investigator_id == user.id


def can_transfer(user, item):
    return item.custodian_id == user.id and item.pending_transfer is None and item.case.status == "Open"


def visible_cases_query(user):
    q = Case.query
    if user.has_role(Role.INVESTIGATOR):
        q = q.filter(
            (Case.lead_investigator_id == user.id)
            | (Case.created_by_id == user.id)
            | Case.id.in_(db.session.query(Evidence.case_id).filter(Evidence.custodian_id == user.id))
        )
    return q
