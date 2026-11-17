"""Entity classes (database tables)."""
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from . import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Role:
    ADMIN = "Admin"
    SUPERVISOR = "Supervisor"
    INVESTIGATOR = "Investigator"
    AUDITOR = "Auditor"
    ALL = [ADMIN, SUPERVISOR, INVESTIGATOR, AUDITOR]


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=Role.INVESTIGATOR)
    active = db.Column(db.Boolean, nullable=False, default=True)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    @property
    def is_active(self):
        return self.active

    def has_role(self, *roles):
        return self.role in roles

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Case(db.Model):
    __tablename__ = "cases"
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(30), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False, default="Open")  # Open / Closed
    lead_investigator_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    closed_at = db.Column(db.DateTime)

    lead_investigator = db.relationship("User", foreign_keys=[lead_investigator_id])
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    evidence_items = db.relationship("Evidence", back_populates="case", lazy="dynamic")


class Evidence(db.Model):
    __tablename__ = "evidence"
    id = db.Column(db.Integer, primary_key=True)
    evidence_code = db.Column(db.String(40), unique=True, nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    mime_type = db.Column(db.String(120))
    size_bytes = db.Column(db.BigInteger, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)  # hash computed at upload, never changed
    description = db.Column(db.Text)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    custodian_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    integrity_status = db.Column(db.String(20), nullable=False, default="Verified")  # Verified / Mismatch / Missing
    last_verified_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    case = db.relationship("Case", back_populates="evidence_items")
    uploaded_by = db.relationship("User", foreign_keys=[uploaded_by_id])
    custodian = db.relationship("User", foreign_keys=[custodian_id])
    transfers = db.relationship("Transfer", back_populates="evidence", lazy="dynamic")

    @property
    def pending_transfer(self):
        return self.transfers.filter_by(status="Pending").first()


class CustodyEvent(db.Model):
    """One row in the tamper-evident audit log.

    entry_hash = SHA-256(prev_hash | timestamp | user | action | evidence | case | details)
    so editing or deleting any row breaks every hash after it.
    """
    __tablename__ = "custody_events"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(30), nullable=False)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"))
    details = db.Column(db.Text, nullable=False, default="")
    ip_address = db.Column(db.String(45))
    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), unique=True, nullable=False)

    user = db.relationship("User")
    evidence = db.relationship("Evidence")
    case = db.relationship("Case")


class Transfer(db.Model):
    __tablename__ = "transfers"
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"), nullable=False)
    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="Pending")  # Pending/Accepted/Rejected/Cancelled
    requested_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    responded_at = db.Column(db.DateTime)
    response_note = db.Column(db.Text)

    evidence = db.relationship("Evidence", back_populates="transfers")
    from_user = db.relationship("User", foreign_keys=[from_user_id])
    to_user = db.relationship("User", foreign_keys=[to_user_id])


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    rule = db.Column(db.String(40), nullable=False)
    severity = db.Column(db.String(10), nullable=False, default="Medium")  # Low/Medium/High
    message = db.Column(db.Text, nullable=False)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    acknowledged_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    acknowledged_at = db.Column(db.DateTime)

    evidence = db.relationship("Evidence")
    user = db.relationship("User", foreign_keys=[user_id])
    acknowledged_by = db.relationship("User", foreign_keys=[acknowledged_by_id])
