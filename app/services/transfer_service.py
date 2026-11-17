"""TransferService - two-step custody transfer (request, then receiver accepts)."""
from .. import db
from ..models import Transfer, User, utcnow
from .audit import Action, log_event


class TransferError(Exception):
    pass


def request_transfer(item, from_user, to_user_id, reason):
    if item.custodian_id != from_user.id:
        raise TransferError("Only the current custodian can transfer this evidence.")
    if item.pending_transfer is not None:
        raise TransferError("This evidence already has a pending transfer.")
    if item.case.status != "Open":
        raise TransferError("Evidence in a closed case cannot be transferred.")
    to_user = db.session.get(User, int(to_user_id)) if to_user_id else None
    if to_user is None or not to_user.active:
        raise TransferError("Please choose an active receiving user.")
    if to_user.id == from_user.id:
        raise TransferError("You cannot transfer evidence to yourself.")
    if not (reason or "").strip():
        raise TransferError("A reason for the transfer is required.")

    t = Transfer(evidence_id=item.id, from_user_id=from_user.id, to_user_id=to_user.id, reason=reason.strip())
    db.session.add(t)
    db.session.flush()
    log_event(Action.TRANSFER_REQUESTED, user=from_user, evidence=item,
              details=f"transfer={t.id}; to={to_user.username}; reason={t.reason}")
    return t


def respond_transfer(transfer, user, accept, note=""):
    if transfer.status != "Pending":
        raise TransferError("This transfer has already been handled.")
    if transfer.to_user_id != user.id:
        raise TransferError("Only the receiving user can accept or reject this transfer.")
    transfer.responded_at = utcnow()
    transfer.response_note = note
    item = transfer.evidence
    if accept:
        transfer.status = "Accepted"
        item.custodian_id = user.id  # custody changes only now
        action = Action.TRANSFER_ACCEPTED
    else:
        transfer.status = "Rejected"
        action = Action.TRANSFER_REJECTED
    db.session.flush()
    log_event(action, user=user, evidence=item,
              details=f"transfer={transfer.id}; from={transfer.from_user.username}; note={note}")
    return transfer


def cancel_transfer(transfer, user):
    if transfer.status != "Pending":
        raise TransferError("Only pending transfers can be cancelled.")
    if user.id != transfer.from_user_id and not user.has_role("Supervisor", "Admin"):
        raise TransferError("You are not allowed to cancel this transfer.")
    transfer.status = "Cancelled"
    transfer.responded_at = utcnow()
    db.session.flush()
    log_event(Action.TRANSFER_CANCELLED, user=user, evidence=transfer.evidence,
              details=f"transfer={transfer.id}")
    return transfer
