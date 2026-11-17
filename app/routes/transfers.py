from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from .. import db
from ..models import Evidence, Transfer
from ..services.evidence_service import can_view_evidence
from ..services.transfer_service import TransferError, cancel_transfer, request_transfer, respond_transfer

bp = Blueprint("transfers", __name__, url_prefix="/transfers")


@bp.route("/")
@login_required
def inbox():
    incoming = Transfer.query.filter_by(to_user_id=current_user.id).order_by(Transfer.id.desc()).all()
    outgoing = Transfer.query.filter_by(from_user_id=current_user.id).order_by(Transfer.id.desc()).all()
    return render_template("transfers.html", incoming=incoming, outgoing=outgoing)


@bp.route("/request/<int:evidence_id>", methods=["POST"])
@login_required
def create(evidence_id):
    item = db.get_or_404(Evidence, evidence_id)
    if not can_view_evidence(current_user, item):
        abort(403)
    try:
        t = request_transfer(item, current_user, request.form.get("to_user_id"), request.form.get("reason", ""))
        flash(f"Transfer requested. Custody changes when {t.to_user.full_name} accepts.", "success")
    except TransferError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("evidence.detail", evidence_id=item.id))


@bp.route("/<int:transfer_id>/respond", methods=["POST"])
@login_required
def respond(transfer_id):
    t = db.get_or_404(Transfer, transfer_id)
    accept = request.form.get("decision") == "accept"
    try:
        respond_transfer(t, current_user, accept, request.form.get("note", "").strip())
        flash("Transfer accepted - you are now the custodian." if accept else "Transfer rejected.",
              "success" if accept else "info")
    except TransferError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("transfers.inbox"))


@bp.route("/<int:transfer_id>/cancel", methods=["POST"])
@login_required
def cancel(transfer_id):
    t = db.get_or_404(Transfer, transfer_id)
    try:
        cancel_transfer(t, current_user)
        flash("Transfer cancelled.", "info")
    except TransferError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("transfers.inbox"))
