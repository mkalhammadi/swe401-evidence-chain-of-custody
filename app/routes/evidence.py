from flask import (Blueprint, Response, abort, flash, redirect, render_template, request,
                   send_file, url_for)
from flask_login import current_user, login_required

from .. import db
from ..models import Case, CustodyEvent, Role, User
from ..services.audit import Action, log_event
from ..services.evidence_service import (EvidenceError, can_transfer, can_upload, can_view_evidence,
                                         evidence_path, store_evidence)
from ..services.integrity import verify_evidence
from ..services.report_service import build_custody_report
from ..models import Evidence

bp = Blueprint("evidence", __name__, url_prefix="/evidence")


def _get_visible(evidence_id):
    item = db.get_or_404(Evidence, evidence_id)
    if not can_view_evidence(current_user, item):
        abort(403)
    return item


@bp.route("/upload/<int:case_id>", methods=["POST"])
@login_required
def upload(case_id):
    case = db.get_or_404(Case, case_id)
    if not can_upload(current_user, case):
        abort(403)
    try:
        item = store_evidence(case, request.files.get("file"), request.form.get("description", "").strip(), current_user)
    except EvidenceError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    flash(f"Uploaded {item.evidence_code}. SHA-256: {item.sha256}", "success")
    return redirect(url_for("evidence.detail", evidence_id=item.id))


@bp.route("/<int:evidence_id>")
@login_required
def detail(evidence_id):
    item = _get_visible(evidence_id)
    log_event(Action.VIEW, user=current_user, evidence=item)
    history = CustodyEvent.query.filter_by(evidence_id=item.id).order_by(CustodyEvent.id.desc()).all()
    receivers = User.query.filter(User.id != current_user.id, User.active.is_(True),
                                  User.role.in_([Role.INVESTIGATOR, Role.SUPERVISOR])).order_by(User.full_name).all()
    return render_template("evidence/detail.html", item=item, history=history, receivers=receivers,
                           can_transfer=can_transfer(current_user, item))


@bp.route("/<int:evidence_id>/download")
@login_required
def download(evidence_id):
    item = _get_visible(evidence_id)
    if current_user.has_role(Role.AUDITOR):
        abort(403)  # auditors review history and reports, not the evidence content
    log_event(Action.DOWNLOAD, user=current_user, evidence=item)
    return send_file(evidence_path(item), as_attachment=True, download_name=item.original_filename,
                     mimetype=item.mime_type)


@bp.route("/<int:evidence_id>/verify", methods=["POST"])
@login_required
def verify(evidence_id):
    item = _get_visible(evidence_id)
    ok, current = verify_evidence(item, current_user)
    if ok:
        flash("Integrity verified: the current SHA-256 matches the original hash.", "success")
    else:
        flash("INTEGRITY FAILURE: the file does not match its original hash. An alert has been raised.", "danger")
    return redirect(url_for("evidence.detail", evidence_id=item.id))


@bp.route("/<int:evidence_id>/report.pdf")
@login_required
def report(evidence_id):
    item = _get_visible(evidence_id)
    pdf = build_custody_report(item, current_user)
    log_event(Action.REPORT_EXPORTED, user=current_user, evidence=item)
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="custody-report-{item.evidence_code}.pdf"'})
