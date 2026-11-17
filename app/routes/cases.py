from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from .. import db
from ..models import Case, Role, User, utcnow
from ..services.audit import Action, log_event
from ..services.evidence_service import can_upload, can_view_case, visible_cases_query
from . import roles_required

bp = Blueprint("cases", __name__, url_prefix="/cases")


@bp.route("/")
@login_required
def list_cases():
    status = request.args.get("status", "")
    term = request.args.get("q", "").strip()
    q = visible_cases_query(current_user)
    if status:
        q = q.filter(Case.status == status)
    if term:
        like = f"%{term}%"
        q = q.filter((Case.title.ilike(like)) | (Case.case_number.ilike(like)))
    return render_template("cases/list.html", cases=q.order_by(Case.id.desc()).all(), status=status, term=term)


@bp.route("/new", methods=["GET", "POST"])
@login_required
@roles_required(Role.ADMIN, Role.SUPERVISOR, Role.INVESTIGATOR)
def new_case():
    investigators = User.query.filter(User.role == Role.INVESTIGATOR, User.active.is_(True)).order_by(User.full_name).all()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        lead_id = request.form.get("lead_investigator_id", type=int) or current_user.id
        if current_user.has_role(Role.INVESTIGATOR):
            lead_id = current_user.id
        if not title:
            flash("Case title is required.", "danger")
            return render_template("cases/new.html", investigators=investigators), 400
        year = utcnow().year
        n = Case.query.filter(Case.case_number.like(f"CASE-{year}-%")).count() + 1
        case = Case(case_number=f"CASE-{year}-{n:04d}", title=title, description=description,
                    lead_investigator_id=lead_id, created_by_id=current_user.id)
        db.session.add(case)
        db.session.flush()
        log_event(Action.CASE_CREATED, user=current_user, case=case, details=f"title={title}")
        flash(f"Case {case.case_number} created.", "success")
        return redirect(url_for("cases.case_detail", case_id=case.id))
    return render_template("cases/new.html", investigators=investigators)


@bp.route("/<int:case_id>")
@login_required
def case_detail(case_id):
    case = db.get_or_404(Case, case_id)
    if not can_view_case(current_user, case):
        abort(403)
    items = case.evidence_items.order_by("id").all()
    return render_template("cases/detail.html", case=case, items=items,
                           can_upload=can_upload(current_user, case) and case.status == "Open")


@bp.route("/<int:case_id>/close", methods=["POST"])
@login_required
@roles_required(Role.ADMIN, Role.SUPERVISOR)
def close_case(case_id):
    case = db.get_or_404(Case, case_id)
    if case.status == "Closed":
        flash("Case is already closed.", "info")
    else:
        case.status = "Closed"
        case.closed_at = utcnow()
        db.session.flush()
        log_event(Action.CASE_CLOSED, user=current_user, case=case)
        flash(f"Case {case.case_number} closed. Its evidence is now read-only.", "success")
    return redirect(url_for("cases.case_detail", case_id=case.id))
