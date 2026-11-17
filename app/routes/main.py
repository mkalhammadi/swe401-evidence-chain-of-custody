from datetime import timedelta

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from .. import db
from ..models import Alert, Case, CustodyEvent, Evidence, Role, Transfer, utcnow
from ..services.audit import verify_chain
from ..services.evidence_service import visible_cases_query
from . import roles_required

bp = Blueprint("main", __name__)


@bp.route("/")
@login_required
def dashboard():
    cases_q = visible_cases_query(current_user)
    case_ids = [c.id for c in cases_q.all()]
    evidence_q = Evidence.query.filter(Evidence.case_id.in_(case_ids)) if case_ids else Evidence.query.filter(False)
    stats = {
        "open_cases": cases_q.filter(Case.status == "Open").count(),
        "evidence": evidence_q.count(),
        "my_custody": Evidence.query.filter_by(custodian_id=current_user.id).count(),
        "pending_in": Transfer.query.filter_by(to_user_id=current_user.id, status="Pending").count(),
        "open_alerts": Alert.query.filter_by(acknowledged_at=None).count(),
        "mismatch": evidence_q.filter(Evidence.integrity_status != "Verified").count(),
    }
    # activity per day for the last 7 days (simple bar chart)
    today = utcnow().date()
    chart = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        n = CustodyEvent.query.filter(db.func.date(CustodyEvent.timestamp) == day.isoformat()).count()
        chart.append({"label": day.strftime("%a %d"), "count": n})
    peak = max([c["count"] for c in chart] + [1])
    recent_q = CustodyEvent.query.order_by(CustodyEvent.id.desc())
    if current_user.has_role(Role.INVESTIGATOR):
        recent_q = recent_q.filter(CustodyEvent.user_id == current_user.id)
    return render_template("dashboard.html", stats=stats, chart=chart, peak=peak,
                           recent=recent_q.limit(8).all())


@bp.route("/alerts")
@login_required
@roles_required(Role.ADMIN, Role.SUPERVISOR, Role.AUDITOR)
def alerts():
    show = request.args.get("show", "open")
    q = Alert.query.order_by(Alert.id.desc())
    if show == "open":
        q = q.filter_by(acknowledged_at=None)
    return render_template("alerts.html", alerts=q.all(), show=show)


@bp.route("/alerts/<int:alert_id>/ack", methods=["POST"])
@login_required
@roles_required(Role.ADMIN, Role.SUPERVISOR)
def ack_alert(alert_id):
    alert = db.get_or_404(Alert, alert_id)
    alert.acknowledged_by_id = current_user.id
    alert.acknowledged_at = utcnow()
    db.session.commit()
    flash("Alert acknowledged.", "success")
    return redirect(url_for("main.alerts"))


@bp.route("/audit")
@login_required
@roles_required(Role.ADMIN, Role.AUDITOR, Role.SUPERVISOR)
def audit_log():
    action = request.args.get("action", "")
    q = CustodyEvent.query.order_by(CustodyEvent.id.desc())
    if action:
        q = q.filter_by(action=action)
    page = q.paginate(page=request.args.get("page", 1, type=int), per_page=25, error_out=False)
    actions = [a[0] for a in db.session.query(CustodyEvent.action).distinct().order_by(CustodyEvent.action)]
    return render_template("audit/log.html", page=page, actions=actions, action=action, chain=None)


@bp.route("/audit/verify", methods=["POST"])
@login_required
@roles_required(Role.ADMIN, Role.AUDITOR, Role.SUPERVISOR)
def audit_verify():
    ok, checked, broken_at = verify_chain()
    if ok:
        flash(f"Audit chain intact: {checked} entries verified.", "success")
    else:
        flash(f"Audit chain BROKEN at entry #{broken_at} (after {checked} valid entries).", "danger")
    return redirect(url_for("main.audit_log"))
