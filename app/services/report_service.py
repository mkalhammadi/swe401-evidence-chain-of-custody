"""ReportService - PDF chain-of-custody report for one evidence item."""
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ..models import CustodyEvent, utcnow
from .audit import verify_chain


def build_custody_report(item, requested_by):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm,
                            title=f"Chain of Custody Report {item.evidence_code}")
    styles = getSampleStyleSheet()
    small = styles["BodyText"].clone("small", fontSize=8, leading=10)
    story = [
        Paragraph("Chain-of-Custody Report", styles["Title"]),
        Paragraph(f"Generated {utcnow():%Y-%m-%d %H:%M} UTC by {requested_by.full_name} ({requested_by.role})",
                  styles["Normal"]),
        Spacer(1, 6 * mm),
    ]

    chain_ok, checked, broken_at = verify_chain()
    meta = [
        ["Evidence ID", item.evidence_code, "Case", f"{item.case.case_number} - {item.case.title}"],
        ["File name", item.original_filename, "Size (bytes)", f"{item.size_bytes:,}"],
        ["Uploaded by", item.uploaded_by.full_name, "Uploaded at (UTC)", f"{item.created_at:%Y-%m-%d %H:%M:%S}"],
        ["Current custodian", item.custodian.full_name, "Integrity status", item.integrity_status],
        ["Original SHA-256", Paragraph(item.sha256, small), "Audit chain",
         "Intact" if chain_ok else f"BROKEN at entry #{broken_at}"],
    ]
    t = Table(meta, colWidths=[35 * mm, 95 * mm, 35 * mm, 100 * mm])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e9eef5")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#e9eef5")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story += [t, Spacer(1, 6 * mm), Paragraph("Custody history", styles["Heading2"])]

    rows = [["#", "Date/time (UTC)", "Action", "User", "Details", "Entry hash (first 16)"]]
    events = CustodyEvent.query.filter_by(evidence_id=item.id).order_by(CustodyEvent.id).all()
    for i, ev in enumerate(events, 1):
        rows.append([str(i), f"{ev.timestamp:%Y-%m-%d %H:%M:%S}", ev.action,
                     ev.user.full_name if ev.user else "System",
                     Paragraph(ev.details[:300], small), ev.entry_hash[:16]])
    h = Table(rows, colWidths=[10 * mm, 35 * mm, 40 * mm, 40 * mm, 110 * mm, 32 * mm], repeatRows=1)
    h.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3b5c")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
    ]))
    story += [h, Spacer(1, 6 * mm), Paragraph(
        "This report lists every recorded action on the item. Each log entry is linked to the previous "
        "one by a SHA-256 hash, so any later edit to the history can be detected. This report does not by "
        "itself establish legal admissibility.", small)]
    doc.build(story)
    return buf.getvalue()
