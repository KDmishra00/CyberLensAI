"""PDF incident report generation with ReportLab (Platypus flowables).

Mirrors the on-screen report view: header, summary paragraph, key stats,
category and severity tables, timeline chart, top detections, mitigations,
method and limitations. One accent colour, black text on white, page
numbers in the footer.
"""
from __future__ import annotations

from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, PageTemplate, Paragraph,
                                Spacer, Table, TableStyle)
from reportlab.graphics.shapes import Drawing, PolyLine, String

import config
from core.security import mitigations_for_categories

ACCENT = colors.HexColor("#1F3A5F")
MUTED = colors.HexColor("#6B6A64")
LIGHT = colors.HexColor("#E4E2DC")
SEV_COLORS = {
    "Low": colors.HexColor("#5B7F5B"),
    "Medium": colors.HexColor("#B08A2E"),
    "High": colors.HexColor("#B5602B"),
    "Critical": colors.HexColor("#A32E2E"),
}


def _styles() -> dict:
    body = ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=14,
                          textColor=colors.HexColor("#1C1C1A"))
    h1 = ParagraphStyle("h1", parent=body, fontName="Helvetica-Bold", fontSize=20,
                        leading=24, textColor=ACCENT, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=12.5,
                        leading=16, textColor=ACCENT, spaceBefore=14, spaceAfter=5)
    muted = ParagraphStyle("muted", parent=body, fontSize=8, leading=11,
                           textColor=MUTED)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=12)
    cell = ParagraphStyle("cell", parent=body, fontSize=8.5, leading=11)
    return {"h1": h1, "h2": h2, "body": body, "muted": muted, "small": small, "cell": cell}


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 12 * mm,
                      "CyberLens AI - generated locally, offline. Data read as data, never executed.")
    canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _timeline_drawing(points: list[dict]) -> Drawing | None:
    """A simple ReportLab line chart; hand-drawn axes keep it dependency-free."""
    if len(points) < 2:
        return None
    w, h = 160 * mm, 45 * mm
    d = Drawing(w, h)
    pad_l, pad_r, pad_t, pad_b = 30, 10, 12, 24
    counts = [p["count"] for p in points]
    max_c = max(counts)
    n = len(points)
    xs = [pad_l + i * (w - pad_l - pad_r) / (n - 1) for i in range(n)]
    ys = [pad_t + (h - pad_t - pad_b) * (c / max_c) for c in counts]
    d.add(PolyLine(list(zip(xs, ys)), strokeColor=ACCENT, strokeWidth=1.2))
    d.add(String(pad_l - 4, h - pad_t - 2, str(max_c), fontName="Helvetica",
                 fontSize=6.5, fillColor=MUTED, textAnchor="end"))
    d.add(String(pad_l - 4, pad_b, "0", fontName="Helvetica", fontSize=6.5,
                 fillColor=MUTED, textAnchor="end"))
    d.add(String(pad_l, 6, points[0]["time"], fontName="Helvetica", fontSize=6.5,
                 fillColor=MUTED))
    last = points[-1]["time"]
    d.add(String(w - pad_r, 6, last, fontName="Helvetica", fontSize=6.5,
                 fillColor=MUTED, textAnchor="end"))
    return d


def _styled_table(data: list, widths: list, align_left_cols=(0,)) -> Table:
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F0EEE9")),
        ("LINEBELOW", (0, 0), (-1, 0), 0.75, ACCENT),
        ("GRID", (0, 1), (-1, -1), 0.4, LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5),
        ("FONT", (0, 1), (-1, -1), "Helvetica", 8.5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for col in align_left_cols:
        style.append(("ALIGN", (col, 1), (col, -1), "LEFT"))
    t.setStyle(TableStyle(style))
    return t


def _esc(text) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cell(text) -> str:
    """Escape a table cell and neutralise formula injection.

    A cell that starts with =, +, - or @ could be read as a formula if the
    text is later pasted into a spreadsheet, so it gets a leading quote.
    """
    raw = str(text)
    if raw.startswith(("=", "+", "-", "@")):
        raw = "'" + raw
    return _esc(raw)


def build_summary_paragraphs(results: dict, filename: str) -> list[str]:
    """Plain-language summary text, shared by the report page and the PDF."""
    total = results["total_records"]
    attacks = results["total_attacks"]
    if attacks == 0:
        return [
            f"We analysed {total:,} records from {filename} and found none that look like "
            "the six attack types CyberLens knows.",
            "That is not proof the file is clean. The model only knows six attack "
            "categories plus normal traffic, and it was trained on synthetic data. "
            "Treat this as one automated opinion, not a security sign-off.",
        ]
    worst = results["detections"][0] if results["detections"] else None
    top_category = max(results["category_counts"], key=results["category_counts"].get)
    paragraphs = [
        f"We analysed {total:,} records from {filename}. {attacks:,} of them "
        f"({results['attack_pct']:.1f}%) look like attacks, most often {top_category} "
        f"({results['category_counts'][top_category]} events).",
    ]
    if worst:
        when = f" at {worst['timestamp']}" if worst.get("timestamp") else ""
        paragraphs.append(
            f"The most severe finding is a {worst['severity']} {worst['predicted_category']} "
            f"from {worst['src_ip']}{when}. The table below lists the strongest detections, "
            "and the mitigation section suggests concrete next steps per category.")
    if results["low_confidence_count"]:
        paragraphs.append(
            f"{results['low_confidence_count']} additional events were called attacks with "
            "low confidence; they are counted as normal here but listed as a caveat on the "
            "dashboard.")
    return paragraphs


def severity_rule_text() -> str:
    """The documented severity rule, shown on the report page and in the PDF."""
    return ("Base severity per category (Malware Activity = Critical; SQL Injection, "
            "Privilege Escalation and DoS Indicators = High; Brute Force = Medium; "
            "Port Scan = Low), then one level up if confidence is at least 0.90 or the "
            "same source IP produced at least 20 attack events, one level down if "
            "confidence is below 0.65.")


def generate_report_pdf(summary: dict, meta: dict, save_path: str) -> str:
    """Build the PDF at save_path and return the path."""
    S = _styles()
    doc = BaseDocTemplate(save_path, pagesize=A4,
                          leftMargin=18 * mm, rightMargin=18 * mm,
                          topMargin=16 * mm, bottomMargin=18 * mm,
                          title="CyberLens AI - Incident Report",
                          author="CyberLens AI")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="page", frames=[frame], onPage=_footer)])

    story = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph("CyberLens AI", S["h1"]))
    story.append(Paragraph(f"Incident report - {meta.get('filename', 'upload')} - generated {now}",
                           S["muted"]))
    story.append(Spacer(1, 8))

    # Summary paragraph (same templated text as the on-screen report view).
    for para in meta.get("summary_paragraphs", []):
        story.append(Paragraph(_esc(para), S["body"]))
        story.append(Spacer(1, 4))

    story.append(Paragraph("Key figures", S["h2"]))
    stats_rows = [
        ["Total records analysed", f"{summary['total_records']:,}"],
        ["Attacks found", f"{summary['total_attacks']:,}"],
        ["Normal records", f"{summary['total_normal']:,}"],
        ["Attack rate", f"{summary['attack_pct']:.1f}%"],
        ["Low-confidence attack calls kept as Normal", f"{summary['low_confidence_count']:,}"],
    ]
    story.append(_styled_table(stats_rows, [90 * mm, 60 * mm]))

    if summary["category_counts"]:
        story.append(Paragraph("Attack categories", S["h2"]))
        cat_rows = [["Category", "Count", "Share"]]
        for cat, count in sorted(summary["category_counts"].items(),
                                 key=lambda kv: -kv[1]):
            cat_rows.append([_esc(cat), str(count), f"{summary['category_pct'][cat]:.1f}%"])
        story.append(_styled_table(cat_rows, [70 * mm, 30 * mm, 30 * mm]))

        story.append(Paragraph("Severity breakdown", S["h2"]))
        sev_rows = [["Severity", "Count"]] + [
            [sev, str(summary["severity_counts"].get(sev, 0))]
            for sev in config.SEVERITY_LEVELS
        ]
        story.append(_styled_table(sev_rows, [50 * mm, 30 * mm]))

        timeline_drawing = _timeline_drawing(summary.get("timeline", []))
        if timeline_drawing is not None:
            story.append(Paragraph(f"Attack timeline ({summary.get('timeline_note') or 'over the observed period'})", S["h2"]))
            story.append(timeline_drawing)
        elif summary.get("timeline_note"):
            story.append(Paragraph(f"Timeline: {_esc(summary['timeline_note'])}", S["small"]))

        story.append(Paragraph("Top detections", S["h2"]))
        det_rows = [["Time", "Source IP", "Category", "Sev.", "Conf.", "Event"]]
        for det in summary["detections"][:10]:
            sev_color = SEV_COLORS.get(det["severity"])
            sev_hex = f"#{sev_color.hexval()[2:]}" if sev_color else "#1C1C1A"
            det_rows.append([
                Paragraph(_cell(det.get("timestamp") or "-"), S["cell"]),
                Paragraph(_cell(det.get("src_ip") or "-"), S["cell"]),
                Paragraph(_cell(det["predicted_category"]), S["cell"]),
                Paragraph(f'<font color="{sev_hex}">{_cell(det["severity"])}</font>', S["cell"]),
                Paragraph(f"{det['confidence']:.2f}", S["cell"]),
                Paragraph(_cell(det["event"][:120]), S["cell"]),
            ])
        story.append(_styled_table(det_rows, [26 * mm, 24 * mm, 26 * mm, 14 * mm, 12 * mm, 66 * mm]))

        story.append(Paragraph("Recommended mitigations", S["h2"]))
        for m in mitigations_for_categories(list(summary["category_counts"].keys())):
            mitre = f" (MITRE ATT&CK: {', '.join(m['mitre'])})" if m["mitre"] else ""
            story.append(Paragraph(f"<b>{_esc(m['category'])}</b>{_esc(mitre)} - {_esc(m['summary'])}",
                                   S["body"]))
            story.append(Spacer(1, 2))
            for i, step in enumerate(m["steps"], 1):
                story.append(Paragraph(f"{i}. {_esc(step)}", S["small"]))
            story.append(Spacer(1, 6))

        story.append(Paragraph("How severity is decided", S["h2"]))
        story.append(Paragraph(
            "Each detection starts from a base severity per category (SQL Injection, "
            "Privilege Escalation and DoS Indicators = High; Malware Activity = Critical; "
            "Brute Force = Medium; Port Scan = Low), then moves up one level if the model's "
            "confidence is at least 0.90 or the same source IP produced at least 20 attack "
            "events, and down one level if confidence is below 0.65. Severity is only ever "
            "Low, Medium, High or Critical.", S["small"]))
    else:
        story.append(Paragraph(
            "No attacks were detected in this file, so there are no categories, "
            "severities or mitigations to report.", S["body"]))

    story.append(Paragraph("Limitations", S["h2"]))
    story.append(Paragraph(
        "CyberLens AI was trained on a synthetic corpus and is a demonstration of the "
        "analysis pipeline, not a production detector. It only knows seven categories: "
        "Normal, Brute Force, Port Scan, Malware Activity, SQL Injection, Privilege "
        "Escalation and DoS Indicators. Low-confidence attack calls (below 0.55) are "
        "counted as Normal and reported separately. This report was generated entirely "
        "on this machine; no data left it.", S["small"]))

    doc.build(story)
    return save_path
