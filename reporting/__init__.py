"""Reporting module - generates PDF incident reports (FR-14, FR-15, FR-16)"""
import os
import tempfile
from datetime import datetime
from typing import List, Dict, Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT


# ── Colour palette ──────────────────────────────────────────────────────────
COLORS = {
    'primary':   HexColor('#1e3a5f'),
    'secondary': HexColor('#2c5f8a'),
    'accent':    HexColor('#e8a838'),
    'critical':  HexColor('#c0392b'),
    'high':      HexColor('#e74c3c'),
    'medium':    HexColor('#f39c12'),
    'low':       HexColor('#27ae60'),
    'normal':    HexColor('#2980b9'),
    'bg_light':  HexColor('#f8f9fa'),
    'bg_dark':   HexColor('#ecf0f1'),
    'text':      HexColor('#2c3e50'),
    'white':     HexColor('#ffffff'),
}

SEV_COLORS = {
    'Critical': COLORS['critical'],
    'High':     COLORS['high'],
    'Medium':   COLORS['medium'],
    'Low':      COLORS['low'],
}


def generate_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate summary statistics from analysis results (FR-14)."""
    from cybersecurity import get_attack_statistics
    return get_attack_statistics(results)


def generate_pdf_report(results: List[Dict[str, Any]]) -> str:
    """Main entry point — build and return a PDF report path (FR-16)."""
    summary = generate_summary(results)
    return _build_pdf(results, summary)


def _build_pdf(results, summary):
    """Build the actual PDF with reportlab."""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    temp_path = temp_file.name
    temp_file.close()

    doc = SimpleDocTemplate(
        temp_path, pagesize=A4,
        rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50,
    )

    styles = getSampleStyleSheet()
    story = []

    # ── Custom styles ─────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        'CTitle', parent=styles['Title'],
        fontSize=28, textColor=COLORS['primary'],
        spaceAfter=10, alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        'CSubtitle', parent=styles['Normal'],
        fontSize=14, textColor=COLORS['secondary'],
        spaceAfter=20, alignment=TA_CENTER,
    )
    heading_style = ParagraphStyle(
        'CHeading', parent=styles['Heading2'],
        fontSize=16, textColor=COLORS['primary'],
        spaceBefore=20, spaceAfter=10,
    )
    body_style = ParagraphStyle(
        'CBody', parent=styles['Normal'],
        fontSize=10, textColor=COLORS['text'], spaceAfter=6,
    )

    # ── Title page ────────────────────────────────────────────────────────
    story.append(Paragraph('CyberLens AI', title_style))
    story.append(Paragraph('Incident Analysis Report', subtitle_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 20))

    # ── Executive summary (FR-14) ─────────────────────────────────────────
    story.append(Paragraph('Executive Summary', heading_style))

    summary_data = [
        ['Metric', 'Value'],
        ['Total Records Analyzed', str(summary.get('total_records', 0))],
        ['Total Attacks Detected', str(summary.get('total_attacks', 0))],
        ['Normal Records',        str(summary.get('normal_records', 0))],
        ['Attack Percentage',     f"{summary.get('attack_percentage', 0)}%"],
    ]
    story.append(_styled_table(summary_data, [3 * inch, 2 * inch]))
    story.append(Spacer(1, 20))

    # ── Category distribution ─────────────────────────────────────────────
    if summary.get('category_distribution'):
        story.append(Paragraph('Attack Category Distribution', heading_style))
        cat_data = [['Category', 'Count', 'Percentage']]
        total_attacks = max(summary.get('total_attacks', 1), 1)
        for cat, count in sorted(
            summary['category_distribution'].items(), key=lambda x: -x[1]
        ):
            pct = round(count / total_attacks * 100, 1)
            cat_data.append([cat, str(count), f'{pct}%'])
        story.append(_styled_table(cat_data, [2.5 * inch, 1.5 * inch, 1.5 * inch]))
        story.append(Spacer(1, 20))

    # ── Severity distribution ─────────────────────────────────────────────
    if summary.get('severity_distribution'):
        story.append(Paragraph('Severity Distribution', heading_style))
        sev_data = [['Severity', 'Count']]
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            count = summary['severity_distribution'].get(sev, 0)
            if count > 0:
                sev_data.append([sev, str(count)])
        story.append(_styled_table(sev_data, [2 * inch, 2 * inch]))
        story.append(Spacer(1, 20))

    # ── Attack timeline (FR-15) ───────────────────────────────────────────
    attacks = [r for r in results if r.get('category') != 'Normal']
    if attacks:
        story.append(Paragraph('Attack Timeline', heading_style))
        story.append(Paragraph(
            'Chronological list of detected attacks:', body_style))
        story.append(Spacer(1, 10))

        attacks_sorted = sorted(attacks, key=lambda x: str(x.get('timestamp', '')))

        tl_data = [['Timestamp', 'Category', 'Severity', 'Confidence',
                     'Source IP', 'Mitigation']]

        for atk in attacks_sorted[:50]:
            ts = str(atk.get('timestamp', 'N/A'))[:25]
            cat = atk.get('category', 'Unknown')
            sev = atk.get('severity', 'Medium')
            conf = f"{atk.get('confidence', 0):.1%}"
            ip = str(atk.get('source_ip', 'N/A'))[:20]
            mit = str(atk.get('mitigation', 'N/A'))[:60]
            tl_data.append([ts, cat, sev, conf, ip, mit])

        col_widths = [1.1 * inch, 0.9 * inch, 0.7 * inch,
                      0.7 * inch, 0.9 * inch, 2.3 * inch]
        tl_table = _styled_table(tl_data, col_widths, font_size=7)

        # Colour-code severity cells
        for i, atk in enumerate(attacks_sorted[:50], 1):
            sev = atk.get('severity', 'Medium')
            if sev in SEV_COLORS:
                tl_table.setStyle(TableStyle([
                    ('TEXTCOLOR', (2, i), (2, i), SEV_COLORS[sev]),
                    ('FONTNAME',  (2, i), (2, i), 'Helvetica-Bold'),
                ]))

        story.append(tl_table)

        if len(attacks) > 50:
            story.append(Spacer(1, 10))
            story.append(Paragraph(
                f'<i>Showing first 50 of {len(attacks)} attacks.</i>', body_style))

    # ── Recommendations ───────────────────────────────────────────────────
    story.append(Spacer(1, 30))
    story.append(Paragraph('Recommendations', heading_style))
    recommendations = [
        'Review all Critical and High severity alerts immediately',
        'Implement mitigations as suggested for each attack category',
        'Update firewall rules to block malicious source IPs',
        'Enable enhanced monitoring for affected systems',
        'Conduct post-incident review and update security policies',
        'Consider threat hunting for potential lateral movement',
        'Update IDS/IPS signatures based on detected patterns',
        'Schedule regular security awareness training for staff',
    ]
    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f'{i}. {rec}', body_style))

    # ── Footer ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 30))
    footer_style = ParagraphStyle(
        'CFooter', parent=styles['Normal'],
        fontSize=8, textColor=HexColor('#95a5a6'), alignment=TA_CENTER,
    )
    story.append(Paragraph('— End of Report —', footer_style))
    story.append(Paragraph(
        'Generated by CyberLens AI — Intelligent Log Analysis & Attack Detection',
        footer_style))

    doc.build(story)
    return temp_path


def _styled_table(data, col_widths, font_size=10):
    """Return a consistently-styled Table."""
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND',     (0, 0), (-1, 0), COLORS['primary']),
        ('TEXTCOLOR',      (0, 0), (-1, 0), COLORS['white']),
        ('ALIGN',          (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME',       (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',       (0, 0), (-1, -1), font_size),
        ('BOTTOMPADDING',  (0, 0), (-1, 0), 10),
        ('BACKGROUND',     (0, 1), (-1, -1), COLORS['bg_light']),
        ('GRID',           (0, 0), (-1, -1), 0.5, COLORS['bg_dark']),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1),
         [COLORS['white'], COLORS['bg_light']]),
    ]))
    return t
