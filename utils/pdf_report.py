"""
CipherGuard — PDF Forensic Report Generator
Generates a professional PDF report of all detected threats and statistics.
"""

import os
from datetime import datetime
from typing import List

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)

from models.schemas import ThreatStats
from config import APP_NAME, APP_VERSION, PDF_REPORT_FILENAME, BASE_DIR
from utils.logger import setup_logger

logger = setup_logger("PDFReport")


def generate_report(
    stats: ThreatStats,
    hijack_events: List[dict],
    output_path: str = None
) -> str:
    """
    Generate a PDF forensic report.

    Args:
        stats: Aggregated threat statistics.
        hijack_events: List of hijack event dicts from the database.
        output_path: Custom output path (defaults to project directory).

    Returns:
        Absolute path to the generated PDF file.
    """
    if output_path is None:
        output_path = os.path.join(BASE_DIR, PDF_REPORT_FILENAME)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    # ─── Styles ───────────────────────────────────────────
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor("#1a1a2e"),
        spaceAfter=6,
    )

    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.HexColor("#666666"),
        spaceAfter=20,
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor("#0f3460"),
        spaceBefore=20,
        spaceAfter=10,
    )

    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor("#333333"),
        spaceAfter=8,
    )

    # ─── Build Document ──────────────────────────────────
    elements = []

    # Title
    elements.append(Paragraph(f"🛡️ {APP_NAME} — Forensic Threat Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Version: {APP_VERSION}",
        subtitle_style
    ))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0f3460")))
    elements.append(Spacer(1, 12))

    # Executive Summary
    elements.append(Paragraph("📊 Executive Summary", heading_style))
    elements.append(Paragraph(
        f"This report summarizes the security events detected by {APP_NAME} "
        f"during the monitoring session that started at {stats.session_start_time[:19]}.",
        normal_style
    ))

    # Statistics Table
    stats_data = [
        ["Metric", "Value"],
        ["Keystrokes Protected", str(stats.total_keystrokes_protected)],
        ["Clipboard Hijacks Blocked", str(stats.total_clipboard_hijacks_blocked)],
        ["Clipboard Copies Monitored", str(stats.total_clipboard_copies_monitored)],
        ["Unique Attacker Processes", str(stats.unique_attacker_processes)],
        ["Vault Entries", str(stats.vault_entries_count)],
    ]

    stats_table = Table(stats_data, colWidths=[250, 200])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f3460")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 11),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 20))

    # Hijack Events Detail
    if hijack_events:
        elements.append(Paragraph("🚨 Clipboard Hijack Events", heading_style))
        elements.append(Paragraph(
            f"A total of {len(hijack_events)} clipboard hijack attempts were detected and blocked.",
            normal_style
        ))

        # Events table
        events_data = [["#", "Timestamp", "Pattern", "Attacker Process", "Action"]]
        for i, event in enumerate(hijack_events[:20], 1):  # Limit to 20 for readability
            events_data.append([
                str(i),
                event.get("timestamp", "")[:19],
                event.get("pattern_type", "Unknown"),
                event.get("attacker_process", "Unknown")[:40],
                event.get("action_taken", ""),
            ])

        events_table = Table(events_data, colWidths=[30, 130, 80, 180, 70])
        events_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#cc0000")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff0f0")]),
        ]))
        elements.append(events_table)
        elements.append(Spacer(1, 20))

        # Detailed event breakdowns
        elements.append(Paragraph("📋 Event Details", heading_style))
        for i, event in enumerate(hijack_events[:5], 1):  # Detail first 5
            elements.append(Paragraph(
                f"<b>Event #{i}</b> — {event.get('timestamp', '')[:19]}",
                normal_style
            ))
            elements.append(Paragraph(
                f"<b>Original Content:</b> {event.get('original_content', 'N/A')[:80]}",
                normal_style
            ))
            elements.append(Paragraph(
                f"<b>Hijacked Content:</b> {event.get('hijacked_content', 'N/A')[:80]}",
                normal_style
            ))
            elements.append(Paragraph(
                f"<b>Attacker:</b> {event.get('attacker_process', 'Unknown')} "
                f"(PID: {event.get('attacker_pid', 'N/A')})",
                normal_style
            ))
            elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd")))
            elements.append(Spacer(1, 8))
    else:
        elements.append(Paragraph("✅ No Hijack Events", heading_style))
        elements.append(Paragraph(
            "No clipboard hijack attempts were detected during this session.",
            normal_style
        ))

    # Footer
    elements.append(Spacer(1, 40))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f3460")))
    elements.append(Paragraph(
        f"Report generated by {APP_NAME} v{APP_VERSION} | "
        f"© {datetime.now().year} CipherGuard Project",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9,
                       textColor=colors.HexColor("#999999"), alignment=1)
    ))

    # Build PDF
    doc.build(elements)
    logger.info(f"PDF report generated: {output_path}")
    return output_path
