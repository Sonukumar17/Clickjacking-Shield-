"""PDF Security Report Generation Service

Generates polished, executive-ready PDF audit reports using ReportLab.
Includes cybersecurity visual hierarchy, findings breakdown, technical explanations,
and actionable remediation steps.
"""

import io
from typing import Any, Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def generate_pdf_report(assessment: Dict[str, Any]) -> io.BytesIO:
    """Renders an assessment record into a stylized PDF document in memory."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()

    # Custom color palette (Dark Navy, Cyan, Emerald, Slate)
    NAVY = colors.HexColor("#0f172a")
    DARK_CARD = colors.HexColor("#1e293b")
    TEXT_LIGHT = colors.HexColor("#f8fafc")
    TEXT_MUTED = colors.HexColor("#94a3b8")
    CYAN = colors.HexColor("#06b6d4")
    GREEN = colors.HexColor("#10b981")
    AMBER = colors.HexColor("#f59e0b")
    RED = colors.HexColor("#ef4444")
    BORDER = colors.HexColor("#334155")

    # Pick outcome color
    outcome = assessment.get("outcome", "Inconclusive")
    if outcome == "Protected":
        badge_bg = GREEN
        badge_text = "PROTECTED (Anti-Framing Controls Active)"
    elif outcome == "Potential Risk":
        badge_bg = AMBER
        badge_text = "POTENTIAL RISK (Anti-Framing Controls Missing/Weak)"
    else:
        badge_bg = colors.HexColor("#64748b")
        badge_text = "INCONCLUSIVE (Could Not Assess Reliably)"

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=NAVY,
    )

    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=NAVY,
        spaceAfter=6,
    )

    body_text = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#1e293b"),
    )

    code_text = ParagraphStyle(
        "CodeText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#0f172a"),
    )

    table_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=TEXT_LIGHT,
    )

    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#0f172a"),
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("CYBERSECURITY ASSESSMENT REPORT", title_style))
    story.append(Paragraph("Clickjacking Vulnerability & HTTP Anti-Framing Audit", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=2, color=CYAN, spaceAfter=14))

    # 2. Executive Status Badge Box
    status_table_data = [
        [
            Paragraph(
                f"<font color='white'><b>ASSESSMENT POSTURE: {badge_text}</b></font>",
                ParagraphStyle("Badge", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=10.5, leading=14),
            )
        ]
    ]
    status_table = Table(status_table_data, colWidths=[532])
    status_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), badge_bg),
                ("PADDING", (0, 0), (-1, -1), 8),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(status_table)
    story.append(Spacer(1, 14))

    # 3. Overview Metadata Table
    meta_data = [
        [
            Paragraph("<b>Target Hostname:</b>", body_text),
            Paragraph(assessment.get("hostname", "N/A"), code_text),
            Paragraph("<b>Assessment ID:</b>", body_text),
            Paragraph(assessment.get("id", "N/A")[:18] + "...", code_text),
        ],
        [
            Paragraph("<b>Initial URL:</b>", body_text),
            Paragraph(assessment.get("url", "N/A"), code_text),
            Paragraph("<b>Scan Timestamp:</b>", body_text),
            Paragraph(assessment.get("scan_timestamp", "N/A"), body_text),
        ],
        [
            Paragraph("<b>Final Destination:</b>", body_text),
            Paragraph(assessment.get("final_url", "N/A"), code_text),
            Paragraph("<b>Confidence Level:</b>", body_text),
            Paragraph(f"<b>{assessment.get('confidence', 'Medium')}</b>", body_text),
        ],
        [
            Paragraph("<b>HTTP Status:</b>", body_text),
            Paragraph(f"HTTP {assessment.get('http_status', 'N/A')}", body_text),
            Paragraph("<b>Target IP:</b>", body_text),
            Paragraph(assessment.get("ip_address", "N/A"), code_text),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[105, 161, 105, 161])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 4. Anti-Framing Header Findings Table
    story.append(Paragraph("Security Header Findings", section_heading))
    headers_table_data = [
        [
            Paragraph("Security Mechanism", table_header),
            Paragraph("Status & Directives", table_header),
            Paragraph("Evaluation Details", table_header),
        ],
        [
            Paragraph("<b>X-Frame-Options</b>", table_cell),
            Paragraph(
                f"<b>Status:</b> {assessment.get('xfo_status', 'Missing')}<br/>"
                f"<b>Value:</b> {assessment.get('xfo_raw') or 'None'}",
                table_cell,
            ),
            Paragraph(assessment.get("xfo_details", "No details available."), table_cell),
        ],
        [
            Paragraph("<b>Content-Security-Policy</b><br/>(frame-ancestors)", table_cell),
            Paragraph(
                f"<b>Status:</b> {assessment.get('csp_status', 'Missing')}<br/>"
                f"<b>Directive:</b> {assessment.get('csp_frame_ancestors') or 'None'}",
                table_cell,
            ),
            Paragraph(assessment.get("csp_details", "No details available."), table_cell),
        ],
    ]

    headers_table = Table(headers_table_data, colWidths=[120, 182, 230])
    headers_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]
        )
    )
    story.append(headers_table)
    story.append(Spacer(1, 14))

    # 5. Technical Explanation Box
    story.append(Paragraph("Technical Evaluation & Threat Context", section_heading))
    explanation_p = Paragraph(assessment.get("explanation", "N/A"), body_text)
    exp_table = Table([[explanation_p]], colWidths=[532])
    exp_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(exp_table)
    story.append(Spacer(1, 12))

    # 6. Actionable Remediation Guidance
    story.append(Paragraph("Actionable Remediation Guidance", section_heading))
    remediation_text = assessment.get("remediation", "None specified.").replace("\n", "<br/>")
    remediation_p = Paragraph(remediation_text, body_text)
    rem_table = Table([[remediation_p]], colWidths=[532])
    rem_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ecfdf5")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#6ee7b7")),
                ("PADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(rem_table)
    story.append(Spacer(1, 12))

    # 7. Limitations & Ethical Disclaimer
    story.append(Paragraph("Audit Limitations & Ethical Scope", section_heading))
    disclaimer_text = (
        "<b>Limitations Notice:</b> This automated audit examines HTTP response headers delivered by the server. "
        "It does not perform active browser DOM frame-busting analysis, verify authentication state boundaries, or "
        "assess contextual UI vulnerability. Missing headers constitute a configuration deficiency, not guaranteed "
        "exploitability.<br/>"
        "<b>Ethical Use Notice:</b> Assessments must be conducted strictly on systems owned or explicitly authorized "
        "for defensive cybersecurity review."
    )
    disc_table = Table([[Paragraph(disclaimer_text, table_cell)]], colWidths=[532])
    disc_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(disc_table)

    doc.build(story)
    buffer.seek(0)
    return buffer
