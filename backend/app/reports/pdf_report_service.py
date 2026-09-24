import io
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from app.core.logging import logger
from app.models.scan import Scan


class PDFReportService:
    @staticmethod
    def generate_scan_pdf(scan: Scan, intelligence_data: Optional[Dict[str, Any]] = None) -> bytes:
        """
        Generates a publication-grade, vector-rendered cybersecurity audit report
        for a PhishGuard AI scan using ReportLab.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        # Custom high-contrast styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b"),
        )
        heading_style = ParagraphStyle(
            "DocHeading",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )
        label_style = ParagraphStyle(
            "DocLabel",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#475569"),
        )
        val_style = ParagraphStyle(
            "DocVal",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#0f172a"),
        )
        body_style = ParagraphStyle(
            "DocBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#334155"),
        )

        elements = []

        # 1. Header Banner
        header_table_data = [
            [
                Paragraph("<b>PHISHGUARD AI</b>", title_style),
                Paragraph(
                    f"<b>REPORT GENERATED:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>"
                    f"<b>CLASSIFICATION:</b> OFFICIAL CYBERSECURITY REPORT",
                    subtitle_style,
                ),
            ]
        ]
        header_table = Table(header_table_data, colWidths=[3.5 * inch, 4.0 * inch])
        header_table.setStyle(
            TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ])
        )
        elements.append(header_table)
        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=14))

        # 2. Executive Threat Assessment
        verdict = (scan.scan_result.verdict if scan.scan_result else "unrated").upper()
        risk_score = scan.scan_result.risk_score if (scan.scan_result and scan.scan_result.risk_score is not None) else 0.0
        confidence = scan.scan_result.confidence_score if (scan.scan_result and scan.scan_result.confidence_score is not None) else 0.0

        # Determine verdict palette
        if verdict == "PHISHING":
            banner_bg = colors.HexColor("#ffe4e6")
            banner_border = colors.HexColor("#e11d48")
            banner_text_color = colors.HexColor("#9f1239")
            verdict_badge = "THREAT DETECTED: PHISHING"
        elif verdict == "SUSPICIOUS":
            banner_bg = colors.HexColor("#fef3c7")
            banner_border = colors.HexColor("#d97706")
            banner_text_color = colors.HexColor("#92400e")
            verdict_badge = "ELEVATED RISK: SUSPICIOUS"
        elif verdict == "LEGITIMATE":
            banner_bg = colors.HexColor("#dcfce7")
            banner_border = colors.HexColor("#16a34a")
            banner_text_color = colors.HexColor("#166534")
            verdict_badge = "BENIGN TARGET: LEGITIMATE"
        else:
            banner_bg = colors.HexColor("#f1f5f9")
            banner_border = colors.HexColor("#64748b")
            banner_text_color = colors.HexColor("#334155")
            verdict_badge = "UNRATED SCAN"

        assessment_style = ParagraphStyle(
            "AssessmentBanner",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=banner_text_color,
        )

        assessment_data = [
            [
                Paragraph(f"<b>{verdict_badge}</b><br/><font size=9>Empirical Multi-Modal Decision Policy</font>", assessment_style),
                Paragraph(
                    f"<b>RISK SCORE:</b> {risk_score:.1f} / 100<br/>"
                    f"<b>CONFIDENCE:</b> {(confidence * 100):.1f}%",
                    ParagraphStyle("RiskScore", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=11, leading=15, textColor=banner_text_color, alignment=2),
                ),
            ]
        ]
        assessment_table = Table(assessment_data, colWidths=[4.5 * inch, 3.0 * inch])
        assessment_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), banner_bg),
                ("BOX", (0, 0), (-1, -1), 1, banner_border),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ])
        )
        elements.append(assessment_table)
        elements.append(Spacer(1, 14))

        # 3. Target Metadata Table
        elements.append(Paragraph("<b>Target Metadata & Telemetry</b>", heading_style))
        created_str = scan.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.created_at else "N/A"
        meta_data = [
            [Paragraph("Target URL:", label_style), Paragraph(scan.url or "N/A", val_style)],
            [Paragraph("Target Domain:", label_style), Paragraph(scan.domain or "N/A", val_style)],
            [Paragraph("Scan UUID:", label_style), Paragraph(scan.id, val_style)],
            [Paragraph("Scan Status:", label_style), Paragraph((scan.status or "completed").upper(), val_style)],
            [Paragraph("Created Timestamp:", label_style), Paragraph(created_str, val_style)],
            [Paragraph("Client / Request IP:", label_style), Paragraph(scan.client_ip or "Internal / Loopback", val_style)],
        ]
        meta_table = Table(meta_data, colWidths=[1.8 * inch, 5.7 * inch])
        meta_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ])
        )
        elements.append(meta_table)
        elements.append(Spacer(1, 14))

        # 4. Multi-Modal Intelligence Breakdown
        elements.append(Paragraph("<b>Multi-Modal AI Decision Signals</b>", heading_style))
        url_prob = "N/A"
        dom_prob = "N/A"
        vis_prob = "N/A"
        fused_prob = f"{(confidence * 100):.1f}%" if scan.scan_result else "N/A"

        if intelligence_data and "modality_breakdown" in intelligence_data:
            mb = intelligence_data["modality_breakdown"]
            if "url" in mb and mb["url"].get("phishing_probability") is not None:
                url_prob = f"{(mb['url']['phishing_probability'] * 100):.1f}%"
            if "website" in mb and mb["website"].get("phishing_probability") is not None:
                dom_prob = f"{(mb['website']['phishing_probability'] * 100):.1f}%"
            if "visual" in mb and mb["visual"].get("phishing_probability") is not None:
                vis_prob = f"{(mb['visual']['phishing_probability'] * 100):.1f}%"

        modal_data = [
            [
                Paragraph("<b>Modality</b>", label_style),
                Paragraph("<b>Model Architecture</b>", label_style),
                Paragraph("<b>Status</b>", label_style),
                Paragraph("<b>Phishing Probability</b>", label_style),
            ],
            [
                Paragraph("URL Intelligence", val_style),
                Paragraph("RandomForest / LightGBM (34 Lexical Features)", body_style),
                Paragraph("Analyzed", val_style),
                Paragraph(url_prob, val_style),
            ],
            [
                Paragraph("Website Telemetry", val_style),
                Paragraph("DOM / Form / SSL / Script Analysis (48 Features)", body_style),
                Paragraph("Analyzed" if scan.html_features else "Skipped", val_style),
                Paragraph(dom_prob, val_style),
            ],
            [
                Paragraph("Visual AI", val_style),
                Paragraph("MobileNetV2 Transfer Learning + Grad-CAM", body_style),
                Paragraph("Analyzed" if scan.visual_analysis else "Unavailable", val_style),
                Paragraph(vis_prob, val_style),
            ],
            [
                Paragraph("<b>Multi-Modal Fusion</b>", label_style),
                Paragraph("<b>Stacking Meta-Classifier + Platt Calibration</b>", label_style),
                Paragraph("<b>Active</b>", label_style),
                Paragraph(f"<b>{fused_prob}</b>", label_style),
            ],
        ]
        modal_table = Table(modal_data, colWidths=[1.8 * inch, 3.2 * inch, 1.2 * inch, 1.3 * inch])
        modal_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#e0f2fe")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ])
        )
        elements.append(modal_table)
        elements.append(Spacer(1, 14))

        # 5. Threat Indicators Table
        elements.append(Paragraph("<b>Triggered Security Indicators & Evidence</b>", heading_style))
        indicators: List = scan.threat_indicators or []
        if indicators:
            ind_data = [
                [
                    Paragraph("<b>Rule ID</b>", label_style),
                    Paragraph("<b>Type</b>", label_style),
                    Paragraph("<b>Severity</b>", label_style),
                    Paragraph("<b>Finding Details</b>", label_style),
                ]
            ]
            for ind in indicators[:12]:  # Top 12 indicators to fit clean page layout
                sev_color = "#e11d48" if ind.severity in ["high", "critical"] else "#d97706" if ind.severity == "medium" else "#64748b"
                ind_data.append([
                    Paragraph(ind.rule_id, val_style),
                    Paragraph(ind.indicator_type.upper(), body_style),
                    Paragraph(f"<font color='{sev_color}'><b>{ind.severity.upper()}</b></font>", body_style),
                    Paragraph(ind.description or ind.details or "Pattern detected", body_style),
                ])
            ind_table = Table(ind_data, colWidths=[1.6 * inch, 1.2 * inch, 1.0 * inch, 3.7 * inch])
            ind_table.setStyle(
                TableStyle([
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ])
            )
            elements.append(ind_table)
        else:
            no_ind_p = Paragraph(
                "<i>No explicit heuristic threat indicators or blacklisted security patterns were triggered during static and heuristic examination.</i>",
                body_style,
            )
            elements.append(no_ind_p)

        elements.append(Spacer(1, 16))

        # 6. Academic Provenance & Disclaimer Notice
        disclaimer_p = Paragraph(
            "<b>PROVENANCE & ACADEMIC NOTICE:</b> This threat assessment report was automatically synthesized by the PhishGuard AI "
            "Multi-Modal Intelligence Engine. Signals incorporate URL lexical modeling, DOM AST security metrics, and transfer-learning "
            "visual analysis calibrated through empirical decision boundaries. This artifact was produced in accordance with IEEE CSE "
            "Project guidelines. Results should be corroborated with security operations center (SOC) operational policy.",
            ParagraphStyle("Disclaimer", parent=styles["Normal"], fontName="Helvetica-Oblique", fontSize=7, leading=10, textColor=colors.HexColor("#94a3b8")),
        )
        elements.append(KeepTogether([
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=8),
            disclaimer_p,
        ]))

        # Build PDF
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        logger.info(f"Generated PDF report for scan {scan.id} (size: {len(pdf_bytes)} bytes)")
        return pdf_bytes
