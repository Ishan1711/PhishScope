import io
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from app.models.analysis import AnalysisResult

# Brand colors
COLOR_DARK = colors.HexColor("#0a0a0f")
COLOR_CARD = colors.HexColor("#18181b")
COLOR_ACCENT = colors.HexColor("#3b82f6")
COLOR_SAFE = colors.HexColor("#10b981")
COLOR_WARNING = colors.HexColor("#f59e0b")
COLOR_DANGER = colors.HexColor("#ef4444")
COLOR_TEXT = colors.HexColor("#fafafa")
COLOR_MUTED = colors.HexColor("#a1a1aa")
COLOR_BORDER = colors.HexColor("#27272a")
COLOR_ROW_ALT = colors.HexColor("#1c1c1f")


def _get_threat_color(threat_level: str) -> colors.Color:
    if threat_level == "HIGHLY SUSPICIOUS":
        return COLOR_DANGER
    elif threat_level == "SUSPICIOUS":
        return COLOR_WARNING
    return COLOR_SAFE


def _get_severity_color(severity: str) -> colors.Color:
    if severity == "HIGH":
        return COLOR_DANGER
    elif severity == "MEDIUM":
        return COLOR_WARNING
    return colors.HexColor("#6366f1")


class ReportGenerator:
    """Service for exporting analysis results to JSON and PDF formats."""

    @staticmethod
    def generate_json(analysis: AnalysisResult) -> str:
        """Serializes the AnalysisResult model to a JSON string."""
        return analysis.model_dump_json(indent=2)

    @staticmethod
    def generate_pdf(analysis: AnalysisResult) -> bytes:
        """Generates a professional enterprise-grade PDF report from the AnalysisResult."""
        buffer = io.BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.6 * inch,
            leftMargin=0.6 * inch,
            topMargin=0.7 * inch,
            bottomMargin=0.7 * inch,
        )

        styles = getSampleStyleSheet()

        # --- Custom Style Definitions ---
        def make_style(name, parent_name='Normal', **kwargs):
            return ParagraphStyle(name, parent=styles[parent_name], **kwargs)

        report_title_style = make_style('ReportTitle', 'Title',
            textColor=COLOR_TEXT, fontSize=22, leading=28, spaceAfter=4)
        subtitle_style = make_style('Subtitle',
            textColor=COLOR_MUTED, fontSize=10, leading=14, spaceAfter=16)
        section_header_style = make_style('SectionHeader',
            textColor=COLOR_ACCENT, fontSize=12, leading=16,
            fontName='Helvetica-Bold', spaceBefore=16, spaceAfter=8)
        normal_dark_style = make_style('NormalDark',
            textColor=COLOR_TEXT, fontSize=9, leading=14)
        muted_style = make_style('Muted',
            textColor=COLOR_MUTED, fontSize=8, leading=12)
        threat_label_style = make_style('ThreatLabel',
            textColor=_get_threat_color(analysis.risk_assessment.threat_level),
            fontSize=14, fontName='Helvetica-Bold', leading=20)
        footer_style = make_style('Footer',
            textColor=COLOR_MUTED, fontSize=7.5, leading=10, alignment=TA_CENTER)
        ai_style = make_style('AIText',
            textColor=COLOR_TEXT, fontSize=9, leading=15)

        threat_color = _get_threat_color(analysis.risk_assessment.threat_level)
        elements = []

        # ==========================================
        # HEADER BANNER
        # ==========================================
        header_data = [[
            Paragraph('<b>PhishScope</b>', make_style('BrandStyle',
                textColor=COLOR_ACCENT, fontSize=16, fontName='Helvetica-Bold', leading=20)),
            Paragraph('INVESTIGATION REPORT', make_style('ReportTypeStyle',
                textColor=COLOR_MUTED, fontSize=9, leading=12, alignment=TA_RIGHT)),
        ]]
        header_table = Table(header_data, colWidths=[4*inch, 3.5*inch])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (0, -1), 0),
            ('RIGHTPADDING', (-1, 0), (-1, -1), 0),
        ]))
        elements.append(header_table)
        elements.append(HRFlowable(width='100%', thickness=1, color=COLOR_BORDER))
        elements.append(Spacer(1, 12))

        # ==========================================
        # THREAT LEVEL BANNER
        # ==========================================
        threat_banner_data = [[
            Paragraph(f'VERDICT: {analysis.risk_assessment.threat_level}', threat_label_style),
            Paragraph(
                f'Threat Score: <b>{analysis.risk_assessment.threat_score}/100</b> &nbsp;&nbsp; Confidence: <b>{analysis.risk_assessment.confidence_score}%</b>',
                make_style('ScoreInfo', textColor=COLOR_TEXT, fontSize=11, leading=14, alignment=TA_RIGHT)
            ),
        ]]
        threat_banner_table = Table(threat_banner_data, colWidths=[3.5*inch, 4*inch])
        threat_banner_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), COLOR_CARD),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 14),
            ('RIGHTPADDING', (0, 0), (-1, -1), 14),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LINEBELOW', (0, 0), (-1, -1), 2, threat_color),
        ]))
        elements.append(threat_banner_table)
        elements.append(Spacer(1, 14))

        # ==========================================
        # INVESTIGATION METADATA
        # ==========================================
        elements.append(Paragraph('Investigation Details', section_header_style))

        analysis_dt = datetime.fromisoformat(analysis.analysis_time.replace('Z', '+00:00'))
        formatted_time = analysis_dt.strftime('%B %d, %Y at %H:%M UTC')

        meta_data = [
            ['Investigation ID', analysis.investigation_id, 'Analysis Time', formatted_time],
            ['Report Version', analysis.version, 'Duration', f'{analysis.analysis_duration_ms}ms'],
            ['Indicators Found', str(analysis.risk_assessment.ioc_summary.total), 'URL Threats', str(analysis.risk_assessment.ioc_summary.url_threats)],
        ]
        meta_table = Table(meta_data, colWidths=[1.4*inch, 2.3*inch, 1.4*inch, 2.3*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), COLOR_CARD),
            ('BACKGROUND', (0, 0), (0, -1), COLOR_ROW_ALT),
            ('BACKGROUND', (2, 0), (2, -1), COLOR_ROW_ALT),
            ('TEXTCOLOR', (0, 0), (0, -1), COLOR_MUTED),
            ('TEXTCOLOR', (2, 0), (2, -1), COLOR_MUTED),
            ('TEXTCOLOR', (1, 0), (1, -1), COLOR_TEXT),
            ('TEXTCOLOR', (3, 0), (3, -1), COLOR_TEXT),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('FONTNAME', (3, 0), (3, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.3, COLOR_BORDER),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 14))

        # ==========================================
        # EMAIL DETAILS
        # ==========================================
        hdr = analysis.header_data
        elements.append(Paragraph('Email Information', section_header_style))

        ip_display = hdr.originating_ip
        if hdr.ip_is_hidden:
            ip_display = f"Hidden by Email Provider ({hdr.ip_provider})"
        elif not ip_display:
            ip_display = "N/A"

        email_details = [
            ['Subject', hdr.subject or 'N/A'],
            ['From', hdr.from_address or 'N/A'],
            ['Display Name', hdr.display_name or 'N/A'],
            ['Sender Domain', hdr.from_domain or 'N/A'],
            ['Reply-To', hdr.reply_to or 'N/A'],
            ['Return-Path', hdr.return_path or 'N/A'],
            ['To', hdr.to_address or 'N/A'],
            ['Date', hdr.date or 'N/A'],
            ['Message-ID', hdr.message_id or 'N/A'],
            ['Originating IP', ip_display],
        ]
        email_table = Table(email_details, colWidths=[1.4*inch, 6*inch])
        email_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), COLOR_CARD),
            ('BACKGROUND', (0, 0), (0, -1), COLOR_ROW_ALT),
            ('TEXTCOLOR', (0, 0), (0, -1), COLOR_MUTED),
            ('TEXTCOLOR', (1, 0), (1, -1), COLOR_TEXT),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ('WORDWRAP', (1, 0), (1, -1), True),
        ]))
        elements.append(email_table)
        elements.append(Spacer(1, 14))

        # ==========================================
        # AUTHENTICATION RESULTS
        # ==========================================
        elements.append(Paragraph('Authentication Results', section_header_style))

        auth = hdr.auth_results

        def auth_color(result: str) -> colors.Color:
            if result == "PASS":
                return COLOR_SAFE
            elif result in ("FAIL", "SOFTFAIL"):
                return COLOR_DANGER
            return COLOR_WARNING

        auth_data = [
            [
                Paragraph('<b>Protocol</b>', muted_style),
                Paragraph('<b>Result</b>', muted_style),
                Paragraph('<b>Details</b>', muted_style),
            ],
            [
                Paragraph('SPF', normal_dark_style),
                Paragraph(f'<b>{auth.spf}</b>', make_style('AuthResult',
                    textColor=auth_color(auth.spf), fontSize=9, fontName='Helvetica-Bold', leading=12)),
                Paragraph(auth.spf_domain or '—', muted_style),
            ],
            [
                Paragraph('DKIM', normal_dark_style),
                Paragraph(f'<b>{auth.dkim}</b>', make_style('AuthResult2',
                    textColor=auth_color(auth.dkim), fontSize=9, fontName='Helvetica-Bold', leading=12)),
                Paragraph(f"domain: {auth.dkim_domain or '—'}  selector: {auth.dkim_selector or '—'}", muted_style),
            ],
            [
                Paragraph('DMARC', normal_dark_style),
                Paragraph(f'<b>{auth.dmarc}</b>', make_style('AuthResult3',
                    textColor=auth_color(auth.dmarc), fontSize=9, fontName='Helvetica-Bold', leading=12)),
                Paragraph(f"policy: {auth.dmarc_policy or '—'}", muted_style),
            ],
        ]
        auth_table = Table(auth_data, colWidths=[1.2*inch, 1.5*inch, 4.7*inch])
        auth_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_ROW_ALT),
            ('BACKGROUND', (0, 1), (-1, -1), COLOR_CARD),
            ('TEXTCOLOR', (0, 0), (-1, -1), COLOR_TEXT),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.3, COLOR_BORDER),
        ]))
        elements.append(auth_table)
        elements.append(Spacer(1, 14))

        # ==========================================
        # SCORE BREAKDOWN
        # ==========================================
        elements.append(Paragraph('Risk Score Breakdown', section_header_style))

        if analysis.risk_assessment.score_breakdown:
            breakdown_data = [
                [
                    Paragraph('<b>Points</b>', muted_style),
                    Paragraph('<b>Reason</b>', muted_style),
                    Paragraph('<b>Category</b>', muted_style),
                    Paragraph('<b>Severity</b>', muted_style),
                ]
            ]
            for item in sorted(analysis.risk_assessment.score_breakdown, key=lambda x: x.points, reverse=True):
                breakdown_data.append([
                    Paragraph(f'<b>+{item.points}</b>', make_style(f'BreakdownPts_{item.points}',
                        textColor=_get_severity_color(item.severity), fontSize=9, fontName='Helvetica-Bold', leading=12)),
                    Paragraph(item.reason, normal_dark_style),
                    Paragraph(item.category, muted_style),
                    Paragraph(item.severity, make_style(f'BrkSev_{item.severity}',
                        textColor=_get_severity_color(item.severity), fontSize=8, leading=12)),
                ])
            breakdown_table = Table(breakdown_data, colWidths=[0.7*inch, 4*inch, 1.2*inch, 0.9*inch])
            breakdown_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLOR_ROW_ALT),
                ('BACKGROUND', (0, 1), (-1, -1), COLOR_CARD),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_CARD, COLOR_ROW_ALT]),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ]))
            elements.append(breakdown_table)
        else:
            elements.append(Paragraph('No score contributors detected.', muted_style))
        elements.append(Spacer(1, 14))

        # ==========================================
        # PHISHING INDICATORS
        # ==========================================
        elements.append(Paragraph('Identified Phishing Indicators', section_header_style))

        if analysis.risk_assessment.indicators:
            indicator_data = [
                [
                    Paragraph('<b>Severity</b>', muted_style),
                    Paragraph('<b>Indicator</b>', muted_style),
                    Paragraph('<b>Description</b>', muted_style),
                ]
            ]
            for ind in analysis.risk_assessment.indicators:
                sev_color = _get_severity_color(ind.severity)
                indicator_data.append([
                    Paragraph(f'<b>{ind.severity}</b>', make_style(f'IndSev_{ind.name[:10]}',
                        textColor=sev_color, fontSize=8, fontName='Helvetica-Bold', leading=12)),
                    Paragraph(ind.name, make_style(f'IndName_{ind.name[:10]}',
                        textColor=COLOR_TEXT, fontSize=8, fontName='Helvetica-Bold', leading=12)),
                    Paragraph(ind.description, muted_style),
                ])
            ind_table = Table(indicator_data, colWidths=[0.7*inch, 1.8*inch, 4.9*inch])
            ind_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLOR_ROW_ALT),
                ('BACKGROUND', (0, 1), (-1, -1), COLOR_CARD),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_CARD, COLOR_ROW_ALT]),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.3, COLOR_BORDER),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(ind_table)
        else:
            elements.append(Paragraph('No significant phishing indicators found.', muted_style))
        elements.append(Spacer(1, 14))

        # ==========================================
        # MITRE ATT&CK MAPPING
        # ==========================================
        if analysis.risk_assessment.mitre_techniques:
            elements.append(Paragraph('MITRE ATT&CK® Technique Mapping', section_header_style))
            mitre_data = [
                [
                    Paragraph('<b>Technique ID</b>', muted_style),
                    Paragraph('<b>Technique Name</b>', muted_style),
                    Paragraph('<b>Tactic</b>', muted_style),
                ]
            ]
            for t in analysis.risk_assessment.mitre_techniques:
                mitre_data.append([
                    Paragraph(f'<b>{t.technique_id}</b>', make_style(f'MitreId_{t.technique_id.replace(".", "_")}',
                        textColor=COLOR_ACCENT, fontSize=8, fontName='Helvetica-Bold', leading=12)),
                    Paragraph(t.technique_name, normal_dark_style),
                    Paragraph(t.tactic, muted_style),
                ])
            mitre_table = Table(mitre_data, colWidths=[1.2*inch, 3.5*inch, 2.7*inch])
            mitre_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLOR_ROW_ALT),
                ('BACKGROUND', (0, 1), (-1, -1), COLOR_CARD),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_CARD, COLOR_ROW_ALT]),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 7),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ]))
            elements.append(mitre_table)
            elements.append(Spacer(1, 14))

        # ==========================================
        # AI ANALYSIS
        # ==========================================
        if analysis.ai_explanation:
            elements.append(Paragraph('AI-Powered Analysis (Groq · Llama 3.3 70B)', section_header_style))
            ai_box_data = [[Paragraph(analysis.ai_explanation.replace('\n', '<br/>'), ai_style)]]
            ai_box = Table(ai_box_data, colWidths=[7.4*inch])
            ai_box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), COLOR_CARD),
                ('TOPPADDING', (0, 0), (-1, -1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('LEFTPADDING', (0, 0), (-1, -1), 14),
                ('RIGHTPADDING', (0, 0), (-1, -1), 14),
                ('LINEABOVE', (0, 0), (-1, 0), 1.5, COLOR_ACCENT),
                ('GRID', (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ]))
            elements.append(ai_box)
            elements.append(Spacer(1, 14))

        # ==========================================
        # ROUTING TIMELINE
        # ==========================================
        if hdr.hops:
            elements.append(Paragraph('Email Routing Timeline', section_header_style))
            timeline_data = [
                [
                    Paragraph('<b>Hop</b>', muted_style),
                    Paragraph('<b>From Server</b>', muted_style),
                    Paragraph('<b>By Server</b>', muted_style),
                    Paragraph('<b>Protocol</b>', muted_style),
                    Paragraph('<b>Timestamp</b>', muted_style),
                ]
            ]
            for hop in hdr.hops:
                timeline_data.append([
                    Paragraph(f'<b>#{hop.hop_number}</b>', make_style(f'HopNum_{hop.hop_number}',
                        textColor=COLOR_ACCENT, fontSize=8, fontName='Helvetica-Bold', leading=12)),
                    Paragraph(hop.from_server[:35] or 'Unknown', muted_style),
                    Paragraph(hop.by_server[:35] or 'Unknown', muted_style),
                    Paragraph(hop.with_protocol or 'SMTP', normal_dark_style),
                    Paragraph(hop.timestamp[:28] or '—', muted_style),
                ])
            timeline_table = Table(timeline_data, colWidths=[0.45*inch, 1.9*inch, 1.9*inch, 1*inch, 2.15*inch])
            timeline_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLOR_ROW_ALT),
                ('BACKGROUND', (0, 1), (-1, -1), COLOR_CARD),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_CARD, COLOR_ROW_ALT]),
                ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.3, COLOR_BORDER),
            ]))
            elements.append(timeline_table)
            elements.append(Spacer(1, 14))

        # ==========================================
        # FOOTER
        # ==========================================
        elements.append(HRFlowable(width='100%', thickness=0.5, color=COLOR_BORDER))
        elements.append(Spacer(1, 6))
        footer_text = (
            f"PhishScope v2.0 — Investigation Report  |  Generated: {formatted_time}  |  "
            f"ID: {analysis.investigation_id}  |  "
            "This report is confidential and intended for authorized security personnel only."
        )
        elements.append(Paragraph(footer_text, footer_style))

        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
