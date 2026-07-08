import io
import json
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from app.models.analysis import AnalysisResult

class ReportGenerator:
    """Service for exporting analysis results to JSON and PDF formats."""
    
    @staticmethod
    def generate_json(analysis: AnalysisResult) -> str:
        """Serializes the AnalysisResult model to a JSON string."""
        return analysis.model_dump_json(indent=2)
        
    @staticmethod
    def generate_pdf(analysis: AnalysisResult) -> bytes:
        """Generates a professional PDF report from the AnalysisResult in memory."""
        buffer = io.BytesIO()
        
        # Setup document
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=letter,
            rightMargin=40, leftMargin=40,
            topMargin=40, bottomMargin=40
        )
        
        styles = getSampleStyleSheet()
        title_style = styles['Title']
        h2_style = styles['Heading2']
        normal_style = styles['Normal']
        
        # Custom styles for the report
        custom_h2 = ParagraphStyle(
            'CustomH2',
            parent=h2_style,
            textColor=colors.HexColor("#1A202C"),
            spaceAfter=12
        )
        
        elements = []
        
        # --- TITLE ---
        elements.append(Paragraph("PhishScope Investigation Report", title_style))
        elements.append(Spacer(1, 20))
        
        # --- METADATA ---
        metadata_data = [
            ["Investigation ID:", analysis.investigation_id],
            ["Analysis Date:", analysis.analysis_time],
            ["Threat Level:", analysis.risk_assessment.threat_level],
            ["Threat Score:", f"{analysis.risk_assessment.threat_score}/100"],
            ["Confidence Score:", f"{analysis.risk_assessment.confidence_score}/100"]
        ]
        
        # Determine color for Threat Level
        threat_color = colors.green
        if analysis.risk_assessment.threat_level == "SUSPICIOUS":
            threat_color = colors.orange
        elif analysis.risk_assessment.threat_level == "HIGHLY SUSPICIOUS":
            threat_color = colors.red
            
        t_meta = Table(metadata_data, colWidths=[150, 350])
        t_meta.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F7FAFC")),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor("#2D3748")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ('TEXTCOLOR', (1,2), (1,2), threat_color), # Color code threat level
            ('FONTNAME', (1,2), (1,2), 'Helvetica-Bold')
        ]))
        elements.append(t_meta)
        elements.append(Spacer(1, 20))
        
        # --- AI EXPLANATION ---
        if analysis.ai_explanation:
            elements.append(Paragraph("AI Executive Summary", custom_h2))
            elements.append(Paragraph(analysis.ai_explanation, normal_style))
            elements.append(Spacer(1, 20))
            
        # --- INDICATORS ---
        elements.append(Paragraph("Identified Indicators", custom_h2))
        if analysis.risk_assessment.indicators:
            indicator_data = [["Indicator", "Severity", "Description"]]
            for ind in analysis.risk_assessment.indicators:
                indicator_data.append([ind.name, ind.severity, ind.description])
                
            t_ind = Table(indicator_data, colWidths=[130, 70, 300])
            t_ind.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2D3748")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
            ]))
            elements.append(t_ind)
        else:
            elements.append(Paragraph("No significant phishing indicators found.", normal_style))
        elements.append(Spacer(1, 20))
        
        # --- BASIC FIELDS ---
        elements.append(Paragraph("Email Details", custom_h2))
        header = analysis.header_data
        details_data = [
            ["Subject:", header.subject],
            ["From:", header.from_address],
            ["To:", header.to_address],
            ["Date:", header.date],
            ["Message-ID:", header.message_id],
            ["Originating IP:", header.originating_ip or "N/A"]
        ]
        t_det = Table(details_data, colWidths=[100, 400])
        t_det.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('LINEBELOW', (0,0), (-1,-1), 0.25, colors.HexColor("#E2E8F0")),
        ]))
        elements.append(t_det)
        
        # Build the PDF
        doc.build(elements)
        
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        return pdf_bytes
