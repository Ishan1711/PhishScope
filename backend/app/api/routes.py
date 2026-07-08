from flask import Blueprint, jsonify, request, current_app, send_file
import os
from werkzeug.utils import secure_filename
from app.services.parser import HeaderParser
from app.services.analyzer import HeaderAnalyzer
from app.services.ai_explainer import AIExplainer
from app.services.report_generator import ReportGenerator
from app.models.analysis import AnalysisResult
from config import ActiveConfig
import io

api_bp = Blueprint('api', __name__)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ActiveConfig.ALLOWED_EXTENSIONS

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "PhishScope API",
        "version": "1.0.0"
    }), 200

@api_bp.route('/analyze/text', methods=['POST'])
def analyze_text():
    """Accepts raw header text, parses fields, calculates risk, and returns analysis JSON."""
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "Missing 'text' field in JSON payload"}), 400
        
    raw_text = data['text']
    if not raw_text.strip():
        return jsonify({"error": "Empty text provided"}), 400

    try:
        header = HeaderParser.parse_text(raw_text)
        risk = HeaderAnalyzer.analyze(header)
        analysis = AnalysisResult(header_data=header, risk_assessment=risk)
        
        # Async-like or synchronous AI call (keeping sync for MVP)
        explanation = AIExplainer.generate_explanation(analysis)
        analysis.ai_explanation = explanation
        
        return jsonify(analysis.model_dump()), 200
    except Exception as e:
        current_app.logger.error(f"Error parsing text: {e}")
        return jsonify({"error": "Failed to analyze text", "details": str(e)}), 500

@api_bp.route('/analyze/file', methods=['POST'])
def analyze_file():
    """Accepts .eml or .txt file uploads, extracts headers, and processes them."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed. Must be .txt or .eml"}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        header = HeaderParser.parse_file(filepath)
        risk = HeaderAnalyzer.analyze(header)
        analysis = AnalysisResult(header_data=header, risk_assessment=risk)
        
        explanation = AIExplainer.generate_explanation(analysis)
        analysis.ai_explanation = explanation
        
        # Cleanup file after processing
        os.remove(filepath)
        
        return jsonify(analysis.model_dump()), 200
    except Exception as e:
        current_app.logger.error(f"Error parsing file: {e}")
        return jsonify({"error": "Failed to analyze file", "details": str(e)}), 500

@api_bp.route('/export/pdf', methods=['POST'])
def export_pdf():
    """Accepts analysis JSON payload and returns a professional PDF report."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400
        
    try:
        analysis = AnalysisResult(**data)
        pdf_bytes = ReportGenerator.generate_pdf(analysis)
        
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"{analysis.investigation_id}_Report.pdf"
        )
    except Exception as e:
        current_app.logger.error(f"Error generating PDF: {e}")
        return jsonify({"error": "Failed to generate PDF", "details": str(e)}), 500

@api_bp.route('/export/json', methods=['POST'])
def export_json():
    """Accepts analysis JSON payload and returns a formatted JSON report for download."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400
        
    try:
        analysis = AnalysisResult(**data)
        json_str = ReportGenerator.generate_json(analysis)
        
        return send_file(
            io.BytesIO(json_str.encode('utf-8')),
            mimetype='application/json',
            as_attachment=True,
            download_name=f"{analysis.investigation_id}_Report.json"
        )
    except Exception as e:
        current_app.logger.error(f"Error generating JSON export: {e}")
        return jsonify({"error": "Failed to generate JSON", "details": str(e)}), 500

