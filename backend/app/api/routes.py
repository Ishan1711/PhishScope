from flask import Blueprint, jsonify, request, current_app, send_file
import os
import time
from werkzeug.utils import secure_filename
from app.services.parser import HeaderParser
from app.services.analyzer import HeaderAnalyzer
from app.services.ai_explainer import AIExplainer
from app.services.report_generator import ReportGenerator
from app.models.analysis import AnalysisResult
from config import ActiveConfig
import io

api_bp = Blueprint('api', __name__)

MAX_TEXT_LENGTH = 200_000  # 200KB of raw header text is more than enough


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ActiveConfig.ALLOWED_EXTENSIONS


def _sanitize_text(raw_text: str) -> str:
    """Basic input sanitization for raw header text."""
    # Remove null bytes
    raw_text = raw_text.replace('\x00', '')
    # Trim to max allowed length
    return raw_text[:MAX_TEXT_LENGTH]


@api_bp.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "PhishScope API",
        "version": "2.0.0",
        "model": ActiveConfig.MODEL_NAME,
        "ai_provider": ActiveConfig.AI_PROVIDER,
        "groq_configured": bool(ActiveConfig.GROQ_API_KEY),
    }), 200


@api_bp.route('/analyze/text', methods=['POST'])
def analyze_text():
    """Accepts raw header text, parses fields, calculates risk, and returns analysis JSON."""
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "Missing 'text' field in JSON payload"}), 400

    raw_text = data['text']
    if not isinstance(raw_text, str):
        return jsonify({"error": "'text' must be a string"}), 400

    raw_text = _sanitize_text(raw_text)
    if not raw_text.strip():
        return jsonify({"error": "Empty text provided"}), 400

    if len(raw_text.strip()) < 20:
        return jsonify({"error": "Input is too short to be a valid email header"}), 400

    try:
        start_time = time.monotonic()

        header = HeaderParser.parse_text(raw_text)
        risk = HeaderAnalyzer.analyze(header)
        analysis = AnalysisResult(header_data=header, risk_assessment=risk)

        explanation = AIExplainer.generate_explanation(analysis)
        analysis.ai_explanation = explanation

        # Record analysis duration
        analysis.analysis_duration_ms = int((time.monotonic() - start_time) * 1000)

        return jsonify(analysis.model_dump()), 200
    except Exception as e:
        current_app.logger.error(f"Error parsing text: {e}", exc_info=True)
        return jsonify({"error": "Failed to analyze text", "details": str(e)}), 500


@api_bp.route('/analyze/file', methods=['POST'])
def analyze_file():
    """Accepts .eml or .txt file uploads, extracts headers, and processes them."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({"error": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed. Must be .txt or .eml"}), 400

    # Validate file size
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    if file_size > ActiveConfig.MAX_CONTENT_LENGTH:
        return jsonify({"error": "File exceeds the 10MB size limit"}), 413
    if file_size == 0:
        return jsonify({"error": "Uploaded file is empty"}), 400

    filepath = None
    try:
        start_time = time.monotonic()
        filename = secure_filename(file.filename)
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        header = HeaderParser.parse_file(filepath)
        risk = HeaderAnalyzer.analyze(header)
        analysis = AnalysisResult(header_data=header, risk_assessment=risk)

        explanation = AIExplainer.generate_explanation(analysis)
        analysis.ai_explanation = explanation

        analysis.analysis_duration_ms = int((time.monotonic() - start_time) * 1000)

        return jsonify(analysis.model_dump()), 200
    except Exception as e:
        current_app.logger.error(f"Error parsing file: {e}", exc_info=True)
        return jsonify({"error": "Failed to analyze file", "details": str(e)}), 500
    finally:
        # Always clean up the uploaded file
        if filepath and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except OSError:
                pass


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
            download_name=f"{analysis.investigation_id}_PhishScope_Report.pdf"
        )
    except Exception as e:
        current_app.logger.error(f"Error generating PDF: {e}", exc_info=True)
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
            download_name=f"{analysis.investigation_id}_PhishScope_Report.json"
        )
    except Exception as e:
        current_app.logger.error(f"Error generating JSON export: {e}", exc_info=True)
        return jsonify({"error": "Failed to generate JSON", "details": str(e)}), 500
