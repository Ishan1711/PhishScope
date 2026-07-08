import logging
import os
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify
from flask_cors import CORS
from config import ActiveConfig

def create_app(config_class=ActiveConfig):
    """Application factory for the Flask backend."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Ensure necessary directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['LOG_DIR'], exist_ok=True)
    
    # Configure Logging
    _configure_logging(app)
    
    # Register Blueprints
    from app.api.routes import api_bp
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    # Global error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        app.logger.warning(f"404 Not Found: {error}")
        return jsonify({"error": "Resource not found", "details": str(error)}), 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"500 Internal Error: {error}")
        return jsonify({"error": "Internal server error", "details": str(error)}), 500

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({"error": "File too large", "details": "The uploaded file exceeds the 10MB limit."}), 413

    app.logger.info('PhishScope startup completed successfully.')
    return app

def _configure_logging(app):
    """Sets up logging to file and console."""
    log_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )
    
    # File handler
    file_handler = RotatingFileHandler(
        app.config['LOG_FILE'], 
        maxBytes=1024000, # 1 MB
        backupCount=10
    )
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.INFO)
    
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)
