from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    # Determine the port from the environment or default to 5000
    port = int(os.environ.get('PORT', 5000))
    # Run the application
    app.run(host='0.0.0.0', port=port, debug=app.config.get('DEBUG', True))
