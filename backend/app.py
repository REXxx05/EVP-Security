from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Setting up the database and rate limiter
# These are created here so other files can import them easily
db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address)

def create_app():
    
    app = Flask(
        __name__,
        template_folder='../frontend/templates',
        static_folder='../frontend/static'
    )

    # Load settings from config.py
    app.config.from_object('config.Config')

    # Connect the database and limiter to our app
    db.init_app(app)
    limiter.init_app(app)

    # SR-01: Add security headers to every response the server sends back
    # This is part of the Defence in Depth security pattern
    @app.after_request
    def add_security_headers(response):
        
        # Tells browser to always use HTTPS
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Stops the page being put inside an iframe which prevents clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Stops browser from trying to guess file types
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Only allows content from our own server
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        
        return response

    # SR-08: Simple health check so we can monitor if the system is up
    @app.route('/health')
    def health_check():
        return jsonify({'status': 'ok'}), 200

    # Register the different parts of the API
    from routes.auth import auth_bp
    from routes.ballot import ballot_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(ballot_bp, url_prefix='/api/ballot')

    # Basic error handlers
    # We keep error messages vague on purpose so we dont leak system info
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Not found'}), 404

    @app.errorhandler(429)
    def rate_limit_hit(e):
        return jsonify({'error': 'Too many requests. Please wait and try again.'}), 429

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({'error': 'Something went wrong on our end.'}), 500

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    # Running with debug off for security
    app.run(debug=False, host='127.0.0.1', port=5000)