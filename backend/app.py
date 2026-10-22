from flask import Flask, jsonify, render_template
from extensions import db, limiter

# This is the main Flask application factory
# We use a factory function so the app can be created with different configs

def create_app():
    app = Flask(
        __name__,
        template_folder='../frontend/templates',
        static_folder='../frontend/static'
    )

    # Load all settings from config.py
    app.config.from_object('config.Config')

    # Connect database and rate limiter to the app
    db.init_app(app)
    limiter.init_app(app)

    # SR-01: Add security headers to every response
    # This is the Defence in Depth pattern - security at every layer
    @app.after_request
    def add_security_headers(response):
        # Force browser to use HTTPS only
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        # Prevent clickjacking by blocking iframes
        response.headers['X-Frame-Options'] = 'DENY'
        # Prevent browser from guessing content types
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Allow inline scripts and styles for prototype
        # In production this would be stricter
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        return response

    # SR-08: Health check endpoint for monitoring
    @app.route('/health')
    def health_check():
        return jsonify({'status': 'ok'}), 200

    # Frontend page routes
    @app.route('/')
    def index():
        return render_template('login.html')

    @app.route('/ballot')
    def ballot():
        return render_template('ballot.html')

    # Register API blueprints
    from routes.auth import auth_bp
    from routes.ballot import ballot_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    from routes.admin import admin_bp  
    app.register_blueprint(ballot_bp, url_prefix='/api/ballot')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')

    # Error handlers - we keep messages vague so we dont leak system details
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
        # Import all models so SQLAlchemy knows about them before creating tables
        from models.voter import Voter
        from models.admin_user import AdminUser
        from models.ballot import Ballot, BallotHash
        from models.candidate import Candidate
        from models.audit_log import AuditLog
        from models.revoked_token import RevokedToken
        from models.signed_action import SignedAction, CandidateExclusion
        db.create_all()
    app.run(debug=False, host='127.0.0.1', port=5000)