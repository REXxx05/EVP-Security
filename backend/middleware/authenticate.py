import jwt
import hashlib
from functools import wraps
from flask import request, jsonify, current_app
from datetime import datetime, timezone

# Handles JWT token verification for all protected routes
# SR-03: Session isolation
# SR-17: Token expiry and immediate revocation after ballot submission

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'error': 'You need to be logged in to do this'}), 401

        try:
            data = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=[current_app.config['JWT_ALGORITHM']]
            )

            # SR-17: Check if this token has been revoked
            # This handles immediate expiry after ballot submission or logout
            from models.revoked_token import RevokedToken
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if RevokedToken.query.filter_by(token_hash=token_hash).first():
                return jsonify({'error': 'Your session has ended. Please log in again.'}), 401

            # Store token hash on request so routes can revoke it
            request.current_user = data
            request.token_hash = token_hash

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Your session has expired. Please log in again.'}), 401

        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid session token. Please log in again.'}), 401

        return f(*args, **kwargs)

    return decorated


def revoke_token(token_hash):
    # Immediately invalidates a token by storing its hash
    # SR-17: Called after ballot submission and logout
    from extensions import db
    from models.revoked_token import RevokedToken
    revoked = RevokedToken(token_hash=token_hash)
    db.session.add(revoked)
    db.session.commit()