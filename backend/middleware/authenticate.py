import jwt
from functools import wraps
from flask import request, jsonify, current_app
from datetime import datetime, timezone

# This file checks if a user is logged in before they can access protected routes
# SR-03: Makes sure each voter session is isolated
# SR-17: Checks that the session token has not expired

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        # Look for the token in the request header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'error': 'You need to be logged in to do this'}), 401

        try:
            # Decode the token using our secret key
            data = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=[current_app.config['JWT_ALGORITHM']]
            )

            # Attach the user data to the request so routes can use it
            request.current_user = data

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Your session has expired. Please log in again.'}), 401

        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid session token. Please log in again.'}), 401

        return f(*args, **kwargs)

    return decorated