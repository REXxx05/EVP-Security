from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import jsonify

# This file sets up rate limiting to protect against DDoS attacks
# SR-09: Limits how many requests one IP address can make per minute

# These limits apply to specific sensitive routes
# The default limit is set in config.py

# Strict limit for login attempts to prevent brute force attacks
LOGIN_LIMIT = '10 per minute'

# Limit for ballot submission to prevent spam
BALLOT_LIMIT = '5 per minute'

# Limit for general API endpoints
API_LIMIT = '100 per minute'


def get_rate_limit_response():
    # Custom message when someone hits the rate limit
    return jsonify({
        'error': 'Too many requests. Please wait a moment and try again.'
    }), 429