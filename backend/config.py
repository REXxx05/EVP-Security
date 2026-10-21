import os
from datetime import timedelta

# Configuration file for the EVP application
# This file stores all the security settings used across the system

class Config:

    # HTTPS and cookie security - SR-01
    # Makes sure all cookies are only sent over secure connections
    FORCE_HTTPS = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True  # Prevents JavaScript from reading cookies
    SESSION_COOKIE_SAMESITE = 'Strict'  # Stops cross-site request forgery

    # Secret keys for encryption - SR-02
    # These should be set as environment variables in production
    # For development we use placeholder values
    SECRET_KEY = os.environ.get('SECRET_KEY', 'my-secret-key-change-before-production')
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'encryption-key-must-be-32-bytes!!')
    HMAC_KEY = os.environ.get('HMAC_KEY', 'hmac-key-used-for-hashing-voter-pii')

    # Database settings
    # Using SQLite for this prototype as it is simple to set up
    # A real deployment would use PostgreSQL
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(
        BASE_DIR, '../database/evp.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT token settings used for voter sessions
    # Tokens expire after 30 minutes as required by SR-17
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_ALGORITHM = 'HS256'

    # Rate limiting settings to help prevent DDoS attacks - SR-09
    # Limits each IP address to 100 requests per minute
    RATELIMIT_DEFAULT = '100 per minute'
    RATELIMIT_STORAGE_URL = 'memory://'

    # Admin MFA settings using TOTP - SR-10
    # TOTP generates a new code every 30 seconds
    TOTP_ISSUER = 'EVP-Admin-Portal'
    TOTP_INTERVAL = 30

    # Health check interval in seconds - SR-08
    # System checks every 30 seconds to make sure everything is running
    HEALTH_CHECK_INTERVAL = 30