import bcrypt
import jwt
import pyotp
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, current_app
from middleware.authenticate import token_required

# Auth routes handle voter and admin login
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/voter/login', methods=['POST'])
def voter_login():
    # Voter login - checks credentials and returns a session token
    # SR-07: also checks if voter is enrolled before giving access

    from app import db
    from models.voter import Voter

    data = request.get_json()

    # Make sure all required fields are provided
    if not data or not data.get('voter_id') or not data.get('password'):
        return jsonify({'error': 'Please enter your voter ID and password'}), 400

    voter_id = data.get('voter_id').strip()
    password = data.get('password').strip()

    # Find the voter in the database
    voter = Voter.query.filter_by(voter_id=voter_id).first()

    # Check if voter exists and password is correct
    # bcrypt handles the password comparison securely
    if not voter or not bcrypt.checkpw(password.encode(), voter.password_hash.encode()):
        return jsonify({'error': 'Incorrect voter ID or password'}), 401

    # SR-07: Make sure voter is enrolled and eligible
    if not voter.is_enrolled:
        return jsonify({'error': 'You are not enrolled to vote in this election'}), 403

    # SR-17: Create a JWT token that expires after 30 minutes
    token = jwt.encode({
        'voter_id': voter.voter_id,
        'division': voter.division,
        'role': 'voter',
        'exp': datetime.now(timezone.utc) + timedelta(minutes=30)
    },
        current_app.config['SECRET_KEY'],
        algorithm=current_app.config['JWT_ALGORITHM']
    )

    return jsonify({
        'message': 'Login successful',
        'token': token
    }), 200


@auth_bp.route('/voter/logout', methods=['POST'])
@token_required
def voter_logout():
    # Logs the voter out
    # We tell the client to delete their token
    # In production we would also blacklist the token server side
    return jsonify({'message': 'You have been logged out successfully'}), 200


@auth_bp.route('/admin/login', methods=['POST'])
def admin_login():
    # Admin login requires username, password AND a TOTP code
    # SR-10: Two factor authentication for all admin accounts

    from app import db
    from models.admin_user import AdminUser

    data = request.get_json()

    # All three fields are required for admin login
    if not data or not data.get('username') or not data.get('password') or not data.get('totp_code'):
        return jsonify({'error': 'Username, password and MFA code are all required'}), 400

    username = data.get('username').strip()
    password = data.get('password').strip()
    totp_code = data.get('totp_code').strip()

    # Find the admin in the database
    admin = AdminUser.query.filter_by(username=username).first()

    # Check username and password first
    if not admin or not bcrypt.checkpw(password.encode(), admin.password_hash.encode()):
        return jsonify({'error': 'Incorrect username or password'}), 401

    # SR-10: Verify the six digit TOTP code from the authenticator app
    totp = pyotp.TOTP(admin.totp_secret)
    if not totp.verify(totp_code):
        return jsonify({'error': 'Incorrect MFA code. Please try again.'}), 401

    # Create admin session token
    token = jwt.encode({
        'admin_id': admin.id,
        'username': admin.username,
        'role': admin.role,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=30)
    },
        current_app.config['SECRET_KEY'],
        algorithm=current_app.config['JWT_ALGORITHM']
    )

    return jsonify({
        'message': 'Admin login successful',
        'token': token
    }), 200