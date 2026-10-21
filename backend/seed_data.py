import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import bcrypt
import pyotp
from app import create_app, db
from models.voter import Voter
from models.admin_user import AdminUser
from models.candidate import Candidate
from utils.crypto import encrypt_data

# This script adds test data to the database so we can demo the system
# Run it once with: python seed_data.py

def seed():
    app = create_app()
    
    with app.app_context():
        # Create all tables first
        db.create_all()
        
        # Clear existing data
        db.session.query(Voter).delete()
        db.session.query(AdminUser).delete()
        db.session.query(Candidate).delete()
        db.session.commit()

        # Add test voters
        voters = [
            {
                'voter_id': 'VOTER001',
                'password': 'password123',
                'name': 'John Smith',
                'email': 'john@example.com',
                'division': 'Melbourne'
            },
            {
                'voter_id': 'VOTER002',
                'password': 'password123',
                'name': 'Jane Doe',
                'email': 'jane@example.com',
                'division': 'Melbourne'
            }
        ]

        for v in voters:
            password_hash = bcrypt.hashpw(
                v['password'].encode(),
                bcrypt.gensalt()
            ).decode()

            voter = Voter(
                voter_id=v['voter_id'],
                password_hash=password_hash,
                name_encrypted=encrypt_data(v['name']),
                email_encrypted=encrypt_data(v['email']),
                division=v['division'],
                has_voted=False,
                is_enrolled=True
            )
            db.session.add(voter)

        # Add test admin
        admin_password = bcrypt.hashpw(
            'admin123'.encode(),
            bcrypt.gensalt()
        ).decode()

        # Generate a TOTP secret for the admin
        totp_secret = pyotp.random_base32()

        admin = AdminUser(
            username='admin',
            password_hash=admin_password,
            role='admin',
            totp_secret=totp_secret
        )
        db.session.add(admin)

        # Add candidates for Melbourne division
        candidates = [
            {'name': 'Jane Smith', 'party': 'Australian Labor Party', 'ballot_position': 1},
            {'name': 'John Brown', 'party': 'Liberal Party of Australia', 'ballot_position': 2},
            {'name': 'Sarah Lee', 'party': 'Australian Greens', 'ballot_position': 3},
            {'name': 'Mike Davis', 'party': 'Independent', 'ballot_position': 4}
        ]

        for c in candidates:
            candidate = Candidate(
                name=c['name'],
                party=c['party'],
                division='Melbourne',
                ballot_position=c['ballot_position']
            )
            db.session.add(candidate)

        db.session.commit()

        print('Test data added successfully')
        print('Voter logins:')
        print('  Voter ID: VOTER001  Password: password123')
        print('  Voter ID: VOTER002  Password: password123')
        print('Admin login:')
        print('  Username: admin  Password: admin123')
        print(f'  TOTP Secret: {totp_secret}')
        print('  Use Google Authenticator or Authy to scan the TOTP secret')

if __name__ == '__main__':
    seed()