from app import db

# This model represents an admin user who manages the system
# SR-10: Admin accounts require TOTP MFA to log in
# SR-11: Each admin has a role that limits what they can do

class AdminUser(db.Model):
    __tablename__ = 'admin_users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)

    # Password stored as bcrypt hash, never plaintext
    password_hash = db.Column(db.String(255), nullable=False)

    # Role controls what this admin can access (SR-11)
    # Options are: aec_staff, commissioner_delegate, admin
    role = db.Column(db.String(50), nullable=False)

    # Secret key used to generate TOTP codes for MFA (SR-10)
    totp_secret = db.Column(db.String(255), nullable=False)

    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<AdminUser {self.username}>'