from app import db

# This model represents a registered voter in the system
# Sensitive fields like name and email are stored encrypted (SR-02)

class Voter(db.Model):
    __tablename__ = 'voters'

    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # These fields are encrypted with AES-256 before storing (SR-02)
    name_encrypted = db.Column(db.String(500), nullable=False)
    email_encrypted = db.Column(db.String(500), nullable=False)

    division = db.Column(db.String(100), nullable=False)

    # Tracks if voter has already voted to prevent double voting (SR-07)
    has_voted = db.Column(db.Boolean, default=False)

    # Tracks if voter is enrolled and eligible to vote (SR-07)
    is_enrolled = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<Voter {self.voter_id}>'