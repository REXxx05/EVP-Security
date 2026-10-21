from extensions import db

# This model represents a registered voter
# Sensitive fields are stored encrypted (SR-02)

class Voter(db.Model):
    __tablename__ = 'voters'

    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.String(20), unique=True, nullable=False)

    # Password stored as bcrypt hash, never plaintext
    password_hash = db.Column(db.String(255), nullable=False)

    # Name and email encrypted with AES-256 before storing (SR-02)
    name_encrypted = db.Column(db.String(500), nullable=False)
    email_encrypted = db.Column(db.String(500), nullable=False)

    division = db.Column(db.String(100), nullable=False)

    # Prevents double voting (SR-07)
    has_voted = db.Column(db.Boolean, default=False)

    # Checks voter is enrolled and eligible (SR-07)
    is_enrolled = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<Voter {self.voter_id}>'