from app import db

# This model stores submitted ballots
# Voter identity is separated from ballot content (SR-16)

class Ballot(db.Model):
    __tablename__ = 'ballots'

    id = db.Column(db.Integer, primary_key=True)

    # We store a pseudonym instead of real voter id (SR-16)
    voter_pseudonym = db.Column(db.String(255), nullable=False)

    # Ballot preferences encrypted with AES-256 (SR-02)
    preferences_encrypted = db.Column(db.Text, nullable=False)

    division = db.Column(db.String(100), nullable=False)

    # Unique token given to voter as receipt (SR-15)
    receipt_token = db.Column(db.String(255), unique=True, nullable=False)

    submitted_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<Ballot {self.receipt_token}>'


class BallotHash(db.Model):
    __tablename__ = 'ballot_hashes'

    # Stored separately from ballots so tampering is detectable (SR-04)
    id = db.Column(db.Integer, primary_key=True)
    receipt_token = db.Column(db.String(255), unique=True, nullable=False)
    sha256_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<BallotHash {self.receipt_token}>'