from extensions import db

# Stores tokens that have been revoked before their expiry time
# SR-17: Allows immediate token invalidation after ballot submission or logout

class RevokedToken(db.Model):
    __tablename__ = 'revoked_tokens'

    id = db.Column(db.Integer, primary_key=True)
    # We store a hash of the token, not the token itself
    token_hash = db.Column(db.String(255), unique=True, nullable=False)
    revoked_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<RevokedToken {self.token_hash}>'