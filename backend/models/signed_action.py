# SR-14: stores each signed delegate action, so there is proof of who
# made a change and that it wasn't edited afterwards.

from datetime import datetime, timezone

from extensions import db


def _utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SignedAction(db.Model):
    __tablename__ = "signed_actions"

    id = db.Column(db.Integer, primary_key=True)
    signer_pseudonym = db.Column(db.String(128), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    payload = db.Column(db.Text, nullable=False)  # the exact JSON that got signed
    signature = db.Column(db.String(128), nullable=False)  # Ed25519 signature in hex
    created_at = db.Column(db.DateTime, nullable=False, default=_utc_now)


class CandidateExclusion(db.Model):
    __tablename__ = "candidate_exclusions"

    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, nullable=False, unique=True)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utc_now)