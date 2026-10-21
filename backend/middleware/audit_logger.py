import hashlib
from datetime import datetime, timedelta, timezone

from extensions import db
from models.audit_log import AuditLog
from utils.crypto import pseudonymise_voter

# the very first row has nothing before it, so it points at this
GENESIS_HASH = "0" * 64

# 7 years plus 2 days so leap years can't make it come up short
RETENTION = timedelta(days=365 * 7 + 2)


def _utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def compute_hash(prev_hash, timestamp, actor, action, details, retain_until):
    # join everything in the row (plus the previous hash) and hash it,
    # so changing any one field changes the hash
    raw = "|".join(
        [prev_hash, timestamp.isoformat(), actor, action, details, retain_until.isoformat()]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def log_action(voter_id, action, details="", commit=True):
    # the real id never gets stored, only the pseudonym
    actor = pseudonymise_voter(voter_id) if voter_id is not None else "anonymous"

    # find the last row so we can link the new one to it
    last = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev_hash = last.entry_hash if last else GENESIS_HASH

    timestamp = _utc_now()
    retain_until = timestamp + RETENTION

    entry = AuditLog(
        timestamp=timestamp,
        actor_pseudonym=actor,
        action=action,
        details=details,
        prev_hash=prev_hash,
        entry_hash=compute_hash(prev_hash, timestamp, actor, action, details, retain_until),
        retain_until=retain_until,
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    else:
        db.session.flush()  # gets it into the transaction without saving yet
    return entry


def verify_chain():
    # walk through every row in order and recheck the hashes.
    # returns (True, None) if all good, or (False, id) of the first bad row
    prev = GENESIS_HASH
    for row in AuditLog.query.order_by(AuditLog.id).all():
        expected = compute_hash(
            prev, row.timestamp, row.actor_pseudonym, row.action, row.details, row.retain_until
        )
        if row.prev_hash != prev or row.entry_hash != expected:
            return False, row.id
        prev = row.entry_hash
    return True, None


def export_entries():
    # everything as plain dicts, so an auditor can download it (SR-13: within 24 hours)
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat() + "Z",
            "actor": r.actor_pseudonym,
            "action": r.action,
            "details": r.details,
            "prev_hash": r.prev_hash,
            "hash": r.entry_hash,
            "retain_until": r.retain_until.isoformat() + "Z",
        }
        for r in AuditLog.query.order_by(AuditLog.id).all()
    ]