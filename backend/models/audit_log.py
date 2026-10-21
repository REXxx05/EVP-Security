from sqlalchemy import DDL, event

from extensions import db


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)  # saved as UTC
    # only the pseudonym goes here, never the real voter id (SR-18)
    actor_pseudonym = db.Column(db.String(128), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text, nullable=False, default="")
    prev_hash = db.Column(db.String(64), nullable=False)  # hash of the row before
    entry_hash = db.Column(db.String(64), nullable=False, unique=True)
    retain_until = db.Column(db.DateTime, nullable=False)  # SR-12: keep for 7 years


# Database triggers (SQLite): nobody can UPDATE a row, and nobody can DELETE
# a row until its 7 years are up. The hash chain is the backup if someone
# gets round these.
_NO_UPDATE = DDL(
    "CREATE TRIGGER IF NOT EXISTS audit_log_no_update "
    "BEFORE UPDATE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;"
)
_NO_EARLY_DELETE = DDL(
    "CREATE TRIGGER IF NOT EXISTS audit_log_no_delete "
    "BEFORE DELETE ON audit_log "
    "WHEN OLD.retain_until > datetime('now') "
    "BEGIN SELECT RAISE(ABORT, 'audit_log rows are kept for 7 years'); END;"
)

# these run right after the table is created
event.listen(AuditLog.__table__, "after_create", _NO_UPDATE.execute_if(dialect="sqlite"))
event.listen(
    AuditLog.__table__, "after_create", _NO_EARLY_DELETE.execute_if(dialect="sqlite")
)