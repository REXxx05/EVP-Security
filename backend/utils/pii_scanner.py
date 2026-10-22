# SR-18: automated scanner that checks the audit log for raw voter personal info.

# Run it from the backend folder:
#       python -m utils.pii_scanner
# It prints PASS or FAIL and exits with code 1 on FAIL, so a scheduled job
# can pick up the result.
import re
import sys

from extensions import db
from models.audit_log import AuditLog
from models.voter import Voter

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Australian mobiles, like 0412 345 678 or +61 412 345 678
PHONE_RE = re.compile(r"(?<!\d)(?:\+?61|0)4\d{2}[ -]?\d{3}[ -]?\d{3}(?!\d)")

# voter fields that count as personal info. a field the model doesn't have is skipped
PII_FIELDS = ("voter_id", "email", "name", "full_name", "first_name", "last_name")

# ignore very short values, otherwise we'd get silly false alarms
MIN_LENGTH = 4


def _raw_pii_values():
    # collects the real personal details of every voter
    values = set()
    for voter in Voter.query.all():
        for field in PII_FIELDS:
            value = getattr(voter, field, None)
            if isinstance(value, str) and len(value) >= MIN_LENGTH:
                values.add(value)
    return values


def _finding(row, field, kind):
    # note: we deliberately do NOT include the PII we found, otherwise
    # the scan report would become a place where PII leaks
    return {"row_id": row.id, "field": field, "problem": kind}


def scan_audit_log():
    raw_values = _raw_pii_values()

    # one regex that matches any of the real values, so each row is checked in one pass
    raw_re = None
    if raw_values:
        raw_re = re.compile("|".join(re.escape(v) for v in raw_values), re.IGNORECASE)
    raw_lower = {v.lower() for v in raw_values}

    findings = []
    rows = AuditLog.query.order_by(AuditLog.id).all()

    for row in rows:
        # the actor column must only ever hold a pseudonym, never a real value
        if row.actor_pseudonym.lower() in raw_lower:
            findings.append(_finding(row, "actor_pseudonym", "raw voter detail"))

        for field in ("actor_pseudonym", "action", "details"):
            text = getattr(row, field) or ""

            if field != "actor_pseudonym" and raw_re and raw_re.search(text):
                findings.append(_finding(row, field, "raw voter detail"))
            if EMAIL_RE.search(text):
                findings.append(_finding(row, field, "email address"))
            if PHONE_RE.search(text):
                findings.append(_finding(row, field, "phone number"))

    return {"rows_scanned": len(rows), "findings": findings, "passed": not findings}


def main():
    # CHECK: this assumes backend/app.py has a variable called "app"
    from app import app

    with app.app_context():
        result = scan_audit_log()

    print(f"Rows scanned: {result['rows_scanned']}")
    if result["passed"]:
        print("PASS: no raw voter PII found in the audit log")
        return 0

    print(f"FAIL: {len(result['findings'])} problem(s) found")
    for f in result["findings"]:
        print(f"  row {f['row_id']}, field {f['field']}: {f['problem']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())