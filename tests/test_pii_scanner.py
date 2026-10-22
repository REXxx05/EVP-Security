# Tests for SR-18 (the automated PII scanner).
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from flask import Flask

from extensions import db
from middleware import audit_logger
from models.audit_log import AuditLog
from utils import pii_scanner


@pytest.fixture
def app():
    # throwaway app with an in-memory database, so tests never touch real data
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture(autouse=True)
def fake_voters(monkeypatch):
    # pretend these are the real voters, so the tests don't depend on the Voter table
    monkeypatch.setattr(
        pii_scanner,
        "_raw_pii_values",
        lambda: {"VOTER001", "jane@example.com", "Jane Citizen"},
    )


def test_empty_log_passes(app):
    result = pii_scanner.scan_audit_log()
    assert result["passed"] is True
    assert result["rows_scanned"] == 0


def test_normal_entries_pass(app):
    # log_action turns the voter id into a pseudonym, so this should be clean
    for i in range(20):
        audit_logger.log_action(f"VOTER{i:03d}", "LOGIN", "ok")
    result = pii_scanner.scan_audit_log()
    assert result["passed"] is True
    assert result["rows_scanned"] == 20


def test_raw_voter_id_in_details_is_flagged(app):
    audit_logger.log_action("VOTER002", "LOGIN", "voter VOTER001 logged in")
    result = pii_scanner.scan_audit_log()
    assert result["passed"] is False
    assert result["findings"][0]["field"] == "details"


def test_match_ignores_capital_letters(app):
    audit_logger.log_action("VOTER002", "LOGIN", "jane citizen voted")
    assert pii_scanner.scan_audit_log()["passed"] is False


def test_email_address_is_flagged(app):
    audit_logger.log_action("VOTER002", "LOGIN", "contact someone.else@mail.com")
    result = pii_scanner.scan_audit_log()
    assert result["findings"][0]["problem"] == "email address"


def test_phone_number_is_flagged(app):
    audit_logger.log_action("VOTER002", "LOGIN", "called 0412 345 678")
    result = pii_scanner.scan_audit_log()
    assert result["findings"][0]["problem"] == "phone number"


def test_raw_actor_is_flagged(app):
    # add a row by hand where someone forgot to pseudonymise the actor
    now = datetime(2026, 1, 1)
    db.session.add(
        AuditLog(
            timestamp=now,
            actor_pseudonym="VOTER001",
            action="LOGIN",
            details="",
            prev_hash="0" * 64,
            entry_hash="a" * 64,
            retain_until=now + timedelta(days=3000),
        )
    )
    db.session.commit()
    result = pii_scanner.scan_audit_log()
    assert result["passed"] is False
    assert result["findings"][0]["field"] == "actor_pseudonym"


def test_report_never_contains_the_pii_it_found(app):
    audit_logger.log_action("VOTER002", "LOGIN", "voter VOTER001 logged in")
    result = pii_scanner.scan_audit_log()
    assert "VOTER001" not in str(result)