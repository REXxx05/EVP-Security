# Tests for SR-12 (logging + 7 year retention) and SR-13 (tamper-evident chain).
import os
import sys
from datetime import timedelta

# lets the tests find the backend folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from flask import Flask
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from extensions import db
from middleware import audit_logger
from models.audit_log import AuditLog


@pytest.fixture
def app():
    # a throwaway app with an in-memory database, so tests never touch real data
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _add_entries(n=3):
    for i in range(n):
        audit_logger.log_action(f"VOTER{i:03d}", f"ACTION_{i}", f"detail {i}")


def test_chain_is_valid_after_normal_use(app):
    _add_entries(4)
    assert audit_logger.verify_chain() == (True, None)


def test_first_entry_links_to_genesis(app):
    _add_entries(1)
    assert AuditLog.query.first().prev_hash == audit_logger.GENESIS_HASH


def test_each_entry_links_to_previous(app):
    _add_entries(3)
    rows = AuditLog.query.order_by(AuditLog.id).all()
    assert rows[1].prev_hash == rows[0].entry_hash
    assert rows[2].prev_hash == rows[1].entry_hash


def test_update_is_blocked_by_database_trigger(app):
    _add_entries(1)
    row = AuditLog.query.first()
    row.details = "tampered"
    # the trigger should refuse this
    with pytest.raises(DBAPIError):
        db.session.commit()
    db.session.rollback()


def test_early_delete_is_blocked_by_database_trigger(app):
    _add_entries(1)
    db.session.delete(AuditLog.query.first())
    with pytest.raises(DBAPIError):
        db.session.commit()
    db.session.rollback()


def test_modified_row_is_detected_by_chain(app):
    _add_entries(3)
    # pretend an insider switched off the trigger, then edited a row
    db.session.execute(text("DROP TRIGGER audit_log_no_update"))
    db.session.execute(text("UPDATE audit_log SET details='tampered' WHERE id=2"))
    db.session.commit()
    # the chain should still catch it at row 2
    assert audit_logger.verify_chain() == (False, 2)


def test_deleted_row_is_detected_by_chain(app):
    _add_entries(3)
    db.session.execute(text("DROP TRIGGER audit_log_no_delete"))
    db.session.execute(text("DELETE FROM audit_log WHERE id=2"))
    db.session.commit()
    ok, bad_id = audit_logger.verify_chain()
    # row 3 no longer links to anything, so that's where it breaks
    assert ok is False and bad_id == 3


def test_retention_is_at_least_seven_years(app):
    _add_entries(1)
    row = AuditLog.query.first()
    assert row.retain_until - row.timestamp >= timedelta(days=365 * 7)


def test_actor_is_pseudonym_not_raw_id(app):
    audit_logger.log_action("VOTER001", "LOGIN", "")
    row = AuditLog.query.first()
    assert "VOTER001" not in row.actor_pseudonym


def test_export_returns_all_entries(app):
    _add_entries(3)
    assert len(audit_logger.export_entries()) == 3


def test_log_without_commit_rolls_back_with_caller(app):
    # if the caller's transaction is rolled back, the log entry goes too
    audit_logger.log_action("VOTER001", "ACTION", "", commit=False)
    db.session.rollback()
    assert AuditLog.query.count() == 0