# Tests for SR-11 (role-based access control).
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from flask import Flask, request

from extensions import db
from middleware import rbac
from models.audit_log import AuditLog


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _as(app, user):
    # fakes a logged-in request with the given user, like the real token would
    ctx = app.test_request_context("/api/admin/candidates", method="POST")
    ctx.push()
    request.current_user = user
    return ctx


def test_admin_is_allowed(app):
    ctx = _as(app, {"voter_id": "A1", "role": rbac.ROLE_ADMIN})
    try:
        assert rbac._check((rbac.ROLE_ADMIN,)) is None
        assert AuditLog.query.count() == 0  # nothing to log when allowed
    finally:
        ctx.pop()


def test_voter_is_denied_with_403(app):
    ctx = _as(app, {"voter_id": "V1", "role": "voter"})
    try:
        response, status = rbac._check((rbac.ROLE_ADMIN,))
        assert status == 403
    finally:
        ctx.pop()


def test_denial_is_logged(app):
    ctx = _as(app, {"voter_id": "V1", "role": "voter"})
    try:
        rbac._check((rbac.ROLE_ADMIN,))
        row = AuditLog.query.first()
        assert row.action == "ACCESS_DENIED"
        assert "V1" not in row.actor_pseudonym  # pseudonym only, not the real id
    finally:
        ctx.pop()


def test_missing_user_is_denied(app):
    ctx = app.test_request_context("/api/admin/candidates")
    ctx.push()
    try:
        _, status = rbac._check((rbac.ROLE_ADMIN,))
        assert status == 403
    finally:
        ctx.pop()


def test_missing_role_is_denied(app):
    ctx = _as(app, {"voter_id": "X1"})
    try:
        _, status = rbac._check((rbac.ROLE_ADMIN,))
        assert status == 403
    finally:
        ctx.pop()


def test_auditor_cannot_use_admin_only_route(app):
    ctx = _as(app, {"voter_id": "AU1", "role": rbac.ROLE_AUDITOR})
    try:
        _, status = rbac._check((rbac.ROLE_ADMIN,))
        assert status == 403
    finally:
        ctx.pop()


def test_denial_completes_within_one_second(app):
    # the requirement says block and log within 1 second
    ctx = _as(app, {"voter_id": "V1", "role": "voter"})
    try:
        start = time.perf_counter()
        rbac._check((rbac.ROLE_ADMIN,))
        assert time.perf_counter() - start < 1.0
    finally:
        ctx.pop()


#appended code segment   

def test_admin_id_is_used_when_there_is_no_voter_id(app):
    # admin tokens carry admin_id, not voter_id. the log must still say who it was
    ctx = _as(app, {"admin_id": 7, "role": "voter"})
    try:
        rbac._check((rbac.ROLE_ADMIN,))
        row = AuditLog.query.first()
        assert row.actor_pseudonym != "anonymous"
    finally:
        ctx.pop()


def test_actor_id_prefixes_admin_ids():
    assert rbac.actor_id({"admin_id": 7}) == "admin:7"
    assert rbac.actor_id({"voter_id": "VOTER001"}) == "VOTER001"
    assert rbac.actor_id({}) is None