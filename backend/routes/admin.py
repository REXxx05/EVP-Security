# SR-11 / SR-12 / SR-13 / SR-14: admin routes.
import json
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from extensions import db
from middleware.audit_logger import export_entries, log_action, verify_chain
from middleware.rbac import ROLE_ADMIN, ROLE_AUDITOR, actor_id, require_role
from models.candidate import Candidate
from models.signed_action import CandidateExclusion, SignedAction
from utils import signing
from utils.crypto import pseudonymise_voter

admin_bp = Blueprint("admin", __name__)


def _record(action, candidate, change):
    # signs the action, stores the signature and adds the audit entry.
    # it doesn't commit, the route does that at the end
    uid = actor_id(request.current_user)
    signer = pseudonymise_voter(uid)

    payload = {
        "action": action,
        "candidate_id": candidate.id,
        "change": change,
        "by": signer,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    signature = signing.sign_payload(payload)

    db.session.add(
        SignedAction(
            signer_pseudonym=signer,
            action=action,
            payload=json.dumps(payload, sort_keys=True),
            signature=signature,
        )
    )
    log_action(
        uid,
        action,
        f"candidate={candidate.id} change={change}",
        commit=False,
    )
    return signature


@admin_bp.route("/candidates", methods=["GET"])
@require_role(ROLE_ADMIN, ROLE_AUDITOR)
def list_candidates():
    excluded_ids = {e.candidate_id for e in CandidateExclusion.query.all()}
    return jsonify(
        [
            {
                "id": c.id,
                "name": c.name,
                "party": c.party,
                "division": c.division,
                "ballot_position": c.ballot_position,
                "excluded": c.id in excluded_ids,
            }
            for c in Candidate.query.all()
        ]
    )


@admin_bp.route("/candidates/<int:candidate_id>/order", methods=["POST"])
@require_role(ROLE_ADMIN)
def set_candidate_order(candidate_id):
    data = request.get_json(silent=True) or {}
    new_position = data.get("ballot_position")

    # basic input check, must be a whole number of 1 or more
    if not isinstance(new_position, int) or new_position < 1:
        return jsonify({"error": "ballot_position must be a positive integer"}), 400

    candidate = db.session.get(Candidate, candidate_id)
    if candidate is None:
        return jsonify({"error": "Candidate not found"}), 404

    change = {"ballot_position": [candidate.ballot_position, new_position]}
    candidate.ballot_position = new_position

    signature = _record("CANDIDATE_ORDER_CHANGED", candidate, change)
    db.session.commit()
    return jsonify({"status": "ok", "signature": signature})


@admin_bp.route("/candidates/<int:candidate_id>/exclude", methods=["POST"])
@require_role(ROLE_ADMIN)
def exclude_candidate(candidate_id):
    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip()

    # excluding someone needs a reason, so there's a record of why
    if not reason or len(reason) > 500:
        return jsonify({"error": "A reason (1-500 characters) is required"}), 400

    candidate = db.session.get(Candidate, candidate_id)
    if candidate is None:
        return jsonify({"error": "Candidate not found"}), 404

    # can't exclude the same person twice
    if CandidateExclusion.query.filter_by(candidate_id=candidate.id).first():
        return jsonify({"error": "Candidate is already excluded"}), 409

    db.session.add(CandidateExclusion(candidate_id=candidate.id, reason=reason))

    signature = _record(
        "CANDIDATE_EXCLUDED", candidate, {"excluded": True, "reason": reason}
    )
    db.session.commit()
    return jsonify({"status": "ok", "signature": signature})


@admin_bp.route("/audit-log", methods=["GET"])
@require_role(ROLE_ADMIN, ROLE_AUDITOR)
def audit_log_export():
    # the full log, plus whether the hash chain still checks out
    ok, bad_id = verify_chain()
    return jsonify(
        {"chain_valid": ok, "first_bad_entry": bad_id, "entries": export_entries()}
    )


@admin_bp.route("/audit-log/verify", methods=["GET"])
@require_role(ROLE_ADMIN, ROLE_AUDITOR)
def audit_log_verify():
    ok, bad_id = verify_chain()
    return jsonify({"chain_valid": ok, "first_bad_entry": bad_id})


@admin_bp.route("/public-key", methods=["GET"])
def public_key():
    # no login needed, the public key is meant to be shared
    return jsonify({"algorithm": "Ed25519", "public_key_pem": signing.public_key_pem()})