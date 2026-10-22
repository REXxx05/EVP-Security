# SR-11: role-based access control.

#   @admin_bp.route("/something")
#   @require_role(ROLE_ADMIN)
#   def something():
#       ...
#
# Anyone without the right role gets a 403, and the attempt goes in the audit log.
from functools import wraps

from flask import jsonify, request

from middleware.audit_logger import log_action
from middleware.authenticate import token_required

# these match the role strings in the login tokens (seed_data.py uses 'admin').
# nobody has the auditor role yet, so it simply never matches
ROLE_ADMIN = "admin"
ROLE_AUDITOR = "auditor"


def actor_id(user):
    # voter tokens have a voter_id, admin tokens have an admin_id instead.
    # admin ids get an "admin:" prefix so they can never clash with a voter id
    if user.get("voter_id") is not None:
        return user["voter_id"]
    if user.get("admin_id") is not None:
        return f"admin:{user['admin_id']}"
    return None


def _check(allowed_roles):
    # returns None if the user is allowed, otherwise a (response, 403)
    user = getattr(request, "current_user", None) or {}
    role = user.get("role")

    if role in allowed_roles:
        return None

    # not allowed, so log it before saying no
    log_action(
        actor_id(user),
        "ACCESS_DENIED",
        f"{request.method} {request.path} role={role}",
    )
    return jsonify({"error": "Forbidden"}), 403


def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def checked(*args, **kwargs):
            denied = _check(allowed_roles)
            if denied is not None:
                return denied
            return f(*args, **kwargs)

        # wrapping with token_required means the user is logged in first,
        # then the role check runs
        return token_required(checked)

    return decorator