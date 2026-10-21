# SR-11: role-based access control.

# Anyone without the right role gets a 403, and the attempt goes in the audit log.
from functools import wraps

from flask import jsonify, request

from middleware.audit_logger import log_action
from middleware.authenticate import token_required

# CHECK: change these to match the exact role names in the JWT token
ROLE_ADMIN = "admin"
ROLE_AUDITOR = "auditor"


def _check(allowed_roles):
    # returns None if the user is allowed, otherwise a (response, 403)
    user = getattr(request, "current_user", None) or {}
    role = user.get("role")

    if role in allowed_roles:
        return None

    # not allowed, so log it before saying no
    log_action(
        user.get("voter_id"),
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