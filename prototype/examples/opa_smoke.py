"""Smoke-test the real OPA REST API against the checked-in Rego policy."""
from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from paca_mvp.hardening import OPAClient

client = OPAClient(os.environ.get("OPA_URL", "http://127.0.0.1:8181"))
version = client.get_policy_version()
assert version == "paca-example-v4", f"unexpected policy version: {version!r}"

base = {
    "principal": {"subject": "user-17", "claims": {"suspended": False}},
    "action": "file.read",
    "resource": "file:report-1",
    "context": {
        "authorization": {"principal_id": "principal-17", "tenant_id": "tenant-1",
                          "role": "analyst", "suspended": False},
        "resource": {"owner_principal_id": "principal-17", "tenant_id": "tenant-1"},
    },
}
allowed = client.decide(base)
assert allowed["allowed"] is True, f"expected permit, got {allowed!r}"
assert allowed["policy_version"] == version

not_owner = {
    **base,
    "context": {
        "authorization": {"principal_id": "principal-17", "tenant_id": "tenant-1",
                          "role": "analyst", "suspended": False},
        "resource": {"owner_principal_id": "principal-99", "tenant_id": "tenant-1"},
    },
}
denied = client.decide(not_owner)
assert denied["allowed"] is False, f"expected deny, got {denied!r}"

# A raw OIDC subject is not an internal resource identifier. This prevents a
# colliding subject from another issuer/tenant matching an owner's internal ID.
raw_subject_collision = {
    **base,
    "principal": {"subject": "principal-17", "claims": {"suspended": False}},
    "context": {
        "authorization": {"principal_id": "different-internal-user", "tenant_id": "tenant-1",
                          "role": "analyst", "suspended": False},
        "resource": {"owner_principal_id": "principal-17", "tenant_id": "tenant-1"},
    },
}
assert client.decide(raw_subject_collision)["allowed"] is False, (
    "a raw subject collision must not satisfy internal ownership"
)

cross_tenant = {
    **base,
    "context": {
        "authorization": {"principal_id": "principal-17", "tenant_id": "tenant-1",
                          "role": "analyst", "suspended": False},
        "resource": {"owner_principal_id": "principal-17", "tenant_id": "tenant-2"},
    },
}
assert client.decide(cross_tenant)["allowed"] is False, (
    "matching owner ID must not override a tenant mismatch"
)

missing_status = {
    **base,
    "context": {
        "authorization": {"principal_id": "principal-17", "tenant_id": "tenant-1",
                          "role": "analyst"},
        "resource": {"owner_principal_id": "principal-17", "tenant_id": "tenant-1"},
    },
}
denied_missing_status = client.decide(missing_status)
assert denied_missing_status["allowed"] is False, (
    f"expected deny when suspended status is missing, got {denied_missing_status!r}"
)

suspended = {
    **base,
    "principal": {"subject": "user-17", "claims": {"suspended": True}},
}
denied_suspended = client.decide(suspended)
assert denied_suspended["allowed"] is False, f"expected suspended-user deny, got {denied_suspended!r}"

# The token may still contain suspended=False after an account is suspended;
# the trusted context service is authoritative for the current state.
currently_suspended = {
    **base,
    "context": {
        "authorization": {"principal_id": "principal-17", "tenant_id": "tenant-1",
                          "role": "analyst", "suspended": True},
        "resource": {"owner_principal_id": "principal-17", "tenant_id": "tenant-1"},
    },
}
denied_current_status = client.decide(currently_suspended)
assert denied_current_status["allowed"] is False, (
    f"expected deny based on trusted current suspension state, got {denied_current_status!r}"
)

ticket = {
    **base,
    "action": "ticket.create",
    "resource": "ticket-collection:default",
    "principal": {"subject": "user-17", "claims": {"suspended": False}},
    "context": {
        "authorization": {"principal_id": "principal-17", "tenant_id": "tenant-1",
                          "role": "support", "can_create_tickets": True, "suspended": False},
        "resource": {"tenant_id": "tenant-1", "owner_principal_id": None},
    },
}
assert client.decide(ticket)["allowed"] is True, "expected support ticket create to be permitted"
ticket_denied = {
    **ticket,
    "context": {
        "authorization": {"principal_id": "principal-17", "tenant_id": "tenant-1",
                          "role": "support", "can_create_tickets": False, "suspended": False},
        "resource": {"tenant_id": "tenant-1", "owner_principal_id": None},
    },
}
assert client.decide(ticket_denied)["allowed"] is False, "expected ticket create without trusted capability to be denied"

print(
    f"OPA integration smoke passed: policy={version}, internal-owner permit/deny, raw-subject collision deny, "
    "cross-tenant deny, missing-status deny, JWT/current-suspension deny, ticket-create permit/deny verified"
)
