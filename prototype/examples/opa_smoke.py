"""Smoke-test the real OPA REST API against the checked-in Rego policy."""
from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from paca_mvp.hardening import OPAClient

client = OPAClient(os.environ.get("OPA_URL", "http://127.0.0.1:8181"))
version = client.get_policy_version()
assert version == "paca-example-v2", f"unexpected policy version: {version!r}"

base = {
    "principal": {"subject": "user-17", "claims": {"suspended": False}},
    "action": "file.read",
    "resource": "file:report-1",
    "context": {
        "authorization": {"role": "analyst"},
        "resource": {"owner": "user-17"},
    },
}
allowed = client.decide(base)
assert allowed["allowed"] is True, f"expected permit, got {allowed!r}"
assert allowed["policy_version"] == version

not_owner = {
    **base,
    "context": {
        "authorization": {"role": "analyst"},
        "resource": {"owner": "another-user"},
    },
}
denied = client.decide(not_owner)
assert denied["allowed"] is False, f"expected deny, got {denied!r}"

missing_status = {
    **base,
    "principal": {"subject": "user-17", "claims": {"role": "analyst"}},
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

ticket = {
    **base,
    "action": "ticket.create",
    "resource": "ticket-collection:default",
    "principal": {"subject": "user-17", "claims": {"suspended": False}},
    "context": {"authorization": {"role": "support", "can_create_tickets": True}},
}
assert client.decide(ticket)["allowed"] is True, "expected support ticket create to be permitted"
ticket_denied = {
    **ticket,
    "context": {"authorization": {"role": "support", "can_create_tickets": False}},
}
assert client.decide(ticket_denied)["allowed"] is False, "expected ticket create without trusted capability to be denied"

print(
    f"OPA integration smoke passed: policy={version}, read permit, ownership deny, "
    "missing-status deny, suspended deny, ticket-create permit/deny verified"
)
