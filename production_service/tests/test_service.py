from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient

from paca_service.adapters import AdapterRouter
from paca_service.app import create_app
from paca_service.auth import AuthenticationError, Principal
from paca_service.config import Settings
from paca_service.opa import PolicyDecision, PolicyEngineUnavailable
from paca_service.store import ClaimResult, PermitRecord


class FakeAuthenticator:
    def authenticate(self, token: str) -> Principal:
        if token != "signed-by-test-idp":
            raise AuthenticationError("invalid_bearer_token")
        return Principal(
            subject="alice",
            tenant_id="tenant-1",
            roles=(),
            scopes=("file:read", "document:read"),
            tools=("text.word_count",),
            token_id="jwt-test-id",
        )


class FakeOPA:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.inputs: list[dict[str, Any]] = []
        self.fail = False

    def evaluate(self, input_document: dict[str, Any]) -> PolicyDecision:
        self.inputs.append(input_document)
        if self.fail:
            raise PolicyEngineUnavailable("opa_unavailable")
        return PolicyDecision(
            allowed=self.allowed,
            reason="test_allow" if self.allowed else "test_deny",
            policy_revision="paca-dev-2026-10-23",
            decision_id="opa-decision-test",
        )

    def health(self) -> None:
        if self.fail:
            raise PolicyEngineUnavailable("opa_unavailable")

    def close(self) -> None:
        pass


class FakeStore:
    def __init__(self) -> None:
        self.resources: dict[tuple[str, str], dict[str, Any]] = {
            ("tenant-1", "file-1"): {
                "tenant_id": "tenant-1",
                "resource_id": "file-1",
                "owner_id": "alice",
                "kind": "file",
                "status": "active",
                "attributes": {"relative_path": "report.txt"},
            },
        }
        self.permits: dict[str, PermitRecord] = {}
        self.audits: list[dict[str, Any]] = []
        self.executions: dict[str, dict[str, Any]] = {}
        self.idempotency: dict[tuple[str, str, str], str] = {}
        self.opened = False
        self.claim_count = 0

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.opened = False

    def ping(self) -> None:
        return None

    def mark_stale_executions_unknown(self, stale_after_seconds: int) -> int:
        return 0

    def fetch_resource(self, tenant_id: str, resource_id: str) -> dict[str, Any] | None:
        row = self.resources.get((tenant_id, resource_id))
        return dict(row) if row else None

    def issue_permit(self, **kwargs: Any) -> PermitRecord:
        permit_id = str(uuid4())
        permit = PermitRecord(
            permit_id=permit_id,
            tenant_id=kwargs["tenant_id"],
            principal_id=kwargs["principal_id"],
            action=kwargs["action"],
            resource_id=kwargs["resource_id"],
            arguments_digest=kwargs["arguments_digest"],
            context_digest=kwargs["context_digest"],
            policy_revision=kwargs["policy_revision"],
            decision_id=kwargs["decision_id"],
            status="issued",
            expires_at=datetime.now(UTC) + timedelta(seconds=kwargs["ttl_seconds"]),
        )
        self.permits[permit_id] = permit
        self.audits.append({"event_type": "permit_issued", **kwargs})
        return permit

    def get_permit(self, permit_id: Any, tenant_id: str, principal_id: str) -> PermitRecord | None:
        item = self.permits.get(str(permit_id))
        if item and (item.tenant_id, item.principal_id) == (tenant_id, principal_id):
            return item
        return None

    def revoke_permit(
        self, permit_id: Any, tenant_id: str, principal_id: str, reason: str,
        request_id: str | None,
    ) -> None:
        item = self.get_permit(permit_id, tenant_id, principal_id)
        if item and item.status == "issued":
            self.permits[item.permit_id] = replace(item, status="revoked")
            self.audits.append({"event_type": "permit_revoked", "reason_code": reason})

    def record_audit(self, **kwargs: Any) -> None:
        self.audits.append(kwargs)

    def claim_execution(self, **kwargs: Any) -> ClaimResult:
        self.claim_count += 1
        key = (kwargs["tenant_id"], kwargs["principal_id"], kwargs["idempotency_key"])
        req_hash = (
            kwargs["permit_id"], kwargs["action"], kwargs["resource_id"],
            kwargs["arguments_digest"], kwargs["context_digest"], kwargs["policy_revision"],
        )
        previous_id = self.idempotency.get(key)
        if previous_id:
            previous = self.executions[previous_id]
            if previous["request"] != req_hash:
                return ClaimResult("conflict", reason="idempotency_key_reused_for_different_request")
            if previous["status"] == "succeeded":
                return ClaimResult(
                    "replayed_success", execution_id=previous_id,
                    status="succeeded", result=previous["result"],
                )
            if previous["status"] == "executing":
                return ClaimResult("in_progress", execution_id=previous_id, status="executing")
            if previous["status"] == "unknown":
                return ClaimResult("outcome_unknown", execution_id=previous_id, status="unknown")
            return ClaimResult("failed", execution_id=previous_id, status="failed")
        permit = self.get_permit(kwargs["permit_id"], kwargs["tenant_id"], kwargs["principal_id"])
        if not permit:
            return ClaimResult("rejected", reason="invalid_permit")
        if permit.status != "issued":
            prior = self.executions.get(permit.permit_id)
            if prior:
                return ClaimResult("in_progress", execution_id=permit.permit_id, status=prior["status"])
            return ClaimResult("rejected", reason="permit_not_issued")
        if permit.expires_at <= datetime.now(UTC):
            return ClaimResult("rejected", reason="permit_expired")
        if (permit.action, permit.resource_id) != (kwargs["action"], kwargs["resource_id"]):
            return ClaimResult("rejected", reason="operation_mismatch")
        if permit.arguments_digest != kwargs["arguments_digest"]:
            return ClaimResult("rejected", reason="arguments_mismatch")
        if permit.context_digest != kwargs["context_digest"]:
            return ClaimResult("rejected", reason="context_changed")
        if permit.policy_revision != kwargs["policy_revision"]:
            return ClaimResult("rejected", reason="stale_policy")
        execution_id = str(uuid4())
        self.idempotency[key] = execution_id
        self.executions[execution_id] = {
            "request": req_hash, "status": "executing", "result": None,
            "tenant_id": kwargs["tenant_id"], "principal_id": kwargs["principal_id"],
            "permit_id": permit.permit_id, "action": kwargs["action"],
            "resource_id": kwargs["resource_id"],
        }
        self.permits[permit.permit_id] = replace(permit, status="executing")
        return ClaimResult("claimed", execution_id=execution_id, status="executing")

    def finish_execution(
        self, *, execution_id: str, tenant_id: str, principal_id: str,
        outcome: str, result: dict[str, Any] | None,
        error_code: str | None, request_id: str | None,
    ) -> None:
        item = self.executions[execution_id]
        if (item["tenant_id"], item["principal_id"]) != (tenant_id, principal_id):
            raise RuntimeError("execution tenant/principal mismatch")
        item["status"] = outcome
        item["result"] = result
        item["error_code"] = error_code
        permit = self.permits[item["permit_id"]]
        self.permits[item["permit_id"]] = replace(permit, status=outcome)

    def get_execution_status(
        self, execution_id: Any, tenant_id: str, principal_id: str
    ) -> dict[str, Any] | None:
        item = self.executions.get(str(execution_id))
        if not item or (item["tenant_id"], item["principal_id"]) != (tenant_id, principal_id):
            return None
        return {
            "execution_id": str(execution_id),
            "status": item["status"],
            "error_code": item.get("error_code"),
            "action": item["action"],
            "resource_id": item["resource_id"],
            "policy_revision": "paca-dev-2026-10-23",
            "created_at": datetime.now(UTC).isoformat(),
            "started_at": datetime.now(UTC).isoformat(),
            "finished_at": datetime.now(UTC).isoformat() if item["status"] != "executing" else None,
        }


class RecordingAdapter:
    def __init__(self, actions: set[str] | None = None) -> None:
        self.actions = actions or {"file.read"}
        self.requests = []

    def supports(self, action: str, arguments: dict[str, Any], context: dict[str, Any]) -> bool:
        return action in self.actions

    def execute(self, request: Any) -> dict[str, Any]:
        self.requests.append(request)
        return {"ok": True, "resource_id": request.resource_id}


def make_settings() -> Settings:
    return Settings(
        database_url="postgresql://test:test@localhost/test",
        opa_url="http://opa:8181",
        opa_decision_path="/v1/data/paca/authz/decision",
        opa_timeout_seconds=2,
        expected_policy_revision="paca-dev-2026-10-23",
        jwt_issuer="https://identity.example.org/",
        jwt_audience="paca-api",
        jwt_jwks_url="https://identity.example.org/.well-known/jwks.json",
        jwt_timeout_seconds=5,
        permit_ttl_seconds=30,
        execution_timeout_seconds=10,
        stale_execution_seconds=120,
        api_base_url=None,
        api_routes={},
        api_bearer_token=None,
        file_root=None,
    )


def make_client(store: FakeStore | None = None, opa: FakeOPA | None = None, adapter: Any = None):
    store = store or FakeStore()
    opa = opa or FakeOPA()
    adapter = adapter or RecordingAdapter()
    app = create_app(
        settings=make_settings(),
        store=store,
        opa=opa,  # type: ignore[arg-type]
        authenticator=FakeAuthenticator(),  # type: ignore[arg-type]
        adapter_router=AdapterRouter([adapter]),  # type: ignore[list-item]
    )
    return app, store, opa, adapter


def auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer signed-by-test-idp"}


def authorize(client: TestClient, action: str = "file.read", resource_id: str = "file-1") -> dict[str, Any]:
    response = client.post(
        "/v1/authorizations",
        headers=auth_headers(),
        json={"action": action, "resource_id": resource_id, "arguments": {}},
    )
    assert response.status_code == 201, response.text
    return response.json()


def execute(
    client: TestClient, permit_id: str, action: str = "file.read",
    resource_id: str = "file-1", idempotency_key: str = "request-1",
):
    return client.post(
        "/v1/executions",
        headers={**auth_headers(), "Idempotency-Key": idempotency_key},
        json={
            "permit_id": permit_id, "action": action,
            "resource_id": resource_id, "arguments": {},
        },
    )


def test_authentication_is_required_before_authorization():
    app, store, _, _ = make_client()
    with TestClient(app) as client:
        response = client.post(
            "/v1/authorizations",
            json={"action": "file.read", "resource_id": "file-1", "arguments": {}},
        )
    assert response.status_code == 401
    assert store.permits == {}


def test_successful_operation_replays_result_without_calling_adapter_twice():
    app, _store, opa, adapter = make_client()
    with TestClient(app) as client:
        permit = authorize(client)
        first = execute(client, permit["permit_id"])
        second = execute(client, permit["permit_id"])
        assert first.status_code == 200, first.text
        assert first.json()["status"] == "succeeded"
        assert second.status_code == 200, second.text
        assert second.json()["idempotent_replay"] is True
    assert len(adapter.requests) == 1
    assert len(opa.inputs) == 3


def test_resource_context_change_revokes_permit_before_effect():
    app, store, _, adapter = make_client()
    with TestClient(app) as client:
        permit = authorize(client)
        store.resources[("tenant-1", "file-1")]["owner_id"] = "mallory"
        response = execute(client, permit["permit_id"])
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "context_changed_reauthorize"
    assert adapter.requests == []
    assert store.permits[permit["permit_id"]].status == "revoked"


def test_policy_denial_is_audited_and_never_reaches_adapter():
    app, store, _, adapter = make_client(opa=FakeOPA(allowed=False))
    with TestClient(app) as client:
        response = client.post(
            "/v1/authorizations", headers=auth_headers(),
            json={"action": "file.read", "resource_id": "file-1", "arguments": {}},
        )
    assert response.status_code == 403
    assert any(item.get("event_type") == "authorization_denied" for item in store.audits)
    assert adapter.requests == []


def test_opa_failure_fails_closed_without_issuing_permit():
    opa = FakeOPA()
    opa.fail = True
    app, store, _, _ = make_client(opa=opa)
    with TestClient(app) as client:
        response = client.post(
            "/v1/authorizations", headers=auth_headers(),
            json={"action": "file.read", "resource_id": "file-1", "arguments": {}},
        )
    assert response.status_code == 503
    assert store.permits == {}


def test_unregistered_action_has_no_effect_adapter_and_is_not_claimed():
    app, store, _, adapter = make_client()
    with TestClient(app) as client:
        permit = authorize(client, action="document.read")
        response = execute(client, permit["permit_id"], action="document.read")
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "no_adapter_for_operation"
    assert store.claim_count == 0
    assert adapter.requests == []


def test_execution_status_is_scoped_to_authenticated_principal():
    app, _, _, _ = make_client()
    with TestClient(app) as client:
        permit = authorize(client)
        done = execute(client, permit["permit_id"])
        execution_id = done.json()["execution_id"]
        status = client.get(
            f"/v1/executions/{execution_id}", headers=auth_headers()
        )
        assert status.status_code == 200
        assert status.json()["status"] == "succeeded"
        other = client.get(
            f"/v1/executions/{execution_id}",
            headers={"Authorization": "Bearer not-valid"},
        )
        assert other.status_code == 401
