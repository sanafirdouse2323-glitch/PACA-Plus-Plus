from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from paca_mvp.hardening import (
    AuthenticationFailed, ContextUnavailable, EffectOutcomeUnknown,
    IdempotencyConflict, IdentityProviderUnavailable, PermitRejected, PolicyUnavailable,
)
from paca_mvp.service import (
    MAX_REQUEST_BYTES, TICKET_ACTION, TICKET_RESOURCE, build_gateway_from_environment, create_app,
)


class GatewayAppTests(unittest.TestCase):
    def setUp(self):
        self.gateway = Mock()
        self.gateway.authorize_and_execute.return_value = {
            "ticket_id": "ticket-123", "status": "created",
        }
        self.store = Mock()
        self.store.current_state_version.return_value = 7
        self.opa = Mock()
        self.opa.get_policy_version.return_value = "policy-test-v1"
        self.adapter = object()
        self.app = create_app(
            gateway=self.gateway, ticket_adapter=self.adapter,
            store=self.store, opa=self.opa,
        )
        self.client = TestClient(self.app)

    def test_health_and_readiness_expose_only_dependency_status(self):
        health = self.client.get("/healthz")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json(), {"status": "ok"})
        ready = self.client.get("/readyz")
        self.assertEqual(ready.status_code, 200)
        self.assertEqual(ready.json(), {
            "status": "ready", "policy_version": "policy-test-v1", "state_version": 7,
        })

    def test_missing_bearer_token_is_rejected_without_gateway_call(self):
        response = self.client.post(
            "/v1/tickets", json={"title": "Incident"},
            headers={"Idempotency-Key": "op-1"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["www-authenticate"], "Bearer")
        self.gateway.authorize_and_execute.assert_not_called()

    def test_missing_idempotency_key_is_rejected(self):
        response = self.client.post(
            "/v1/tickets",
            json={"title": "Incident"},
            headers={"Authorization": "Bearer valid-format-token"},
        )
        self.assertEqual(response.status_code, 400)
        self.gateway.authorize_and_execute.assert_not_called()

    def test_malformed_idempotency_keys_are_rejected_as_bad_requests(self):
        for key in ("   ", "x" * 513):
            with self.subTest(key_length=len(key)):
                response = self.client.post(
                    "/v1/tickets", json={"title": "Incident"},
                    headers={"Authorization": "Bearer valid-format-token",
                             "Idempotency-Key": key},
                )
                self.assertEqual(response.status_code, 400)
        self.gateway.authorize_and_execute.assert_not_called()

    def test_endpoint_binds_action_resource_adapter_and_request_body(self):
        response = self.client.post(
            "/v1/tickets",
            json={"title": " Incident ", "description": "Service interruption"},
            headers={"Authorization": "Bearer valid-format-token",
                     "Idempotency-Key": "op-123"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ticket_id": "ticket-123", "status": "created"})
        kwargs = self.gateway.authorize_and_execute.call_args.kwargs
        self.assertEqual(kwargs["credential"], "valid-format-token")
        self.assertEqual(kwargs["action"], TICKET_ACTION)
        self.assertEqual(kwargs["resource"], TICKET_RESOURCE)
        self.assertEqual(kwargs["arguments"], {
            "title": "Incident", "description": "Service interruption",
        })
        self.assertIs(kwargs["adapter"], self.adapter)
        self.assertEqual(kwargs["idempotency_key"], "op-123")

    def test_extra_fields_and_oversized_body_are_rejected(self):
        extra = self.client.post(
            "/v1/tickets",
            json={"title": "Incident", "admin": True},
            headers={"Authorization": "Bearer valid-format-token",
                     "Idempotency-Key": "op-123"},
        )
        self.assertEqual(extra.status_code, 422)
        oversized_body = json.dumps({"title": "x" * (MAX_REQUEST_BYTES + 10)}).encode()
        oversized = self.client.post(
            "/v1/tickets", content=oversized_body,
            headers={"Authorization": "Bearer valid-format-token",
                     "Idempotency-Key": "op-124",
                     "Content-Type": "application/json"},
        )
        self.assertEqual(oversized.status_code, 413)
        self.gateway.authorize_and_execute.assert_not_called()

    def test_dependency_and_policy_errors_map_to_safe_http_statuses(self):
        mappings = [
            (AuthenticationFailed("internal details"), 401),
            (IdentityProviderUnavailable("internal details"), 503),
            (ContextUnavailable("internal details"), 503),
            (PolicyUnavailable("internal details"), 503),
            (IdempotencyConflict("internal details"), 409),
            (EffectOutcomeUnknown("internal details"), 409),
            (PermitRejected("internal details"), 403),
        ]
        for error, status in mappings:
            with self.subTest(error=type(error).__name__):
                self.gateway.authorize_and_execute.side_effect = error
                response = self.client.post(
                    "/v1/tickets", json={"title": "Incident"},
                    headers={"Authorization": "Bearer valid-format-token",
                             "Idempotency-Key": "op-error"},
                )
                self.assertEqual(response.status_code, status)
                self.assertNotIn("internal details", response.text)
        self.gateway.authorize_and_execute.side_effect = None

    def test_duplicate_authorization_headers_fail_closed(self):
        response = self.client.post(
            "/v1/tickets",
            json={"title": "Incident"},
            headers=[
                ("Authorization", "Bearer valid-format-token"),
                ("Authorization", "Bearer different-token"),
                ("Idempotency-Key", "op-duplicate-auth"),
            ],
        )
        self.assertEqual(response.status_code, 400)
        self.gateway.authorize_and_execute.assert_not_called()

    def test_duplicate_idempotency_headers_fail_closed(self):
        response = self.client.post(
            "/v1/tickets",
            json={"title": "Incident"},
            headers=[
                ("Authorization", "Bearer valid-format-token"),
                ("Idempotency-Key", "op-first"),
                ("Idempotency-Key", "op-second"),
            ],
        )
        self.assertEqual(response.status_code, 400)
        self.gateway.authorize_and_execute.assert_not_called()

    def test_duplicate_content_length_headers_fail_closed(self):
        body = b'{"title":"Incident"}'
        response = self.client.post(
            "/v1/tickets",
            content=body,
            headers=[
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                ("Content-Length", str(len(body))),
                ("Authorization", "Bearer valid-format-token"),
                ("Idempotency-Key", "op-duplicate-length"),
            ],
        )
        self.assertEqual(response.status_code, 400)
        self.gateway.authorize_and_execute.assert_not_called()

    def test_bad_bearer_scheme_is_rejected(self):
        response = self.client.post(
            "/v1/tickets", json={"title": "Incident"},
            headers={"Authorization": "Basic not-a-bearer",
                     "Idempotency-Key": "op-1"},
        )
        self.assertEqual(response.status_code, 401)
        self.gateway.authorize_and_execute.assert_not_called()

    def test_postgres_schema_migrations_default_to_disabled(self):
        env = {
            "OIDC_ISSUER": "https://issuer.example/",
            "OIDC_AUDIENCE": "paca-api",
            "OIDC_JWKS_URL": "https://issuer.example/.well-known/jwks.json",
            "PACA_CONTEXT_URL": "https://context.example/v1/attributes",
            "PACA_CONTEXT_SERVICE_TOKEN": "context-secret-" + "x" * 16,
            "OPA_URL": "https://opa.example",
            "OPA_BEARER_TOKEN": "opa-secret",
            "PACA_DATABASE_URL": "postgresql://paca:secret@db.example/paca?sslmode=verify-full",
            "PACA_PROTECTED_API_BASE_URL": "https://tickets.example",
            "PACA_PROTECTED_API_TOKEN": "tickets-secret",
        }
        with patch.dict(os.environ, env, clear=True), \
             patch("paca_mvp.service.OIDCJWTIdentityProvider"), \
             patch("paca_mvp.service.HTTPAuthorizationContextProvider"), \
             patch("paca_mvp.service.OPAClient"), \
             patch("paca_mvp.service.HTTPJSONToolAdapter"), \
             patch("paca_mvp.service.PostgresPermitStore") as store_cls:
            build_gateway_from_environment()
        store_cls.assert_called_once_with(
            env["PACA_DATABASE_URL"], initialize_schema=False
        )


if __name__ == "__main__":
    unittest.main()
