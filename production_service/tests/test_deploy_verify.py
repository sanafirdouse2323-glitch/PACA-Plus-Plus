from __future__ import annotations

import json
import uuid

import pytest

import paca_deploy


class FakeResponse:
    def __init__(self, status: int, body: dict):
        self.status = status
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        return self.body[:size]


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return self.responses.pop(0)


def valid_environment():
    return {
        "PACA_VERIFY_OWNER_TOKEN": "owner." + "x" * 64,
        "PACA_VERIFY_SAME_TENANT_NONOWNER_TOKEN": "nonowner." + "x" * 64,
        "PACA_VERIFY_OTHER_TENANT_TOKEN": "other." + "x" * 64,
        "PACA_VERIFY_RESOURCE_ID": "smoke-file-001",
        "PACA_VERIFY_API_URL": "http://127.0.0.1:8000",
        "PACA_VERIFY_EXPECTED_POLICY_REVISION": "paca-dev-2026-10-23",
    }


def test_live_verification_checks_allow_execute_status_and_both_denials(monkeypatch, capsys):
    permit_id = str(uuid.uuid4())
    execution_id = str(uuid.uuid4())
    opener = FakeOpener(
        [
            FakeResponse(201, {"permit_id": permit_id, "policy_revision": "paca-dev-2026-10-23"}),
            FakeResponse(
                200,
                {
                    "execution_id": execution_id,
                    "status": "succeeded",
                    "result": {"content": "smoke-test-content"},
                },
            ),
            FakeResponse(200, {"status": "succeeded"}),
            FakeResponse(403, {"detail": {"code": "authorization_denied"}}),
            FakeResponse(404, {"detail": {"code": "resource_not_found"}}),
            FakeResponse(404, {"detail": {"code": "execution_not_found"}}),
        ]
    )
    monkeypatch.setattr(
        paca_deploy.urllib.request,
        "build_opener",
        lambda *_handlers: opener,
    )

    paca_deploy.verify_live_deployment(valid_environment())

    assert len(opener.requests) == 6
    methods = [request.get_method() for request, _timeout in opener.requests]
    assert methods == ["POST", "POST", "GET", "POST", "POST", "GET"]
    assert opener.requests[0][0].full_url.endswith("/v1/authorizations")
    assert opener.requests[1][0].full_url.endswith("/v1/executions")
    assert opener.requests[2][0].full_url.endswith(f"/v1/executions/{execution_id}")
    assert opener.requests[3][0].get_header("Authorization").startswith("Bearer nonowner.")
    assert opener.requests[4][0].get_header("Authorization").startswith("Bearer other.")
    assert "Idempotency-key" in opener.requests[1][0].headers
    output = capsys.readouterr().out
    assert "passed" in output
    assert "owner read/execution" in output
    assert "owner.x" not in output


def test_live_verification_requires_all_three_identity_tokens():
    with pytest.raises(paca_deploy.DeployError, match="three PACA_VERIFY"):
        paca_deploy.verify_live_deployment({"PACA_VERIFY_RESOURCE_ID": "file-1"})


def test_live_verification_rejects_plain_http_remote_api():
    values = valid_environment()
    values["PACA_VERIFY_API_URL"] = "http://api.example.test"

    with pytest.raises(paca_deploy.DeployError, match="Use HTTPS"):
        paca_deploy.verify_live_deployment(values)


def test_live_verification_rejects_wrong_policy_revision(monkeypatch):
    permit_id = str(uuid.uuid4())
    opener = FakeOpener(
        [FakeResponse(201, {"permit_id": permit_id, "policy_revision": "unexpected"})]
    )
    monkeypatch.setattr(
        paca_deploy.urllib.request,
        "build_opener",
        lambda *_handlers: opener,
    )
    values = valid_environment()

    with pytest.raises(paca_deploy.DeployError, match="policy revision"):
        paca_deploy.verify_live_deployment(values)
