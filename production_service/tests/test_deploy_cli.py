from __future__ import annotations

import json
import os
import stat
from unittest.mock import MagicMock, Mock

import pytest

import paca_deploy


def parse_values(content: str) -> dict[str, str]:
    return {
        key: value
        for line in content.splitlines()
        if line and not line.startswith("#") and "=" in line
        for key, value in [line.split("=", 1)]
    }


def sample_environment(monkeypatch) -> dict[str, str]:
    generated = iter(("a" * 64, "b" * 64, "c" * 64))
    monkeypatch.setattr(paca_deploy.secrets, "token_hex", lambda _size: next(generated))
    metadata = {
        "issuer": "https://id.example.test/realms/paca",
        "jwks_uri": "https://id.example.test/realms/paca/keys",
    }
    return parse_values(paca_deploy.make_environment(metadata, "paca-api"))


def test_environment_generation_uses_independent_secrets_and_repository_policy(monkeypatch):
    values = sample_environment(monkeypatch)

    assert values["POSTGRES_PASSWORD"] == "a" * 64
    assert values["PACA_RUNTIME_PASSWORD"] == "b" * 64
    assert values["PACA_TENANT_CONTEXT_HMAC_KEY"] == "c" * 64
    assert values["PACA_JWT_ISSUER"] == "https://id.example.test/realms/paca"
    assert values["PACA_JWT_JWKS_URL"] == "https://id.example.test/realms/paca/keys"
    assert values["PACA_JWT_AUDIENCE"] == "paca-api"
    assert values["PACA_EXPECTED_POLICY_REVISION"] == "paca-dev-2026-10-23"


def test_configuration_validation_reuses_runtime_settings(monkeypatch):
    values = sample_environment(monkeypatch)
    paca_deploy.validate_configuration(values)


def test_configuration_validation_rejects_policy_revision_mismatch(monkeypatch):
    values = sample_environment(monkeypatch)
    values["PACA_EXPECTED_POLICY_REVISION"] = "wrong-revision"

    with pytest.raises(paca_deploy.DeployError, match="does not match"):
        paca_deploy.validate_configuration(values)


def test_configuration_validation_requires_remote_opa_authentication(monkeypatch):
    values = sample_environment(monkeypatch)
    values["PACA_OPA_URL"] = "https://opa.example.test"

    with pytest.raises(paca_deploy.DeployError, match="invalid"):
        paca_deploy.validate_configuration(values)


def test_oidc_discovery_extracts_issuer_and_jwks_uri(monkeypatch):
    metadata = {
        "issuer": "https://id.example.test/realms/paca",
        "jwks_uri": "https://id.example.test/realms/paca/keys",
    }
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = json.dumps(metadata).encode("utf-8")
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(
        paca_deploy.urllib.request, "build_opener", lambda *_args: opener
    )

    result = paca_deploy.oidc_metadata(
        "https://id.example.test/realms/paca/.well-known/openid-configuration"
    )

    assert result == metadata
    opener.open.assert_called_once()


def test_oidc_discovery_rejects_http():
    with pytest.raises(paca_deploy.DeployError, match="HTTPS"):
        paca_deploy.oidc_metadata("http://id.example.test/.well-known/openid-configuration")


def test_write_env_is_restrictive_and_does_not_overwrite(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    monkeypatch.setattr(paca_deploy, "ENV_FILE", env_path)
    paca_deploy.write_env("PACA_VALUE=value\n")

    assert env_path.read_text(encoding="utf-8") == "PACA_VALUE=value\n"
    if os.name == "posix":
        assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    with pytest.raises(paca_deploy.DeployError, match="refusing to overwrite"):
        paca_deploy.write_env("PACA_VALUE=changed\n")


def test_down_command_preserves_named_volumes(monkeypatch):
    calls = []
    monkeypatch.setattr(paca_deploy, "compose", lambda *args: calls.append(args))

    assert paca_deploy.main(["down"]) == 0
    assert calls == [("down",)]
