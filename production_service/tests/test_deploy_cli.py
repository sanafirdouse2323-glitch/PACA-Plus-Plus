from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest

import paca_deploy


def sample_template() -> str:
    return (Path(__file__).parents[1] / ".env.example").read_text(encoding="utf-8")


def sample_policy() -> dict:
    return {"paca": {"meta": {"revision": "paca-test-revision"}}}


def sample_metadata() -> dict[str, str]:
    return {
        "issuer": "https://id.example.test/realms/paca",
        "jwks_uri": "https://id.example.test/realms/paca/protocol/openid-connect/certs",
    }


def sample_environment() -> dict[str, str]:
    template = sample_template()
    generated = iter(("a" * 64, "b" * 64, "c" * 64))
    rendered = paca_deploy.render_environment(
        template,
        sample_metadata(),
        "paca-api",
        "paca-test-revision",
        secret_factory=lambda _size: next(generated),
    )
    return paca_deploy.parse_env_text(rendered)


def test_render_environment_generates_separate_secrets_and_uses_metadata():
    values = sample_environment()

    assert values["POSTGRES_PASSWORD"] == "a" * 64
    assert values["PACA_RUNTIME_PASSWORD"] == "b" * 64
    assert values["PACA_TENANT_CONTEXT_HMAC_KEY"] == "c" * 64
    assert values["PACA_JWT_ISSUER"] == sample_metadata()["issuer"]
    assert values["PACA_JWT_JWKS_URL"] == sample_metadata()["jwks_uri"]
    assert values["PACA_JWT_AUDIENCE"] == "paca-api"
    assert values["PACA_EXPECTED_POLICY_REVISION"] == "paca-test-revision"
    assert values["PACA_API_ROUTES_JSON"] == "{}"


def test_validate_environment_accepts_generated_configuration():
    paca_deploy.validate_environment(sample_environment(), sample_policy())


def test_validate_environment_rejects_policy_revision_mismatch():
    values = sample_environment()
    values["PACA_EXPECTED_POLICY_REVISION"] = "different-revision"

    with pytest.raises(paca_deploy.DeployError, match="does not match"):
        paca_deploy.validate_environment(values, sample_policy())


def test_validate_environment_requires_remote_opa_authentication():
    values = sample_environment()
    values["PACA_OPA_URL"] = "https://opa.example.test"
    values["PACA_OPA_BEARER_TOKEN"] = ""

    with pytest.raises(paca_deploy.DeployError, match="Remote OPA requires"):
        paca_deploy.validate_environment(values, sample_policy())


def test_validate_environment_rejects_http_identity_provider():
    values = sample_environment()
    values["PACA_JWT_ISSUER"] = "http://id.example.test/realms/paca"

    with pytest.raises(paca_deploy.DeployError, match="HTTPS"):
        paca_deploy.validate_environment(values, sample_policy())


def test_parse_env_text_rejects_duplicate_keys():
    with pytest.raises(paca_deploy.DeployError, match="Duplicate"):
        paca_deploy.parse_env_text("PACA_VALUE=one\nPACA_VALUE=two\n")


def test_parse_env_text_ignores_comments_and_preserves_url_trailing_slash():
    values = paca_deploy.parse_env_text(
        "# comment\nPACA_JWT_ISSUER=https://id.example.test/realms/paca/\n"
    )

    assert values["PACA_JWT_ISSUER"] == "https://id.example.test/realms/paca/"


def test_write_new_env_uses_restrictive_permissions_and_refuses_overwrite(tmp_path):
    env_path = tmp_path / ".env"
    paca_deploy.write_new_env(env_path, "PACA_VALUE=value\n")

    assert env_path.read_text(encoding="utf-8") == "PACA_VALUE=value\n"
    if os.name == "posix":
        assert stat.S_IMODE(env_path.stat().st_mode) == 0o600

    with pytest.raises(paca_deploy.DeployError, match="refusing to overwrite"):
        paca_deploy.write_new_env(env_path, "PACA_VALUE=changed\n")
    assert env_path.read_text(encoding="utf-8") == "PACA_VALUE=value\n"


def test_fetch_oidc_metadata_extracts_https_issuer_and_jwks(monkeypatch):
    metadata = sample_metadata()
    response = MagicMock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = json.dumps(metadata).encode("utf-8")
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(paca_deploy.urllib.request, "build_opener", lambda *_args: opener)

    result = paca_deploy.fetch_oidc_metadata(
        "https://id.example.test/realms/paca/.well-known/openid-configuration"
    )

    assert result == metadata
    opener.open.assert_called_once()


def test_fetch_oidc_metadata_rejects_non_https_discovery():
    with pytest.raises(paca_deploy.DeployError, match="HTTPS"):
        paca_deploy.fetch_oidc_metadata(
            "http://id.example.test/.well-known/openid-configuration"
        )


def test_down_command_never_deletes_persistent_volumes(monkeypatch):
    completed = Mock(returncode=0)
    monkeypatch.setattr(paca_deploy.subprocess, "run", Mock(return_value=completed))
    monkeypatch.setattr(paca_deploy, "ENV_FILE", Path("/tmp/paca-test.env"))
    monkeypatch.setattr(paca_deploy, "COMPOSE_FILE", Path("/tmp/compose.yaml"))

    assert paca_deploy.main(["down"]) == 0

    command = paca_deploy.subprocess.run.call_args.args[0]
    assert command[-1] == "down"
    assert "-v" not in command
