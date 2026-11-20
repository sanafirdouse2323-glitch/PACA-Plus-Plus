from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import stat
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from paca_service.config import ConfigurationError, Settings

SERVICE_DIR = Path(__file__).resolve().parent
ENV_EXAMPLE = SERVICE_DIR / ".env.example"
ENV_FILE = SERVICE_DIR / ".env"
COMPOSE_FILE = SERVICE_DIR / "compose.yaml"
POLICY_DATA = SERVICE_DIR / "opa" / "data.json"


class DeployError(RuntimeError):
    """A safe, actionable setup or deployment error."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, request: Any, fp: Any, code: int, msg: str, headers: Any, new_url: str
    ) -> None:
        return None


def oidc_metadata(discovery_url: str) -> dict[str, str]:
    parts = urlsplit(discovery_url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise DeployError("Use the identity provider's HTTPS OIDC discovery URL without a query.")

    request = urllib.request.Request(
        discovery_url, headers={"Accept": "application/json", "User-Agent": "PACA-Setup/1.0"}
    )
    try:
        opener = urllib.request.build_opener(NoRedirect)
        with opener.open(request, timeout=10) as response:
            body = response.read(1_000_001)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise DeployError("OIDC discovery redirected; provide its final HTTPS URL.") from exc
        raise DeployError(f"OIDC discovery returned HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DeployError(f"Could not retrieve OIDC discovery metadata: {exc}") from exc

    if len(body) > 1_000_000:
        raise DeployError("OIDC discovery document exceeded the 1 MB safety limit.")
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeployError("OIDC discovery did not return valid JSON.") from exc

    if not isinstance(document, dict):
        raise DeployError("OIDC discovery document must be a JSON object.")
    issuer, jwks_uri = document.get("issuer"), document.get("jwks_uri")
    issuer_parts = urlsplit(issuer) if isinstance(issuer, str) else None
    jwks_parts = urlsplit(jwks_uri) if isinstance(jwks_uri, str) else None
    if (
        issuer_parts is None
        or issuer_parts.scheme != "https"
        or not issuer_parts.hostname
        or (issuer_parts.scheme, issuer_parts.hostname, issuer_parts.port)
        != (parts.scheme, parts.hostname, parts.port)
    ):
        raise DeployError("OIDC metadata issuer must be HTTPS and match the discovery host.")
    if (
        jwks_parts is None
        or jwks_parts.scheme != "https"
        or not jwks_parts.hostname
        or jwks_parts.username
        or jwks_parts.password
        or jwks_parts.query
        or jwks_parts.fragment
    ):
        raise DeployError("OIDC metadata must contain a valid HTTPS jwks_uri.")
    return {"issuer": issuer, "jwks_uri": jwks_uri}


def replace_env_value(template: str, key: str, value: str) -> str:
    lines = template.splitlines()
    matches = [i for i, line in enumerate(lines) if line.startswith(f"{key}=")]
    if len(matches) != 1 or any(ch in value for ch in "\r\n"):
        raise DeployError(f"Could not safely set {key} in .env.example.")
    lines[matches[0]] = f"{key}={value}"
    return "\n".join(lines) + "\n"


def make_environment(discovery: dict[str, str], audience: str) -> str:
    if not audience or any(ch.isspace() or ord(ch) in (34, 35, 36, 39) for ch in audience):
        raise DeployError("Choose a simple API audience without whitespace or .env metacharacters.")
    try:
        template = ENV_EXAMPLE.read_text(encoding="utf-8")
        policy = json.loads(POLICY_DATA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployError(f"Could not read deployment defaults: {exc}") from exc
    revision = policy.get("paca", {}).get("meta", {}).get("revision")
    if not isinstance(revision, str):
        raise DeployError("OPA policy revision is missing from opa/data.json.")

    values = {
        "POSTGRES_PASSWORD": secrets.token_hex(32),
        "PACA_RUNTIME_PASSWORD": secrets.token_hex(32),
        "PACA_TENANT_CONTEXT_HMAC_KEY": secrets.token_hex(32),
        "PACA_EXPECTED_POLICY_REVISION": revision,
        "PACA_JWT_ISSUER": discovery["issuer"],
        "PACA_JWT_AUDIENCE": audience,
        "PACA_JWT_JWKS_URL": discovery["jwks_uri"],
        "PACA_JWT_TOKEN_USE_CLAIM": "token_use",
        "PACA_JWT_EXPECTED_TOKEN_USE": "access",
        "PACA_OPA_URL": "http://opa:8181",
        "PACA_API_ROUTES_JSON": "{}",
    }
    if len({values[key] for key in (
        "POSTGRES_PASSWORD", "PACA_RUNTIME_PASSWORD", "PACA_TENANT_CONTEXT_HMAC_KEY"
    )}) != 3:
        raise DeployError("Could not generate independent deployment secrets.")
    for key, value in values.items():
        template = replace_env_value(template, key, value)
    return template


def write_env(content: str) -> None:
    try:
        descriptor = os.open(ENV_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise DeployError(".env already exists; refusing to overwrite deployment secrets.") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            os.chmod(ENV_FILE, 0o600)
    except Exception:
        ENV_FILE.unlink(missing_ok=True)
        raise


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(ENV_FILE.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise DeployError(f"Invalid .env syntax on line {number}.")
        key, value = line.split("=", 1)
        if key in values:
            raise DeployError(f"Duplicate .env key: {key}.")
        values[key.strip()] = value.strip().strip("'").strip('"')
    return values


def validate_configuration(values: dict[str, str]) -> None:
    for key in ("POSTGRES_PASSWORD", "PACA_RUNTIME_PASSWORD"):
        if len(values.get(key, "")) < 32:
            raise DeployError(f"{key} must contain at least 32 characters.")
    if values["POSTGRES_PASSWORD"] == values["PACA_RUNTIME_PASSWORD"]:
        raise DeployError("Database administrator and runtime passwords must be different.")

    # Compose constructs this URL from the generated hexadecimal runtime password.
    values = dict(values)
    values["PACA_DATABASE_URL"] = (
        "postgresql://paca_runtime:"
        + values["PACA_RUNTIME_PASSWORD"]
        + "@database:5432/paca"
    )
    try:
        settings = Settings.from_env(values)
        policy = json.loads(POLICY_DATA.read_text(encoding="utf-8"))
    except (ConfigurationError, OSError, json.JSONDecodeError) as exc:
        raise DeployError(f"Deployment configuration is invalid: {exc}") from exc
    revision = policy.get("paca", {}).get("meta", {}).get("revision")
    if settings.expected_policy_revision != revision:
        raise DeployError("PACA_EXPECTED_POLICY_REVISION does not match opa/data.json.")


def compose(*arguments: str) -> None:
    command = [
        "docker", "compose", "--env-file", str(ENV_FILE), "-f", str(COMPOSE_FILE),
        *arguments,
    ]
    try:
        result = subprocess.run(command, cwd=SERVICE_DIR, check=False)
    except FileNotFoundError as exc:
        raise DeployError("Install Docker Engine/Desktop with Docker Compose v2 first.") from exc
    if result.returncode:
        raise DeployError(f"Docker Compose failed with exit code {result.returncode}.")


def check_ready() -> bool:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/readyz", timeout=5) as response:
            return json.loads(response.read(16_384)).get("status") == "ready"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


def _verify_api_request(
    opener: Any,
    base_url: str,
    method: str,
    path: str,
    token: str,
    payload: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    data = None
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(
        base_url + path, data=data, headers=headers, method=method
    )
    try:
        with opener.open(request, timeout=10) as response:
            status = response.status
            body = response.read(16_385)
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read(16_385)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DeployError(f"Deployment verification could not reach the API ({method} {path}).") from exc
    if len(body) > 16_384:
        raise DeployError(f"Deployment verification received an oversized response ({method} {path}).")
    if not body:
        return status, {}
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeployError(f"Deployment verification received invalid JSON ({method} {path}).") from exc
    if not isinstance(document, dict):
        raise DeployError(f"Deployment verification received an unexpected response ({method} {path}).")
    return status, document


def _expect_status(
    actual: tuple[int, dict[str, Any]],
    expected: int,
    method: str,
    path: str,
) -> dict[str, Any]:
    status, body = actual
    if status != expected:
        detail = body.get("detail")
        code = detail.get("code") if isinstance(detail, dict) else None
        suffix = f"; API code: {code}" if isinstance(code, str) and len(code) <= 128 else ""
        raise DeployError(
            f"Deployment verification expected HTTP {expected} for {method} {path}, "
            f"received HTTP {status}{suffix}."
        )
    return body


def verify_live_deployment(environment: dict[str, str] | None = None) -> None:
    values = os.environ if environment is None else environment
    required = (
        "PACA_VERIFY_OWNER_TOKEN",
        "PACA_VERIFY_SAME_TENANT_NONOWNER_TOKEN",
        "PACA_VERIFY_OTHER_TENANT_TOKEN",
        "PACA_VERIFY_RESOURCE_ID",
    )
    missing = [key for key in required if not values.get(key)]
    if missing:
        raise DeployError(
            "Set the three PACA_VERIFY_* access-token variables and PACA_VERIFY_RESOURCE_ID; "
            "tokens are read only from the environment, never command-line arguments."
        )
    for key in required[:3]:
        token = values[key]
        if len(token) > 16_384 or any(character.isspace() for character in token):
            raise DeployError(f"{key} is not a valid bearer-token value.")

    resource_id = values["PACA_VERIFY_RESOURCE_ID"]
    if (
        not resource_id.strip()
        or len(resource_id) > 256
        or any(ord(character) < 32 or character == "\x00" for character in resource_id)
    ):
        raise DeployError("PACA_VERIFY_RESOURCE_ID must be a non-empty safe resource identifier.")

    api_url = values.get("PACA_VERIFY_API_URL", "http://127.0.0.1:8000").rstrip("/")
    parts = urlsplit(api_url)
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise DeployError("PACA_VERIFY_API_URL must be an origin-only HTTP(S) URL.")
    try:
        loopback = ipaddress.ip_address(parts.hostname).is_loopback or parts.hostname == "localhost"
    except ValueError:
        loopback = parts.hostname == "localhost"
    if parts.scheme == "http" and not loopback:
        raise DeployError("Use HTTPS for a non-loopback PACA_VERIFY_API_URL.")

    expected_revision = values.get("PACA_VERIFY_EXPECTED_POLICY_REVISION")
    if not expected_revision and ENV_FILE.is_file():
        expected_revision = read_env().get("PACA_EXPECTED_POLICY_REVISION")
    base_url = api_url
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    authorize_path = "/v1/authorizations"
    owner_token = values["PACA_VERIFY_OWNER_TOKEN"]
    same_tenant_token = values["PACA_VERIFY_SAME_TENANT_NONOWNER_TOKEN"]
    other_tenant_token = values["PACA_VERIFY_OTHER_TENANT_TOKEN"]
    operation = {"action": "file.read", "resource_id": resource_id, "arguments": {}}

    authorized = _expect_status(
        _verify_api_request(opener, base_url, "POST", authorize_path, owner_token, operation),
        201,
        "POST",
        authorize_path,
    )
    permit_id = authorized.get("permit_id")
    try:
        uuid.UUID(str(permit_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise DeployError("Deployment verification received an invalid permit identifier.") from exc
    policy_revision = authorized.get("policy_revision")
    if not isinstance(policy_revision, str) or not policy_revision:
        raise DeployError("Authorization response did not include a policy revision.")
    if expected_revision and policy_revision != expected_revision:
        raise DeployError("Live authorization policy revision does not match the deployment configuration.")

    idempotency_key = "paca-smoke-" + secrets.token_hex(16)
    execute_path = "/v1/executions"
    execution = _expect_status(
        _verify_api_request(
            opener,
            base_url,
            "POST",
            execute_path,
            owner_token,
            {**operation, "permit_id": permit_id},
            idempotency_key,
        ),
        200,
        "POST",
        execute_path,
    )
    result = execution.get("result")
    execution_id = execution.get("execution_id")
    if execution.get("status") != "succeeded" or not isinstance(result, dict):
        raise DeployError("The permitted file.read operation did not complete successfully.")
    if not isinstance(result.get("content"), str):
        raise DeployError("The permitted file.read adapter did not return file content.")
    try:
        uuid.UUID(str(execution_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise DeployError("Execution response did not include a valid execution identifier.") from exc

    status_path = "/v1/executions/" + str(execution_id)
    owner_status = _expect_status(
        _verify_api_request(opener, base_url, "GET", status_path, owner_token),
        200,
        "GET",
        status_path,
    )
    if owner_status.get("status") != "succeeded":
        raise DeployError("The owner could not retrieve the completed execution status.")

    _expect_status(
        _verify_api_request(
            opener, base_url, "POST", authorize_path, same_tenant_token, operation
        ),
        403,
        "POST",
        authorize_path,
    )
    _expect_status(
        _verify_api_request(
            opener, base_url, "POST", authorize_path, other_tenant_token, operation
        ),
        404,
        "POST",
        authorize_path,
    )
    _expect_status(
        _verify_api_request(opener, base_url, "GET", status_path, other_tenant_token),
        404,
        "GET",
        status_path,
    )
    print(
        "End-to-end deployment verification passed: owner read/execution, persisted status, "
        "same-tenant owner denial, and cross-tenant resource/status isolation."
    )


def check() -> None:
    if not ENV_FILE.is_file():
        raise DeployError("No .env found. Run: python paca_deploy.py init")
    try:
        values = read_env()
    except OSError as exc:
        raise DeployError(f"Could not read .env: {exc}") from exc
    validate_configuration(values)
    if os.name == "posix" and stat.S_IMODE(ENV_FILE.stat().st_mode) & 0o077:
        raise DeployError("Restrict .env permissions with: chmod 600 .env")
    compose("config", "--quiet")
    print("Configuration valid; no services were started.")


def init(args: argparse.Namespace) -> None:
    if ENV_FILE.exists():
        raise DeployError(".env already exists; refusing to overwrite it.")
    discovery_url = args.discovery_url
    audience = args.audience
    if not discovery_url and sys.stdin.isatty():
        discovery_url = input("HTTPS OIDC discovery URL: ").strip()
    if not audience and sys.stdin.isatty():
        audience = input("API audience [paca-api]: ").strip() or "paca-api"
    if not discovery_url or not audience:
        raise DeployError("Provide --discovery-url and --audience, or run init interactively.")
    write_env(make_environment(oidc_metadata(discovery_url), audience))
    print("Created .env with separate random secrets and your provider's OIDC metadata.")
    print("Next: python paca_deploy.py check")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PACA++ production-service setup and operations.")
    commands = parser.add_subparsers(dest="command", required=True)
    init_parser = commands.add_parser("init", help="Create .env from HTTPS OIDC metadata.")
    init_parser.add_argument("--discovery-url")
    init_parser.add_argument("--audience")
    for name in ("check", "up", "status", "logs", "down"):
        commands.add_parser(name)
    commands.add_parser(
        "verify",
        help="Verify a live deployment using three pre-obtained test access tokens and a provisioned file.",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            init(args)
        elif args.command == "check":
            check()
        elif args.command == "up":
            check()
            compose("up", "--build", "--detach", "--wait")
            if not check_ready():
                raise DeployError("API did not pass /readyz; inspect: python paca_deploy.py logs")
            print("PACA++ is ready at http://127.0.0.1:8000 (loopback only).")
        elif args.command == "status":
            compose("ps")
            print("API readiness: " + ("ready" if check_ready() else "not ready"))
        elif args.command == "logs":
            compose("logs", "--tail", "100", "--follow")
        elif args.command == "down":
            compose("down")
            print("Services stopped; named database and file volumes were preserved.")
        elif args.command == "verify":
            verify_live_deployment()
        return 0
    except DeployError as exc:
        print(f"Deployment error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
