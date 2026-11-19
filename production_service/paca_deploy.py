from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SERVICE_DIR = Path(__file__).resolve().parent
ENV_EXAMPLE = SERVICE_DIR / ".env.example"
ENV_FILE = SERVICE_DIR / ".env"
COMPOSE_FILE = SERVICE_DIR / "compose.yaml"
POLICY_DATA = SERVICE_DIR / "opa" / "data.json"
_SECRET_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class DeployError(RuntimeError):
    """A safe, actionable deployment setup or orchestration error."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, fp: Any, code: int, msg: str,
                         headers: Any, new_url: str) -> None:
        return None


def _validate_https_url(value: str, label: str) -> str:
    if not isinstance(value, str) or not value or any(ch.isspace() for ch in value):
        raise DeployError(f"{label} must be a valid HTTPS URL.")
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise DeployError(
            f"{label} must be an absolute HTTPS URL without credentials, query, or fragment."
        )
    return value


def fetch_oidc_metadata(discovery_url: str) -> dict[str, str]:
    """Fetch trusted OIDC discovery metadata without following redirects."""
    if (
        not isinstance(discovery_url, str)
        or not discovery_url
        or any(ch.isspace() for ch in discovery_url)
    ):
        raise DeployError("The OIDC discovery address must be a valid HTTPS URL.")
    parts = urlsplit(discovery_url)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.fragment
    ):
        raise DeployError("The OIDC discovery address must use HTTPS and contain no credentials.")

    request = urllib.request.Request(
        discovery_url,
        headers={"Accept": "application/json", "User-Agent": "PACA-Deployment-Setup/1.0"},
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=10) as response:
            body = response.read(1_000_001)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise DeployError(
                "The OIDC discovery endpoint redirected. Use its final HTTPS address directly."
            ) from exc
        raise DeployError(f"OIDC discovery returned HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DeployError(f"Could not retrieve OIDC discovery metadata: {exc}") from exc

    if len(body) > 1_000_000:
        raise DeployError("The OIDC discovery document exceeded the 1 MB safety limit.")
    try:
        metadata = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeployError("The OIDC discovery endpoint did not return valid JSON.") from exc
    if not isinstance(metadata, dict):
        raise DeployError("The OIDC discovery document must be a JSON object.")

    issuer = metadata.get("issuer")
    jwks_uri = metadata.get("jwks_uri")
    if not isinstance(issuer, str) or not isinstance(jwks_uri, str):
        raise DeployError("The discovery document must contain string issuer and jwks_uri fields.")
    _validate_https_url(issuer, "The discovered issuer")
    _validate_https_url(jwks_uri, "The discovered JWKS address")
    return {"issuer": issuer, "jwks_uri": jwks_uri}


def parse_env_text(content: str) -> dict[str, str]:
    """Parse the simple KEY=value format used in PACA's generated .env file."""
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise DeployError(f"Invalid .env syntax on line {line_number}.")
        key, value = line.split("=", 1)
        key = key.strip()
        if not _ENV_KEY_RE.fullmatch(key):
            raise DeployError(f"Invalid .env key on line {line_number}.")
        if key in values:
            raise DeployError(f"Duplicate .env key: {key}.")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def _replace_env_value(content: str, key: str, value: str) -> str:
    pattern = re.compile(rf"(?m)^{re.escape(key)}=.*$")
    replacement = f"{key}={value}"
    updated, count = pattern.subn(lambda _match: replacement, content)
    if count != 1:
        raise DeployError(f"Expected exactly one {key} entry in .env.example; found {count}.")
    return updated


def render_environment(
    template: str,
    metadata: dict[str, str],
    audience: str,
    policy_revision: str,
    secret_factory: Any = secrets.token_hex,
) -> str:
    """Render a local .env with three independently generated secrets."""
    if not isinstance(audience, str) or not audience or any(ch.isspace() for ch in audience):
        raise DeployError("The API audience must be a non-empty value without whitespace.")
    if any(ch in audience for ch in "#'\""):
        raise DeployError("The API audience contains a character unsafe for a Compose .env value.")
    issuer = _validate_https_url(metadata.get("issuer", ""), "The discovered issuer")
    jwks_uri = _validate_https_url(metadata.get("jwks_uri", ""), "The discovered JWKS address")
    if not policy_revision or any(ch.isspace() for ch in policy_revision):
        raise DeployError("The repository policy revision is missing or invalid.")

    generated = [secret_factory(32) for _ in range(3)]
    if any(not _SECRET_RE.fullmatch(secret) for secret in generated):
        raise DeployError("The secret generator did not return three 32-byte hexadecimal secrets.")
    if len(set(generated)) != 3:
        raise DeployError("Secret generation did not produce independent credential values.")

    values = {
        "POSTGRES_PASSWORD": generated[0],
        "PACA_RUNTIME_PASSWORD": generated[1],
        "PACA_TENANT_CONTEXT_HMAC_KEY": generated[2],
        "PACA_EXPECTED_POLICY_REVISION": policy_revision,
        "PACA_JWT_ISSUER": issuer,
        "PACA_JWT_AUDIENCE": audience,
        "PACA_JWT_JWKS_URL": jwks_uri,
        "PACA_JWT_TOKEN_USE_CLAIM": "token_use",
        "PACA_JWT_EXPECTED_TOKEN_USE": "access",
        "PACA_OPA_URL": "http://opa:8181",
        "PACA_API_ROUTES_JSON": "{}",
    }
    for key, value in values.items():
        if any(ch in value for ch in "\r\n"):
            raise DeployError(f"Refusing a newline in {key}.")
        template = _replace_env_value(template, key, value)
    return template


def write_new_env(path: Path, content: str) -> None:
    """Create the secret file exclusively with owner-only permissions where supported."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise DeployError(f"{path.name} already exists; refusing to overwrite secrets.") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            os.chmod(path, 0o600)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


def validate_environment(values: dict[str, str], policy_data: dict[str, Any]) -> None:
    required = (
        "POSTGRES_PASSWORD",
        "PACA_RUNTIME_PASSWORD",
        "PACA_TENANT_CONTEXT_HMAC_KEY",
        "PACA_EXPECTED_POLICY_REVISION",
        "PACA_JWT_ISSUER",
        "PACA_JWT_AUDIENCE",
        "PACA_JWT_JWKS_URL",
        "PACA_API_ROUTES_JSON",
        "PACA_OPA_URL",
    )
    missing = [key for key in required if not values.get(key)]
    if missing:
        raise DeployError("Missing required .env values: " + ", ".join(missing))

    for key in ("POSTGRES_PASSWORD", "PACA_RUNTIME_PASSWORD"):
        value = values[key]
        if len(value) < 32 or any(ch.isspace() for ch in value):
            raise DeployError(f"{key} must be at least 32 characters and contain no whitespace.")
    for key in ("POSTGRES_PASSWORD", "PACA_RUNTIME_PASSWORD"):
        if values[key] == values["PACA_TENANT_CONTEXT_HMAC_KEY"]:
            raise DeployError("Database credentials and the tenant-context HMAC key must be distinct.")
    if values["POSTGRES_PASSWORD"] == values["PACA_RUNTIME_PASSWORD"]:
        raise DeployError("POSTGRES_PASSWORD and PACA_RUNTIME_PASSWORD must be different.")
    if not _SECRET_RE.fullmatch(values["PACA_TENANT_CONTEXT_HMAC_KEY"]):
        raise DeployError("PACA_TENANT_CONTEXT_HMAC_KEY must be exactly 64 hexadecimal characters.")

    _validate_https_url(values["PACA_JWT_ISSUER"], "PACA_JWT_ISSUER")
    _validate_https_url(values["PACA_JWT_JWKS_URL"], "PACA_JWT_JWKS_URL")
    audience = values["PACA_JWT_AUDIENCE"]
    if not audience or any(ch.isspace() for ch in audience):
        raise DeployError("PACA_JWT_AUDIENCE must be a non-empty value without whitespace.")

    expected_use = values.get("PACA_JWT_EXPECTED_TOKEN_USE", "access")
    token_use_claim = values.get("PACA_JWT_TOKEN_USE_CLAIM", "token_use")
    if not expected_use or not token_use_claim:
        raise DeployError("The access-token purpose claim configuration must not be empty.")

    revision = policy_data.get("paca", {}).get("meta", {}).get("revision")
    if not isinstance(revision, str) or values["PACA_EXPECTED_POLICY_REVISION"] != revision:
        raise DeployError(
            "PACA_EXPECTED_POLICY_REVISION does not match production_service/opa/data.json."
        )

    try:
        routes = json.loads(values["PACA_API_ROUTES_JSON"])
    except json.JSONDecodeError as exc:
        raise DeployError("PACA_API_ROUTES_JSON must contain valid JSON.") from exc
    if not isinstance(routes, dict):
        raise DeployError("PACA_API_ROUTES_JSON must be a JSON object.")

    opa_url = values["PACA_OPA_URL"]
    opa_parts = urlsplit(opa_url)
    if opa_parts.scheme not in {"http", "https"} or not opa_parts.hostname:
        raise DeployError("PACA_OPA_URL must be an absolute HTTP(S) URL.")
    local_hosts = {"localhost", "127.0.0.1", "::1", "opa"}
    remote_opa = opa_parts.hostname.lower().rstrip(".") not in local_hosts
    if remote_opa and (
        opa_parts.scheme != "https" or not values.get("PACA_OPA_BEARER_TOKEN")
    ):
        raise DeployError("Remote OPA requires HTTPS and PACA_OPA_BEARER_TOKEN.")

    api_base = values.get("PACA_API_BASE_URL", "").strip()
    if routes and not api_base:
        raise DeployError("PACA_API_BASE_URL is required when API routes are configured.")
    if api_base:
        api_parts = urlsplit(api_base)
        if api_parts.scheme not in {"http", "https"} or not api_parts.hostname:
            raise DeployError("PACA_API_BASE_URL must be an absolute HTTP(S) URL.")
        remote_api = api_parts.hostname.lower().rstrip(".") not in {
            "localhost", "127.0.0.1", "::1"
        }
        if remote_api and (
            api_parts.scheme != "https" or not values.get("PACA_API_BEARER_TOKEN")
        ):
            raise DeployError("Remote effect routes require HTTPS and PACA_API_BEARER_TOKEN.")


def compose_command(*arguments: str) -> list[str]:
    return [
        "docker", "compose", "--env-file", str(ENV_FILE), "-f", str(COMPOSE_FILE),
        *arguments,
    ]


def run_compose(*arguments: str) -> int:
    try:
        result = subprocess.run(compose_command(*arguments), cwd=SERVICE_DIR, check=False)
    except FileNotFoundError as exc:
        raise DeployError(
            "Docker was not found. Install Docker Desktop or Docker Engine with Compose v2."
        ) from exc
    if result.returncode != 0:
        raise DeployError(f"Docker Compose failed with exit code {result.returncode}.")
    return result.returncode


def check_configuration() -> None:
    if not ENV_FILE.is_file():
        raise DeployError("No production_service/.env found. Run: python paca_deploy.py init")
    try:
        values = parse_env_text(ENV_FILE.read_text(encoding="utf-8"))
        policy_data = json.loads(POLICY_DATA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployError(f"Could not read deployment configuration: {exc}") from exc
    validate_environment(values, policy_data)

    if os.name == "posix":
        permissions = stat.S_IMODE(ENV_FILE.stat().st_mode)
        if permissions & 0o077:
            raise DeployError(
                "The .env file is accessible by group/other users. Run: chmod 600 .env"
            )

    run_compose("config", "--quiet")
    print("Configuration valid. No services were started.")


def initialize(args: argparse.Namespace) -> None:
    if ENV_FILE.exists():
        raise DeployError("production_service/.env already exists; refusing to overwrite it.")

    discovery_url = args.discovery_url
    audience = args.audience
    if not discovery_url:
        if not sys.stdin.isatty():
            raise DeployError(
                "Provide --discovery-url and --audience when running without an interactive terminal."
            )
        discovery_url = input(
            "OIDC discovery URL (the provider's /.well-known/openid-configuration): "
        ).strip()
    if not audience and sys.stdin.isatty():
        audience = input("API audience [paca-api]: ").strip() or "paca-api"
    if not audience:
        raise DeployError("Provide the API audience with --audience.")

    metadata = fetch_oidc_metadata(discovery_url)
    try:
        template = ENV_EXAMPLE.read_text(encoding="utf-8")
        policy_data = json.loads(POLICY_DATA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployError(f"Could not read repository deployment defaults: {exc}") from exc
    revision = policy_data.get("paca", {}).get("meta", {}).get("revision")
    if not isinstance(revision, str):
        raise DeployError("The OPA policy revision is missing from opa/data.json.")

    content = render_environment(template, metadata, audience, revision)
    write_new_env(ENV_FILE, content)
    print("Created production_service/.env with three independently generated secrets.")
    print("The file was created with owner-only permissions where supported.")
    print("Next: python paca_deploy.py check")


def check_endpoint(path: str) -> bool:
    url = f"http://127.0.0.1:8000{path}"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read(16_384))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("status") == (
        "alive" if path == "/healthz" else "ready"
    )


def start_services() -> None:
    check_configuration()
    run_compose("up", "--build", "--detach", "--wait")
    if not check_endpoint("/readyz"):
        raise DeployError(
            "Compose started, but PACA++ did not pass /readyz. Inspect: python paca_deploy.py logs"
        )
    print("PACA++ is ready at http://127.0.0.1:8000.")
    print("The API is bound to loopback; it is not exposed directly to the public internet.")


def show_status() -> None:
    run_compose("ps")
    health = check_endpoint("/healthz")
    ready = check_endpoint("/readyz")
    print(f"API liveness: {'alive' if health else 'unavailable'}")
    print(f"API readiness: {'ready' if ready else 'not ready'}")
    if not ready:
        raise DeployError("The service is not ready. Inspect logs and deployment configuration.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Set up and operate the PACA++ production-service Compose deployment."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser(
        "init", help="Create a local .env using real OIDC discovery metadata and random secrets."
    )
    init_parser.add_argument("--discovery-url", help="HTTPS OIDC discovery document URL.")
    init_parser.add_argument("--audience", help="Audience that the identity provider issues for PACA.")

    commands.add_parser("check", help="Validate .env, policy revision, and Compose configuration.")
    commands.add_parser("up", help="Validate configuration, build, start, and wait for readiness.")
    commands.add_parser("status", help="Show container and API readiness status.")
    commands.add_parser("logs", help="Follow recent service logs.")
    commands.add_parser("down", help="Stop services without deleting persistent volumes.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            initialize(args)
        elif args.command == "check":
            check_configuration()
        elif args.command == "up":
            start_services()
        elif args.command == "status":
            show_status()
        elif args.command == "logs":
            run_compose("logs", "--tail", "100", "--follow")
        elif args.command == "down":
            run_compose("down")
            print("Services stopped. Persistent PostgreSQL and file volumes were preserved.")
        return 0
    except DeployError as exc:
        print(f"Deployment error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
