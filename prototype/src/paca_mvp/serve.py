"""Configured PACA++ gateway launcher.

This service deliberately requires an application-specific trusted context provider.
It does not invent a user/resource database schema or trust authorization attributes
submitted by callers.
"""
from __future__ import annotations

import importlib
import os
import sys

from .durable import PostgresOperationStore
from .gateway import HTTPJsonActionAdapter, ProtectedToolGateway
from .http_api import make_server
from .identity import JWTAuthenticator
from .opa import OPAPolicyDecisionPoint


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError("required environment variable is missing: " + name)
    return value


def _load_factory(spec: str):
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name or not attribute:
        raise RuntimeError("PACA_CONTEXT_PROVIDER must use module.path:factory_name syntax")
    module = importlib.import_module(module_name)
    factory = getattr(module, attribute, None)
    if not callable(factory):
        raise RuntimeError("configured trusted context factory is not callable")
    provider = factory()
    if not callable(getattr(provider, "load", None)):
        raise RuntimeError("context provider must implement load(principal, action, resource, arguments)")
    return provider


def main() -> int:
    issuer = _required_env("PACA_OIDC_ISSUER")
    audience = _required_env("PACA_OIDC_AUDIENCE")
    jwks_url = _required_env("PACA_OIDC_JWKS_URL")
    database_url = _required_env("PACA_POSTGRES_DSN")
    context_factory = _required_env("PACA_CONTEXT_PROVIDER")
    downstream_endpoint = _required_env("PACA_FILE_READ_ENDPOINT")
    service_token = _required_env("PACA_DOWNSTREAM_SERVICE_TOKEN")

    authenticator = JWTAuthenticator(issuer=issuer, audience=audience, jwks_url=jwks_url)
    context_provider = _load_factory(context_factory)
    opa = OPAPolicyDecisionPoint(
        base_url=os.environ.get("PACA_OPA_BASE_URL", "http://127.0.0.1:8181"),
        decision_path=os.environ.get("PACA_OPA_DECISION_PATH", "paca/authz/decision"),
        timeout_seconds=float(os.environ.get("PACA_OPA_TIMEOUT_SECONDS", "1.5")),
        bearer_token=os.environ.get("PACA_OPA_BEARER_TOKEN") or None,
    )
    store = PostgresOperationStore(database_url)
    gateway = ProtectedToolGateway(
        authenticator=authenticator,
        context_provider=context_provider,
        policy_decision_point=opa,
        operation_store=store,
        permit_ttl_seconds=float(os.environ.get("PACA_PERMIT_TTL_SECONDS", "30")),
    )
    adapter = HTTPJsonActionAdapter(
        downstream_endpoint,
        service_token_provider=lambda: os.environ.get("PACA_DOWNSTREAM_SERVICE_TOKEN", ""),
        timeout_seconds=float(os.environ.get("PACA_DOWNSTREAM_TIMEOUT_SECONDS", "5")),
    )
    gateway.register_action("file.read", adapter)

    host = os.environ.get("PACA_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("PACA_BIND_PORT", "8080"))
    server = make_server(gateway, host=host, port=port)
    print("PACA++ gateway listening on " + host + ":" + str(port))
    print("Only the registered file.read action is available in this example launcher.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
