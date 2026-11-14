from __future__ import annotations

import logging
from pathlib import Path

from .adapters import (
    AdapterRouter,
    EffectRejected,
    HttpAPIAdapter,
    SandboxedFileAdapter,
    ToolRegistryAdapter,
)
from .app import create_app
from .auth import JWTAuthenticator
from .config import Settings
from .opa import OPAClient
from .store import PostgresStore
from .service_tokens import ClientCredentialsTokenProvider

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

settings = Settings.from_env()
store = PostgresStore(
    settings.database_url,
    settings.tenant_context_hmac_key,
    settings.tenant_context_key_id,
)
opa_token_provider = (
    ClientCredentialsTokenProvider(
        settings.opa_oauth_token_url or "",
        settings.opa_oauth_client_id or "",
        settings.opa_oauth_client_secret or "",
        scope=settings.opa_oauth_scope,
        timeout_seconds=settings.opa_timeout_seconds,
    )
    if settings.opa_oauth_token_url
    else None
)
opa = OPAClient(
    settings.opa_url,
    settings.opa_decision_path,
    settings.expected_policy_revision,
    settings.opa_timeout_seconds,
    bearer_token=settings.opa_bearer_token,
    token_provider=opa_token_provider,
)
authenticator = JWTAuthenticator(
    settings.jwt_issuer,
    settings.jwt_audience,
    settings.jwt_jwks_url,
    settings.jwt_timeout_seconds,
    token_use_claim=settings.jwt_token_use_claim,
    expected_token_use=settings.jwt_expected_token_use,
)

adapters = []
if settings.api_routes:
    api_token_provider = (
        ClientCredentialsTokenProvider(
            settings.api_oauth_token_url or "",
            settings.api_oauth_client_id or "",
            settings.api_oauth_client_secret or "",
            scope=settings.api_oauth_scope,
            timeout_seconds=settings.execution_timeout_seconds,
        )
        if settings.api_oauth_token_url
        else None
    )
    adapters.append(
        HttpAPIAdapter(
            settings.api_base_url or "",
            settings.api_routes,
            settings.execution_timeout_seconds,
            bearer_token=settings.api_bearer_token,
            token_provider=api_token_provider,
        )
    )

tools = ToolRegistryAdapter()


def word_count_tool(tool_input: dict, request: object) -> dict:
    """Small read-only example tool. Replace or extend only with trusted handlers."""
    value = tool_input.get("text")
    if not isinstance(value, str) or len(value.encode("utf-8")) > 100_000:
        raise EffectRejected("word_count_requires_text_under_100kb")
    return {"word_count": len(value.split()), "character_count": len(value)}


tools.register("text.word_count", word_count_tool)
adapters.append(tools)

if settings.file_root:
    root = Path(settings.file_root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    adapters.append(SandboxedFileAdapter(str(root)))

if settings.file_root and set(settings.api_routes).intersection({"file.read", "file.create"}):
    raise RuntimeError("ambiguous_adapter_configuration_for_file_actions")
if "tool.invoke" in settings.api_routes:
    raise RuntimeError("tool_invoke_cannot_be_configured_as_an_http_route")

app = create_app(
    settings=settings,
    store=store,
    opa=opa,
    authenticator=authenticator,
    adapter_router=AdapterRouter(adapters),
)
