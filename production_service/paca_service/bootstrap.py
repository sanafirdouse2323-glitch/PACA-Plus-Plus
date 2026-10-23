from __future__ import annotations

import logging
from pathlib import Path

from .adapters import AdapterRouter, HttpAPIAdapter, SandboxedFileAdapter, ToolRegistryAdapter
from .app import create_app
from .auth import JWTAuthenticator
from .config import Settings
from .opa import OPAClient
from .store import PostgresStore
from .adapters import EffectRejected


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

settings = Settings.from_env()
store = PostgresStore(settings.database_url)
opa = OPAClient(
    settings.opa_url,
    settings.opa_decision_path,
    settings.expected_policy_revision,
    settings.opa_timeout_seconds,
)
authenticator = JWTAuthenticator(
    settings.jwt_issuer,
    settings.jwt_audience,
    settings.jwt_jwks_url,
    settings.jwt_timeout_seconds,
)

adapters = []
if settings.api_routes:
    adapters.append(
        HttpAPIAdapter(
            settings.api_base_url or "",
            settings.api_routes,
            settings.execution_timeout_seconds,
            bearer_token=settings.api_bearer_token,
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
