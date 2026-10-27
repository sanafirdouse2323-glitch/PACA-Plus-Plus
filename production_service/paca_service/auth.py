from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import jwt
from jwt.exceptions import InvalidTokenError, PyJWKClientConnectionError, PyJWKClientError


class AuthenticationError(ValueError):
    """A presented bearer token is invalid or does not meet this service's claim contract."""


class IdentityProviderUnavailable(RuntimeError):
    """The configured JWKS endpoint could not be reached to verify a token."""


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    roles: tuple[str, ...]
    scopes: tuple[str, ...]
    tools: tuple[str, ...]
    token_id: str | None = None


class JWTAuthenticator:
    """Verify access tokens against one configured issuer and audience.

    The accepted algorithm is deliberately pinned to RS256. Claims are read only
    after signature, issuer, audience, expiry, issue-time and required-claim checks.
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        timeout_seconds: float = 5.0,
        jwks_client: Any | None = None,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.jwks_client = jwks_client or jwt.PyJWKClient(
            jwks_url,
            cache_jwk_set=True,
            lifespan=300,
            timeout=timeout_seconds,
            cooldown_duration=30,
        )

    def authenticate(self, token: str) -> Principal:
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise AuthenticationError("invalid_bearer_token")
        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
                leeway=2,
                options={"require": ["sub", "exp", "iat", "iss", "aud", "tenant_id"]},
            )
        except PyJWKClientConnectionError as exc:
            raise IdentityProviderUnavailable("jwks_unavailable") from exc
        except (InvalidTokenError, PyJWKClientError, TypeError, ValueError) as exc:
            raise AuthenticationError("invalid_bearer_token") from exc

        subject = claims.get("sub")
        tenant_id = claims.get("tenant_id")
        if not isinstance(subject, str) or not subject.strip():
            raise AuthenticationError("invalid_subject")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise AuthenticationError("invalid_tenant_claim")

        roles = self._string_list(claims.get("roles", []), "roles")
        tools = self._string_list(claims.get("tools", []), "tools")
        raw_scopes = claims.get("scopes")
        if raw_scopes is None:
            raw_scopes = claims.get("scope", "")
        if isinstance(raw_scopes, str):
            scopes = tuple(sorted(set(raw_scopes.split())))
        else:
            scopes = self._string_list(raw_scopes, "scopes")
        return Principal(
            subject=subject,
            tenant_id=tenant_id,
            roles=roles,
            scopes=scopes,
            tools=tools,
            token_id=claims.get("jti") if isinstance(claims.get("jti"), str) else None,
        )

    @staticmethod
    def _string_list(value: Any, claim_name: str) -> tuple[str, ...]:
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item.strip() or len(item) > 128
            for item in value
        ):
            raise AuthenticationError(f"invalid_{claim_name}_claim")
        return tuple(sorted(set(value)))
