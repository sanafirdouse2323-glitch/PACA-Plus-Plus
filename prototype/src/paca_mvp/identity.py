"""Authentication and trusted authorization-context interfaces.

JWT verification uses PyJWT with a pinned algorithm allow-list, issuer, audience,
and required claims. Authorization attributes are loaded separately from trusted
server-side sources; client-supplied role/resource/context fields are not accepted.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlparse


class AuthenticationError(RuntimeError):
    """Authentication was absent, malformed, expired, or could not be verified."""


class ContextRetrievalError(RuntimeError):
    """Trusted authorization attributes could not be retrieved safely."""


def _json_copy(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ContextRetrievalError("authorization context must be finite JSON") from exc


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    subject: str
    issuer: str
    claims: Mapping[str, Any]

    @property
    def storage_id(self) -> str:
        """Stable pseudonymous key for durable state, scoped to this issuer+subject pair."""
        material = json.dumps(
            [self.issuer, self.subject], separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return "oidc:" + hashlib.sha256(material).hexdigest()

    def opa_identity(self) -> dict[str, str]:
        """Return an issuer-scoped identity; do not equate raw OIDC subject with an app user.

        Ownership must use trusted user_id returned by the context provider after looking
        up this issuer+subject pair in the application's identity mapping. The OIDC sub
        claim is retained as subject for traceability only.
        """
        return {"id": self.storage_id, "issuer": self.issuer, "subject": self.subject}


class JWTAuthenticator:
    """OIDC/JWT bearer authenticator backed by a JWKS endpoint.

    The issuer and audience must match the identity provider configuration used by
    the application. By default, only RS256 tokens are accepted. Tests may inject
    key_resolver for a controlled, local signing key.
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str | None = None,
        algorithms: tuple[str, ...] = ("RS256",),
        leeway_seconds: int = 0,
        key_resolver: Callable[[str], Any] | None = None,
    ) -> None:
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError("issuer is required")
        issuer_url = urlparse(issuer)
        if (issuer_url.scheme != "https" or not issuer_url.hostname
                or issuer_url.username or issuer_url.password or issuer_url.query or issuer_url.fragment):
            raise ValueError("issuer must be a clean HTTPS URL")
        if not isinstance(audience, str) or not audience.strip():
            raise ValueError("audience is required")
        if not algorithms or any(a not in {"RS256", "RS384", "RS512", "ES256", "ES384"} for a in algorithms):
            raise ValueError("Only an explicit asymmetric JWT algorithm allow-list is supported")
        if leeway_seconds < 0:
            raise ValueError("leeway_seconds must not be negative")
        if key_resolver is None:
            if not jwks_url:
                raise ValueError("jwks_url is required when no key_resolver is injected")
            parsed = urlparse(jwks_url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise ValueError("JWKS URL must use HTTPS")
        try:
            import jwt
        except ImportError as exc:
            raise RuntimeError("Install the production extra: pip install -e '.[production]'") from exc
        self._jwt = jwt
        self.issuer = issuer
        self.audience = audience
        self.algorithms = tuple(algorithms)
        self.leeway_seconds = leeway_seconds
        self._key_resolver = key_resolver
        self._jwks_client = None
        if key_resolver is None:
            try:
                self._jwks_client = jwt.PyJWKClient(jwks_url, timeout=3, cache_jwk_set=True)
            except Exception as exc:
                raise AuthenticationError("could not initialize JWKS client") from exc

    def authenticate(self, authorization_header: str | None) -> AuthenticatedPrincipal:
        if not isinstance(authorization_header, str):
            raise AuthenticationError("missing_bearer_token")
        parts = authorization_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
            raise AuthenticationError("invalid_authorization_header")
        token = parts[1]
        if len(token) > 16_384:
            raise AuthenticationError("token_too_large")
        try:
            if self._key_resolver is not None:
                signing_key = self._key_resolver(token)
            else:
                signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
            claims = self._jwt.decode(
                token,
                signing_key,
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway_seconds,
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
            if not isinstance(claims, dict):
                raise AuthenticationError("invalid_token_claims")
            subject, issuer = claims.get("sub"), claims.get("iss")
            if (not isinstance(subject, str) or not subject.strip() or len(subject) > 512
                    or any(ord(character) < 0x20 or ord(character) == 0x7f for character in subject)):
                raise AuthenticationError("invalid_subject")
            if issuer != self.issuer:
                raise AuthenticationError("invalid_issuer")
            copied = _json_copy(claims)
            return AuthenticatedPrincipal(subject, issuer, copied)
        except AuthenticationError:
            raise
        except Exception as exc:
            # Keep the reason generic: decoder errors can reveal token validation detail.
            raise AuthenticationError("token_verification_failed") from exc


@dataclass(frozen=True)
class TrustedAuthorizationContext:
    subject_attributes: Mapping[str, Any]
    resource_attributes: Mapping[str, Any]
    environment: Mapping[str, Any]


class AuthorizationContextProvider(Protocol):
    def load(
        self, principal: AuthenticatedPrincipal, action: str, resource: str,
        arguments: Mapping[str, Any],
    ) -> TrustedAuthorizationContext: ...


class CallbackContextProvider:
    """Resolve subject/resource/environment from trusted application data accessors.

    The callbacks should query authoritative storage (for example, the application's
    user and resource tables). Do not wire these callbacks to request-supplied claims.
    """

    def __init__(
        self,
        subject_lookup: Callable[[AuthenticatedPrincipal], Mapping[str, Any]],
        resource_lookup: Callable[[AuthenticatedPrincipal, str, str, Mapping[str, Any]], Mapping[str, Any]],
        environment_lookup: Callable[[AuthenticatedPrincipal, str, str], Mapping[str, Any]] | None = None,
    ) -> None:
        self.subject_lookup = subject_lookup
        self.resource_lookup = resource_lookup
        self.environment_lookup = environment_lookup or (lambda _p, _a, _r: {})

    def load(
        self, principal: AuthenticatedPrincipal, action: str, resource: str,
        arguments: Mapping[str, Any],
    ) -> TrustedAuthorizationContext:
        try:
            subject = self.subject_lookup(principal)
            resource_attrs = self.resource_lookup(principal, action, resource, arguments)
            environment = self.environment_lookup(principal, action, resource)
            if not isinstance(subject, Mapping) or not isinstance(resource_attrs, Mapping):
                raise ContextRetrievalError("subject/resource lookup must return mappings")
            if not isinstance(environment, Mapping):
                raise ContextRetrievalError("environment lookup must return a mapping")
            # Snapshot at the boundary; no client-supplied context is merged in here.
            return TrustedAuthorizationContext(
                _json_copy(dict(subject)),
                _json_copy(dict(resource_attrs)),
                _json_copy(dict(environment)),
            )
        except ContextRetrievalError:
            raise
        except Exception as exc:
            raise ContextRetrievalError("trusted_context_lookup_failed") from exc
