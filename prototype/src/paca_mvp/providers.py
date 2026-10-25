"""Concrete identity/context providers and protected-effect adapters.

Security note: configuration is part of the trust boundary. OIDC issuer/audience,
JWKS endpoint, context service, route allowlist and filesystem resource map must
be administrator-controlled—not accepted from agent requests.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request
from urllib.parse import urlparse
import json
import os
import stat
import uuid
import threading
from datetime import datetime, timezone

from .hardening import (
    AuthenticationFailed, ContextUnavailable, TrustedPrincipal, _canonical_json,
    _validate_identifier, _urlopen_no_redirect,
)


class ToolInvocationError(RuntimeError):
    """A configured protected tool/API refused or failed an invocation."""


class OIDCJWTIdentityProvider:
    """Validate RS256 JWTs against a configured OIDC JWKS/issuer/audience.

    Requires PyJWT with cryptography support. Decoding a JWT without validating
    its signature and claims is deliberately not supported.
    """
    def __init__(self, issuer: str, audience: str, jwks_url: str,
                 timeout_seconds: float = 3.0, jwks_cache_seconds: int = 300):
        for name, value in (("issuer", issuer), ("audience", audience)):
            _validate_identifier(value, name)
        jwks_parsed = urlparse(jwks_url)
        if (jwks_parsed.scheme != "https" or not jwks_parsed.hostname
                or jwks_parsed.username or jwks_parsed.password
                or jwks_parsed.query or jwks_parsed.fragment):
            raise ValueError("JWKS URL must be an HTTPS URL without embedded credentials/query/fragment")
        if timeout_seconds <= 0 or jwks_cache_seconds <= 0:
            raise ValueError("timeouts/cache lifetime must be positive")
        self.issuer, self.audience = issuer, audience
        self.jwks_url, self.timeout_seconds = jwks_url, timeout_seconds
        self.jwks_cache_seconds = jwks_cache_seconds
        self._jwks_client = None
        self._client_lock = threading.Lock()

    def authenticate(self, credential: str) -> TrustedPrincipal:
        if not isinstance(credential, str) or not credential or len(credential) > 16384:
            raise AuthenticationFailed("missing or invalid bearer credential")
        try:
            import jwt
            with self._client_lock:
                if self._jwks_client is None:
                    self._jwks_client = jwt.PyJWKClient(
                        self.jwks_url,
                        cache_jwk_set=True,
                        lifespan=self.jwks_cache_seconds,
                        timeout=self.timeout_seconds,
                    )
                client = self._jwks_client
            header = jwt.get_unverified_header(credential)
            if header.get("alg") != "RS256" or not header.get("kid"):
                raise ValueError("unsupported token algorithm or missing key id")
            signing_key = client.get_signing_key_from_jwt(credential)
            claims = jwt.decode(
                credential, signing_key.key,
                algorithms=["RS256"], issuer=self.issuer, audience=self.audience,
                options={"require": ["iss", "aud", "exp", "sub"]},
                leeway=0,
            )
            subject = claims.get("sub")
            if not isinstance(subject, str) or not subject.strip():
                raise ValueError("subject claim missing")
            return TrustedPrincipal(
                subject=subject, issuer=self.issuer, audience=self.audience,
                claims=claims, authenticated_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as exc:
            raise AuthenticationFailed("credential verification failed") from exc


class HTTPAuthorizationContextProvider:
    """Fetch authorization attributes from an administrator-configured service.

    The service token must be a secret with the least privilege needed to read
    authorization attributes. HTTPS is required except explicit loopback-only
    development use. Returned context may not overwrite verified identity.
    """
    def __init__(self, endpoint: str, service_token: str, timeout_seconds: float = 3.0,
                 allow_insecure_localhost: bool = False):
        parsed = urlparse(endpoint)
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (
            allow_insecure_localhost and parsed.scheme == "http" and parsed.hostname in local_hosts
        ):
            raise ValueError("context endpoint must use HTTPS (HTTP is allowed only for explicit loopback development)")
        if (not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment):
            raise ValueError("context endpoint must not contain credentials, query or fragment")
        if not service_token or len(service_token) < 16:
            raise ValueError("context service token must be configured as a secret")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.endpoint, self.service_token, self.timeout_seconds = endpoint, service_token, timeout_seconds

    def get_context(self, principal: TrustedPrincipal, action: str,
                    resource: str) -> Mapping[str, Any]:
        body = _canonical_json({
            "subject": principal.subject, "issuer": principal.issuer,
            "audience": principal.audience, "action": action, "resource": resource,
        }).encode("utf-8")
        req = Request(self.endpoint, data=body, method="POST", headers={
            "Authorization": "Bearer " + self.service_token,
            "Content-Type": "application/json", "Accept": "application/json",
        })
        try:
            with _urlopen_no_redirect(req, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise ContextUnavailable(f"context service returned HTTP {response.status}")
                raw = response.read(1_048_577)
                if len(raw) > 1_048_576:
                    raise ContextUnavailable("context response exceeded 1 MiB")
            result = json.loads(raw.decode("utf-8"))
            if not isinstance(result, dict) or "identity" in result:
                raise ValueError("context must be an object and cannot override identity")
            # Verify JSON serializability now, before policy evaluation.
            _canonical_json(result)
            return result
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError,
                json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ContextUnavailable("trusted context retrieval failed") from exc


@dataclass(frozen=True)
class HTTPRoute:
    method: str
    path: str


class HTTPJSONToolAdapter:
    """Call a fixed, administrator-configured HTTP API route.

    Routes are keyed by the exact (action, resource) pair. The agent cannot
    supply a hostname, URL, HTTP method, headers or route. A protected API should
    honor Idempotency-Key for safe recovery; this adapter cannot force that
    behavior on a downstream server.
    """
    _METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    def __init__(self, base_url: str, routes: Mapping[tuple[str, str], HTTPRoute],
                 bearer_token: str | None = None, timeout_seconds: float = 5.0,
                 max_response_bytes: int = 1_048_576):
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("protected API base_url must be an HTTPS origin/base path")
        if parsed.query or parsed.fragment:
            raise ValueError("API base_url must not contain query or fragment")
        if timeout_seconds <= 0 or max_response_bytes < 1:
            raise ValueError("invalid timeout/response size")
        checked: dict[tuple[str, str], HTTPRoute] = {}
        for key, route in routes.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise ValueError("route keys must be (action, resource) tuples")
            action, resource = key
            _validate_identifier(action, "route action")
            _validate_identifier(resource, "route resource")
            if not isinstance(route, HTTPRoute):
                raise ValueError("route values must be HTTPRoute")
            method = route.method.upper()
            if method not in self._METHODS:
                raise ValueError(f"unsupported effect method {method!r}")
            if (not route.path.startswith("/") or route.path.startswith("//")
                    or "://" in route.path or "?" in route.path or "#" in route.path
                    or any(part in {".", ".."} for part in route.path.split("/"))):
                raise ValueError("route path must be a fixed absolute path without query/traversal")
            checked[(action, resource)] = HTTPRoute(method, route.path)
        self.base_url = base_url.rstrip("/")
        self.routes = checked
        self.bearer_token = bearer_token
        self.timeout_seconds, self.max_response_bytes = timeout_seconds, max_response_bytes

    def invoke(self, action: str, resource: str, arguments: Mapping[str, Any],
               idempotency_key: str) -> Any:
        route = self.routes.get((action, resource))
        if route is None:
            raise ToolInvocationError("no configured route for this action/resource")
        _validate_identifier(idempotency_key, "idempotency_key")
        # The route already binds the authorized action/resource pair.
        # Send the protected API's argument object as its ordinary JSON body;
        # the idempotency key is carried in the standard header.
        body = _canonical_json(dict(arguments)).encode("utf-8")
        headers = {
            "Content-Type": "application/json", "Accept": "application/json",
            "Idempotency-Key": idempotency_key,
        }
        if self.bearer_token:
            headers["Authorization"] = "Bearer " + self.bearer_token
        req = Request(self.base_url + route.path, data=body, headers=headers, method=route.method)
        try:
            with _urlopen_no_redirect(req, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_response_bytes + 1)
                if len(raw) > self.max_response_bytes:
                    raise ToolInvocationError("protected API response exceeded configured limit")
                if response.status < 200 or response.status >= 300:
                    raise ToolInvocationError(f"protected API returned HTTP {response.status}")
                if not raw:
                    return {"status": "ok", "http_status": response.status}
                try:
                    return json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    return {"status": "ok", "http_status": response.status,
                            "body_text": raw.decode("utf-8", errors="replace")}
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise ToolInvocationError("protected API invocation failed; outcome may be unknown") from exc


class FilesystemToolAdapter:
    """A constrained local filesystem tool using logical resource identifiers.

    Uses descriptor-relative traversal with O_NOFOLLOW on POSIX, so configured
    nested paths cannot be redirected through symlinks. Resource mappings and
    root path must be admin-controlled. Actions are file.read, file.write, and
    file.delete; file.write requires arguments['content'] as a UTF-8 string.
    """
    def __init__(self, root: str, resources: Mapping[str, str],
                 max_file_bytes: int = 10_000_000):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise RuntimeError("FilesystemToolAdapter requires POSIX O_NOFOLLOW support")
        self.root = str(Path(root).resolve(strict=True))
        if not Path(self.root).is_dir():
            raise ValueError("filesystem root must be an existing directory")
        self.max_file_bytes = max_file_bytes
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        self.resources: dict[str, tuple[str, ...]] = {}
        for logical_id, relative in resources.items():
            _validate_identifier(logical_id, "logical resource id")
            if not isinstance(relative, str) or not relative or os.path.isabs(relative):
                raise ValueError("resource path must be a non-empty relative path")
            parts = tuple(relative.replace("\\", "/").split("/"))
            if any(p in {"", ".", ".."} for p in parts):
                raise ValueError("resource path contains an unsafe component")
            self.resources[logical_id] = parts

    def _open_parent(self, parts: tuple[str, ...]) -> tuple[int, str]:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
        fd = os.open(self.root, flags)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd, parts[-1]
        except Exception:
            os.close(fd)
            raise

    def invoke(self, action: str, resource: str, arguments: Mapping[str, Any],
               idempotency_key: str) -> Any:
        parts = self.resources.get(resource)
        if parts is None:
            raise ToolInvocationError("unknown logical filesystem resource")
        if action not in {"file.read", "file.write", "file.delete"}:
            raise ToolInvocationError("filesystem action is not supported")
        try:
            parent_fd, name = self._open_parent(parts)
        except OSError as exc:
            raise ToolInvocationError("filesystem path traversal rejected or parent unavailable") from exc
        try:
            if action == "file.read":
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_size > self.max_file_bytes:
                        raise ToolInvocationError("target is not a bounded regular file")
                    chunks = []
                    remaining = self.max_file_bytes + 1
                    while remaining:
                        chunk = os.read(fd, min(65536, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    raw = b"".join(chunks)
                    if len(raw) > self.max_file_bytes:
                        raise ToolInvocationError("file exceeded configured size limit")
                    return {"content": raw.decode("utf-8")}
                except UnicodeDecodeError as exc:
                    raise ToolInvocationError("file content is not valid UTF-8") from exc
                finally:
                    os.close(fd)
            if action == "file.write":
                content = arguments.get("content")
                if not isinstance(content, str):
                    raise ToolInvocationError("file.write requires a UTF-8 string content argument")
                raw = content.encode("utf-8")
                if len(raw) > self.max_file_bytes:
                    raise ToolInvocationError("content exceeded configured size limit")
                # Replace a file atomically; do not follow the destination symlink.
                temp_name = ".paca-" + uuid.uuid4().hex
                fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent_fd)
                try:
                    view = memoryview(raw)
                    while view:
                        written = os.write(fd, view)
                        view = view[written:]
                    os.fsync(fd)
                except Exception:
                    try:
                        os.unlink(temp_name, dir_fd=parent_fd)
                    except OSError:
                        pass
                    raise
                finally:
                    os.close(fd)
                try:
                    os.replace(temp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except Exception:
                    try:
                        os.unlink(temp_name, dir_fd=parent_fd)
                    except OSError:
                        pass
                    raise
                return {"bytes_written": len(raw)}
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise ToolInvocationError("refusing to delete a symlink target")
            os.unlink(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            return {"deleted": True}
        except OSError as exc:
            raise ToolInvocationError("filesystem operation failed") from exc
        finally:
            os.close(parent_fd)
