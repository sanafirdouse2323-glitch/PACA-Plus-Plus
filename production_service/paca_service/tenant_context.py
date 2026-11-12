from __future__ import annotations

import hashlib
import hmac


class TenantContextError(ValueError):
    """Invalid or un-signable database tenant context."""


def tenant_context_message(
    tenant_id: str,
    principal_id: str,
    backend_pid: int,
    transaction_id: str,
    issued_at: int,
    expires_at: int,
    key_id: str,
) -> bytes:
    values = (tenant_id, principal_id, transaction_id, key_id)
    if any(not isinstance(value, str) or not value or any(ord(ch) < 32 for ch in value) for value in values):
        raise TenantContextError("tenant context fields must be non-empty printable strings")
    if isinstance(backend_pid, bool) or not isinstance(backend_pid, int) or backend_pid <= 0:
        raise TenantContextError("invalid PostgreSQL backend PID")
    if not transaction_id.isdigit():
        raise TenantContextError("invalid PostgreSQL transaction ID")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in (issued_at, expires_at)):
        raise TenantContextError("tenant context timestamps must be integer Unix seconds")
    if expires_at <= issued_at or expires_at - issued_at > 60:
        raise TenantContextError("tenant context lifetime must be between 1 and 60 seconds")
    fields = (
        "paca-tenant-context-v1",
        tenant_id,
        principal_id,
        str(backend_pid),
        transaction_id,
        str(issued_at),
        str(expires_at),
        key_id,
    )
    return "\n".join(fields).encode("utf-8")


def sign_tenant_context(
    key: bytes,
    tenant_id: str,
    principal_id: str,
    backend_pid: int,
    transaction_id: str,
    issued_at: int,
    expires_at: int,
    key_id: str,
) -> str:
    if not isinstance(key, bytes) or len(key) != 32:
        raise TenantContextError("tenant context HMAC key must contain exactly 32 bytes")
    message = tenant_context_message(
        tenant_id, principal_id, backend_pid, transaction_id,
        issued_at, expires_at, key_id,
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()
