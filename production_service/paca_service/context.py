from __future__ import annotations

from typing import Any, Protocol

from .auth import Principal


class ResourceNotFound(LookupError):
    """The resource is not visible in the caller's verified tenant."""


class ResourceStore(Protocol):
    def fetch_resource(self, tenant_id: str, resource_id: str) -> dict[str, Any] | None: ...


class AuthorizationContextProvider:
    """Construct OPA input without accepting caller-supplied roles or resource metadata."""

    def __init__(self, store: ResourceStore) -> None:
        self.store = store

    def build(
        self,
        principal: Principal,
        action: str,
        resource_id: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        row = self.store.fetch_resource(principal.tenant_id, resource_id)
        if row is None:
            raise ResourceNotFound("resource_not_found")
        attributes = row.get("attributes") or {}
        if not isinstance(attributes, dict):
            raise TypeError("resource_attributes_invalid")
        return {
            "principal": {
                "id": principal.subject,
                "tenant_id": principal.tenant_id,
                "roles": list(principal.roles),
                "scopes": list(principal.scopes),
                "tools": list(principal.tools),
            },
            "action": action,
            "resource": {
                "id": row["resource_id"],
                "tenant_id": row["tenant_id"],
                "owner_id": row["owner_id"],
                "kind": row["kind"],
                "status": row["status"],
                "attributes": attributes,
            },
            "arguments": arguments,
        }
