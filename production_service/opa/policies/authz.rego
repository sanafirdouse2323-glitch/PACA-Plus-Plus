package paca.authz

import rego.v1

default decision := {
  "allow": false,
  "reason": "default_deny",
  "policy_revision": data.paca.meta.revision,
}

decision := {
  "allow": true,
  "reason": "document_read_allowed",
  "policy_revision": data.paca.meta.revision,
} if {
  input.action == "document.read"
  input.resource.status == "active"
  input.principal.tenant_id == input.resource.tenant_id
  "document:read" in input.principal.scopes
  (
    input.principal.id == input.resource.owner_id
    or "admin" in input.principal.roles
  )
}

decision := {
  "allow": true,
  "reason": "document_update_allowed",
  "policy_revision": data.paca.meta.revision,
} if {
  input.action == "document.update"
  input.resource.status == "active"
  input.principal.tenant_id == input.resource.tenant_id
  "document:write" in input.principal.scopes
  (
    input.principal.id == input.resource.owner_id
    or "admin" in input.principal.roles
  )
}

decision := {
  "allow": true,
  "reason": "file_read_allowed",
  "policy_revision": data.paca.meta.revision,
} if {
  input.action == "file.read"
  input.resource.status == "active"
  input.resource.tenant_id == input.principal.tenant_id
  input.resource.kind == "file"
  "file:read" in input.principal.scopes
  (
    input.principal.id == input.resource.owner_id
    or "admin" in input.principal.roles
  )
}

decision := {
  "allow": true,
  "reason": "file_create_allowed",
  "policy_revision": data.paca.meta.revision,
} if {
  input.action == "file.create"
  input.resource.status == "active"
  input.resource.tenant_id == input.principal.tenant_id
  input.resource.kind == "file"
  "file:create" in input.principal.scopes
  (
    input.principal.id == input.resource.owner_id
    or "admin" in input.principal.roles
  )
}
