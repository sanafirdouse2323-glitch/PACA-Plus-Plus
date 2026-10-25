package paca.authz

import rego.v1

owner_or_admin if {
  input.principal.id == input.resource.owner_id
} 
owner_or_admin if {
  "admin" in input.principal.roles
}

default decision := {"allow": false, "reason": "default_deny"}

decision := {
  "allow": true,
  "reason": "document_read_allowed",
  "policy_revision": data.paca.meta.revision,
} if {
  input.action == "document.read"
  input.resource.kind == "document"
  input.resource.status == "active"
  input.principal.tenant_id == input.resource.tenant_id
  "document:read" in input.principal.scopes
  owner_or_admin
}

decision := {
  "allow": true,
  "reason": "document_update_allowed",
  "policy_revision": data.paca.meta.revision,
} if {
  input.action == "document.update"
  input.resource.kind == "document"
  input.resource.status == "active"
  input.principal.tenant_id == input.resource.tenant_id
  "document:write" in input.principal.scopes
  owner_or_admin
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
  owner_or_admin
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
  owner_or_admin
}

decision := {
  "allow": true,
  "reason": "registered_tool_allowed",
  "policy_revision": data.paca.meta.revision,
} if {
  input.action == "tool.invoke"
  input.resource.status == "active"
  input.resource.kind == "tool"
  input.resource.tenant_id == input.principal.tenant_id
  "tool:invoke" in input.principal.scopes
  tool_name := input.arguments.name
  tool_name in input.principal.tools
}
