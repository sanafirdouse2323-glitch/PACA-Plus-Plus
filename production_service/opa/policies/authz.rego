package paca.authz

import rego.v1

# Make the decision shape stable for allow, explicit non-match and health probes.
# OPAClient deliberately rejects results without this policy revision.
default allowed := false
default reason := "default_deny"

owner_or_admin if input.principal.id == input.resource.owner_id
owner_or_admin if "admin" in input.principal.roles

document_read_allowed if {
  input.action == "document.read"
  input.resource.kind == "document"
  input.resource.status == "active"
  input.principal.tenant_id == input.resource.tenant_id
  "document:read" in input.principal.scopes
  owner_or_admin
}

document_update_allowed if {
  input.action == "document.update"
  input.resource.kind == "document"
  input.resource.status == "active"
  input.principal.tenant_id == input.resource.tenant_id
  "document:write" in input.principal.scopes
  owner_or_admin
}

file_read_allowed if {
  input.action == "file.read"
  input.resource.status == "active"
  input.resource.tenant_id == input.principal.tenant_id
  input.resource.kind == "file"
  "file:read" in input.principal.scopes
  owner_or_admin
}

file_create_allowed if {
  input.action == "file.create"
  input.resource.status == "active"
  input.resource.tenant_id == input.principal.tenant_id
  input.resource.kind == "file"
  "file:create" in input.principal.scopes
  owner_or_admin
}

registered_tool_allowed if {
  input.action == "tool.invoke"
  input.resource.status == "active"
  input.resource.kind == "tool"
  input.resource.tenant_id == input.principal.tenant_id
  "tool:invoke" in input.principal.scopes
  tool_name := input.arguments.name
  tool_name in input.principal.tools
}

allowed if document_read_allowed
allowed if document_update_allowed
allowed if file_read_allowed
allowed if file_create_allowed
allowed if registered_tool_allowed

reason := "document_read_allowed" if document_read_allowed
reason := "document_update_allowed" if document_update_allowed
reason := "file_read_allowed" if file_read_allowed
reason := "file_create_allowed" if file_create_allowed
reason := "registered_tool_allowed" if registered_tool_allowed

decision := {
  "allow": allowed,
  "reason": reason,
  "policy_revision": data.paca.meta.revision,
}
