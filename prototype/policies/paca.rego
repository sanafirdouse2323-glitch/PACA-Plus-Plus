package paca.authz

import rego.v1

# Increment this version when the authorization semantics change. For managed
# bundles, prefer returning the verified bundle revision in this field.
policy_version := "paca-example-v4"

default decision := {
    "allow": false,
    "policy_version": "paca-example-v4",
    "reason": "no_matching_permit",
}

# The signed claim is a defensive deny signal, but current suspension state
# must come from the trusted authorization-context service.
deny if {
    input.principal.claims.suspended == true
}

deny if {
    input.context.authorization.suspended == true
}

permit if {
    input.action == "file.read"
    input.context.authorization.suspended == false
    input.context.authorization.role == "analyst"
    input.context.authorization.principal_id == input.context.resource.owner_principal_id
    input.context.authorization.tenant_id == input.context.resource.tenant_id
}

permit if {
    input.action == "ticket.create"
    input.context.authorization.suspended == false
    input.context.authorization.role == "support"
    input.context.authorization.can_create_tickets == true
    input.context.authorization.principal_id != null
    input.context.authorization.tenant_id == input.context.resource.tenant_id
    input.resource == "ticket-collection:default"
}

decision := {
    "allow": false,
    "policy_version": policy_version,
    "reason": "suspended",
} if {
    deny
}

decision := {
    "allow": true,
    "policy_version": policy_version,
    "reason": "analyst_reads_owned_file",
} if {
    permit
    not deny
    input.action == "file.read"
}

decision := {
    "allow": true,
    "policy_version": policy_version,
    "reason": "support_ticket_create",
} if {
    permit
    not deny
    input.action == "ticket.create"
}
