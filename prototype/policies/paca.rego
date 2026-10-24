package paca.authz

import rego.v1

# Increment this version when the authorization semantics change. For managed
# bundles, prefer returning the verified bundle revision in this field.
policy_version := "paca-example-v2"

default decision := {
    "allow": false,
    "policy_version": "paca-example-v2",
    "reason": "no_matching_permit",
}

deny if {
    input.principal.claims.suspended == true
}

permit if {
    input.action == "file.read"
    input.principal.claims.suspended == false
    input.context.authorization.role == "analyst"
    input.context.resource.owner == input.principal.subject
}

permit if {
    input.action == "ticket.create"
    input.principal.claims.suspended == false
    input.context.authorization.role == "support"
    input.context.authorization.can_create_tickets == true
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
