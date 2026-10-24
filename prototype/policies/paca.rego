package paca.authz

import rego.v1

# Increment this version when the authorization semantics change. For managed
# bundles, prefer returning the verified bundle revision in this field.
policy_version := "paca-example-v1"

default decision := {
    "allow": false,
    "policy_version": "paca-example-v1",
    "reason": "no_matching_permit",
}

deny if {
    input.principal.claims.suspended == true
}

permit if {
    input.action == "file.read"
    input.context.authorization.role == "analyst"
    input.context.resource.owner == input.principal.subject
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
}
