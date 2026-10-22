package paca.authz

import rego.v1

# Deny if subject status is absent or anything other than "active".
deny if {
    not input.subject.status == "active"
}

# Example baseline policy. Authorization attributes (role, status, owner, tenant)
# must be populated by the trusted context provider, not accepted from the request.
permit if {
    not deny
    input.action == "file.read"
    input.subject.role == "analyst"
    input.resource.owner_id == input.subject.id
    input.resource.tenant_id == input.subject.tenant_id
    # Bind caller arguments to the authoritative resource mapping. For files this
    # prevents authorizing one record while asking the downstream service for another path.
    input.arguments.path == input.resource.canonical_path
}

decision := {"allow": true, "reason": "permitted"} if {
    permit
}

decision := {"allow": false, "reason": "subject_not_active"} if {
    deny
}

decision := {"allow": false, "reason": "no_matching_permit"} if {
    not permit
    not deny
}
