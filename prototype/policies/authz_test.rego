package paca.authz

import rego.v1

test_allow_owner_same_tenant if {
    result := decision with input as {
        "subject": {"id": "oidc:issuer-scoped-user-1", "subject": "u1", "user_id": "db-user-1",
                    "issuer": "https://id.example", "status": "active",
                    "role": "analyst", "tenant_id": "t1"},
        "action": "file.read",
        "resource": {"id": "file:r1", "owner_id": "db-user-1", "tenant_id": "t1", "canonical_path": "r1"},
        "arguments": {"path": "r1"},
        "environment": {}
    }
    result.allow == true
}

test_deny_other_owner if {
    result := decision with input as {
        "subject": {"id": "oidc:issuer-scoped-user-1", "subject": "u1", "user_id": "db-user-1",
                    "issuer": "https://id.example", "status": "active",
                    "role": "analyst", "tenant_id": "t1"},
        "action": "file.read",
        "resource": {"id": "file:r1", "owner_id": "db-user-2", "tenant_id": "t1", "canonical_path": "r1"},
        "arguments": {},
        "environment": {}
    }
    result.allow == false
}

test_deny_cross_tenant if {
    result := decision with input as {
        "subject": {"id": "oidc:issuer-scoped-user-1", "subject": "u1", "user_id": "db-user-1",
                    "issuer": "https://id.example", "status": "active",
                    "role": "analyst", "tenant_id": "t1"},
        "action": "file.read",
        "resource": {"id": "file:r1", "owner_id": "db-user-1", "tenant_id": "t2", "canonical_path": "r1"},
        "arguments": {},
        "environment": {}
    }
    result.allow == false
}

test_deny_inactive_subject if {
    result := decision with input as {
        "subject": {"id": "u1", "issuer": "https://id.example", "status": "disabled",
                    "role": "analyst", "tenant_id": "t1"},
        "action": "file.read",
        "resource": {"id": "file:r1", "owner_id": "db-user-1", "tenant_id": "t1", "canonical_path": "r1"},
        "arguments": {},
        "environment": {}
    }
    result.allow == false
}

test_deny_unknown_action if {
    result := decision with input as {
        "subject": {"id": "oidc:issuer-scoped-user-1", "subject": "u1", "user_id": "db-user-1",
                    "issuer": "https://id.example", "status": "active",
                    "role": "analyst", "tenant_id": "t1"},
        "action": "file.delete",
        "resource": {"id": "file:r1", "owner_id": "db-user-1", "tenant_id": "t1", "canonical_path": "r1"},
        "arguments": {},
        "environment": {}
    }
    result.allow == false
}
