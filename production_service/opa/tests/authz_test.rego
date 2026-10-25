package paca.authz_test

import rego.v1
import data.paca.authz

test_default_deny_for_unknown_action_includes_revision if {
  result := authz.decision with input as {
    "principal": {"id": "alice", "tenant_id": "t1", "roles": [], "scopes": [], "tools": []},
    "action": "dangerous.exec",
    "resource": {"id": "r1", "tenant_id": "t1", "owner_id": "alice",
                 "kind": "document", "status": "active", "attributes": {}},
    "arguments": {},
  }
  result.allow == false
  result.reason == "default_deny"
  result.policy_revision == data.paca.meta.revision
}

test_owner_can_read_active_document_with_scope if {
  result := authz.decision with input as {
    "principal": {"id": "alice", "tenant_id": "t1", "roles": [], "scopes": ["document:read"], "tools": []},
    "action": "document.read",
    "resource": {"id": "r1", "tenant_id": "t1", "owner_id": "alice",
                 "kind": "document", "status": "active", "attributes": {}},
    "arguments": {},
  }
  result.allow == true
  result.reason == "document_read_allowed"
  result.policy_revision == data.paca.meta.revision
}

test_cross_tenant_is_denied_with_revision if {
  result := authz.decision with input as {
    "principal": {"id": "alice", "tenant_id": "t1", "roles": ["admin"],
                  "scopes": ["document:read"], "tools": []},
    "action": "document.read",
    "resource": {"id": "r2", "tenant_id": "t2", "owner_id": "alice",
                 "kind": "document", "status": "active", "attributes": {}},
    "arguments": {},
  }
  result.allow == false
  result.reason == "default_deny"
  result.policy_revision == data.paca.meta.revision
}

test_inactive_document_is_denied if {
  result := authz.decision with input as {
    "principal": {"id": "alice", "tenant_id": "t1", "roles": ["admin"],
                  "scopes": ["document:read"], "tools": []},
    "action": "document.read",
    "resource": {"id": "r1", "tenant_id": "t1", "owner_id": "alice",
                 "kind": "document", "status": "inactive", "attributes": {}},
    "arguments": {},
  }
  result.allow == false
  result.reason == "default_deny"
  result.policy_revision == data.paca.meta.revision
}

test_tool_requires_verified_tool_allowlist if {
  allowed := authz.decision with input as {
    "principal": {"id": "alice", "tenant_id": "t1", "roles": [],
                  "scopes": ["tool:invoke"], "tools": ["text.word_count"]},
    "action": "tool.invoke",
    "resource": {"id": "tool1", "tenant_id": "t1", "owner_id": "alice",
                 "kind": "tool", "status": "active", "attributes": {}},
    "arguments": {"name": "text.word_count", "input": {"text": "one two"}},
  }
  denied := authz.decision with input as {
    "principal": {"id": "alice", "tenant_id": "t1", "roles": [],
                  "scopes": ["tool:invoke"], "tools": ["text.word_count"]},
    "action": "tool.invoke",
    "resource": {"id": "tool1", "tenant_id": "t1", "owner_id": "alice",
                 "kind": "tool", "status": "active", "attributes": {}},
    "arguments": {"name": "shell.run", "input": {"cmd": "bad"}},
  }
  allowed.allow == true
  allowed.policy_revision == data.paca.meta.revision
  denied.allow == false
  denied.reason == "default_deny"
  denied.policy_revision == data.paca.meta.revision
}
