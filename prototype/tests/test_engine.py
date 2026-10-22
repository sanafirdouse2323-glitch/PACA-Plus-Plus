import sys
import unittest
from pathlib import Path
from threading import Thread

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from paca_mvp import AuthorizationEngine, Policy, PolicyError, AuthorizationError


def make_policy(version="v1", include_deny=False):
    rules = [{
        "id": "read_owned", "effect": "permit", "action": "file.read",
        "conditions": [
            {"path": "user.role", "op": "eq", "value": "analyst"},
            {"path": "resource.owner", "op": "eq", "value_from_path": "user.id"},
        ],
    }]
    if include_deny:
        rules.append({"id": "deny_suspended", "effect": "deny", "action": "file.read",
                      "conditions": [{"path": "user.suspended", "op": "eq", "value": True}]})
    return Policy.from_dict({"version": version, "rules": rules})


def context():
    return {"user": {"id": "u1", "role": "analyst", "suspended": False},
            "resource": {"owner": "u1"}}


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.engine = AuthorizationEngine(make_policy())
        self.ctx = context()

    def test_permit_for_matching_user_and_owned_resource(self):
        d = self.engine.authorize("file.read", "file:r1", self.ctx)
        self.assertTrue(d.allowed)
        self.assertIsNotNone(d.permit_id)

    def test_default_deny_for_unknown_action(self):
        d = self.engine.authorize("file.delete", "file:r1", self.ctx)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "no_matching_permit")

    def test_missing_namespaced_attribute_does_not_fall_back(self):
        ctx = {"role": "analyst", "user": {"id": "u1"}, "resource": {"owner": "u1"}}
        self.assertFalse(self.engine.authorize("file.read", "file:r1", ctx).allowed)

    def test_missing_attribute_ne_does_not_pass(self):
        policy = Policy.from_dict({"version": "v1", "rules": [{
            "id": "r", "effect": "permit", "action": "file.read",
            "conditions": [{"path": "user.role", "op": "ne", "value": "blocked"}],
        }]})
        self.assertFalse(AuthorizationEngine(policy).authorize("file.read", "file:r1", {"user": {}}).allowed)

    def test_action_substitution_is_blocked_before_effect(self):
        args = {"path": "report-1"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        ran = []
        with self.assertRaisesRegex(AuthorizationError, "action_or_resource_mismatch"):
            self.engine.execute_operation(d.permit_id, "user-1", "file.delete", "file:r1", args, lambda: ran.append("executed"))
        self.assertEqual(ran, [])

    def test_resource_substitution_is_blocked(self):
        args = {"path": "report-1"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        with self.assertRaisesRegex(AuthorizationError, "action_or_resource_mismatch"):
            self.engine.execute_operation(d.permit_id, "user-1", "file.read", "file:r2", args, lambda: "bad")

    def test_permit_is_one_use(self):
        args = {"path": "report-1"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        self.assertEqual(self.engine.execute_operation(d.permit_id, "user-1", "file.read", "file:r1", args, lambda: 7), 7)
        with self.assertRaisesRegex(AuthorizationError, "permit_replayed"):
            self.engine.execute_operation(d.permit_id, "user-1", "file.read", "file:r1", args, lambda: 8)

    def test_state_change_invalidates_permit(self):
        args = {"path": "report-1"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        self.engine.advance_state()
        with self.assertRaisesRegex(AuthorizationError, "stale_state"):
            self.engine.execute_operation(d.permit_id, "user-1", "file.read", "file:r1", args, lambda: "bad")

    def test_policy_change_invalidates_permit(self):
        args = {"path": "report-1"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        self.engine.update_policy(make_policy(version="v2"))
        with self.assertRaisesRegex(AuthorizationError, "stale_policy"):
            self.engine.execute_operation(d.permit_id, "user-1", "file.read", "file:r1", args, lambda: "bad")

    def test_policy_content_change_invalidates_permit_even_if_version_label_is_reused(self):
        args = {"path": "report-1"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        changed = Policy.from_dict({"version": "v1", "rules": [{
            "id": "read_owned", "effect": "permit", "action": "file.read",
            "conditions": [
                {"path": "user.role", "op": "eq", "value": "engineer"},
                {"path": "resource.owner", "op": "eq", "value_from_path": "user.id"},
            ],
        }]})
        self.engine.update_policy(changed)
        with self.assertRaisesRegex(AuthorizationError, "stale_policy"):
            self.engine.execute_operation(
                d.permit_id, "user-1", "file.read", "file:r1", args, lambda: "must not run"
            )


    def test_deny_overrides_permit(self):
        engine = AuthorizationEngine(make_policy(include_deny=True))
        ctx = context()
        ctx["user"]["suspended"] = True
        d = engine.authorize("file.read", "file:r1", ctx)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "deny_override")

    def test_empty_permit_rule_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict({"version": "v1", "rules": [{
                "id": "unsafe", "effect": "permit", "action": "file.read", "conditions": [],
            }]})

    def test_concurrent_replay_allows_at_most_one_effect(self):
        args = {"path": "report-1"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        outcomes, rejected = [], []
        def attempt():
            try:
                self.engine.execute_operation(d.permit_id, "user-1", "file.read", "file:r1", args, lambda: outcomes.append("effect"))
            except AuthorizationError:
                rejected.append("rejected")
        t1, t2 = Thread(target=attempt), Thread(target=attempt)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(outcomes, ["effect"])
        self.assertEqual(len(rejected), 1)


    def test_unbound_legacy_permit_cannot_execute_effect(self):
        d = self.engine.authorize("file.read", "file:r1", self.ctx)
        ran = []
        with self.assertRaisesRegex(AuthorizationError, "operation_binding_required"):
            self.engine.execute(d.permit_id, "file.read", "file:r1", lambda: ran.append(True))
        self.assertEqual(ran, [])


    def test_operation_permit_binds_principal_and_exact_arguments(self):
        args = {"path": "reports/q1.csv", "mode": "read"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        self.assertTrue(d.allowed)
        result = self.engine.execute_operation(
            d.permit_id, "user-1", "file.read", "file:r1", args, lambda: "ok"
        )
        self.assertEqual(result, "ok")

    def test_operation_permit_rejects_changed_arguments_before_effect(self):
        args = {"path": "reports/q1.csv", "mode": "read"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        ran = []
        with self.assertRaisesRegex(AuthorizationError, "arguments_mismatch"):
            self.engine.execute_operation(
                d.permit_id, "user-1", "file.read", "file:r1",
                {"path": "secrets.csv", "mode": "read"}, lambda: ran.append(True)
            )
        self.assertEqual(ran, [])

    def test_operation_permit_rejects_changed_principal_before_effect(self):
        args = {"path": "reports/q1.csv"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        ran = []
        with self.assertRaisesRegex(AuthorizationError, "principal_mismatch"):
            self.engine.execute_operation(
                d.permit_id, "user-2", "file.read", "file:r1", args, lambda: ran.append(True)
            )
        self.assertEqual(ran, [])

    def test_non_finite_or_non_positive_ttl_is_denied(self):
        for ttl in (0, -1, 301, 10**100, float("nan"), float("inf"), float("-inf")):
            with self.subTest(ttl=ttl):
                d = self.engine.authorize("file.read", "file:r1", self.ctx, ttl)
                self.assertFalse(d.allowed)
                self.assertEqual(d.reason, "invalid_permit_ttl")

    def test_non_json_operation_arguments_are_denied(self):
        d = self.engine.authorize_operation(
            "user-1", "file.read", "file:r1", {"value": object()}, self.ctx
        )
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "invalid_arguments")

    def test_non_callable_effect_is_rejected(self):
        args = {"path": "report-1"}
        d = self.engine.authorize_operation("user-1", "file.read", "file:r1", args, self.ctx)
        with self.assertRaisesRegex(AuthorizationError, "effect_not_callable"):
            self.engine.execute_operation(d.permit_id, "user-1", "file.read", "file:r1", args, None)

    def test_raw_policy_input_mutation_does_not_change_parsed_policy(self):
        raw = {"version": "v1", "rules": [{
            "id": "r", "effect": "permit", "action": "file.read",
            "conditions": [{"path": "user.role", "op": "in", "value": ["analyst"]}],
        }]}
        policy = Policy.from_dict(raw)
        raw["rules"][0]["conditions"][0]["value"].append("admin")
        engine = AuthorizationEngine(policy)
        self.assertFalse(engine.authorize(
            "file.read", "file:r1", {"user": {"role": "admin"}}
        ).allowed)


if __name__ == "__main__":
    unittest.main()
