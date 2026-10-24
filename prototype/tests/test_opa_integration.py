from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import os
import unittest

from paca_mvp.opa import OPAPolicyDecisionPoint


BASE_URL = os.environ.get("PACA_OPA_BASE_URL")


@unittest.skipUnless(BASE_URL, "Set PACA_OPA_BASE_URL to run live OPA integration tests")
class LiveOPATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.opa = OPAPolicyDecisionPoint(base_url=BASE_URL, decision_path="paca/authz/decision")

    @staticmethod
    def input_doc(role="analyst", owner="db-user-1", subject="u1", user_id="db-user-1", subject_tenant="t1",
                  resource_tenant="t1", status="active", action="file.read",
                  argument_path="r1", canonical_path="r1"):
        return {
            "subject": {"id": "oidc:fixture-principal", "subject": subject, "user_id": user_id,
                        "issuer": "https://identity.example", "status": status,
                        "role": role, "tenant_id": subject_tenant},
            "action": action,
            "resource": {"id": "file:r1", "owner_id": owner, "tenant_id": resource_tenant, "canonical_path": canonical_path},
            "arguments": {"path": argument_path},
            "environment": {},
        }

    def test_real_opa_allows_valid_owner(self):
        result = self.opa.evaluate(self.input_doc())
        self.assertTrue(result.allowed, result.reason)

    def test_real_opa_denies_wrong_owner(self):
        self.assertFalse(self.opa.evaluate(self.input_doc(owner="db-user-2")).allowed)

    def test_real_opa_denies_cross_tenant(self):
        self.assertFalse(self.opa.evaluate(self.input_doc(resource_tenant="t2")).allowed)

    def test_real_opa_denies_inactive_subject_and_unknown_action(self):
        self.assertFalse(self.opa.evaluate(self.input_doc(status="disabled")).allowed)
        self.assertFalse(self.opa.evaluate(self.input_doc(action="file.delete")).allowed)


    def test_real_opa_denies_argument_path_that_does_not_match_resource(self):
        self.assertFalse(self.opa.evaluate(
            self.input_doc(argument_path="../private/secret.csv", canonical_path="r1")
        ).allowed)


    def test_real_opa_preflight_requires_a_defined_default_deny(self):
        result = self.opa.preflight()
        self.assertFalse(result.allowed)
        self.assertNotEqual(result.reason, "undefined_decision")


if __name__ == "__main__":
    unittest.main()
