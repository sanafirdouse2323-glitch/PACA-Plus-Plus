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
    def input_doc(role="analyst", owner="u1", subject="u1", subject_tenant="t1",
                  resource_tenant="t1", status="active", action="file.read"):
        return {
            "subject": {"id": subject, "issuer": "https://identity.example",
                        "status": status, "role": role, "tenant_id": subject_tenant},
            "action": action,
            "resource": {"id": "file:r1", "owner_id": owner, "tenant_id": resource_tenant},
            "arguments": {"path": "r1"},
            "environment": {},
        }

    def test_real_opa_allows_valid_owner(self):
        result = self.opa.evaluate(self.input_doc())
        self.assertTrue(result.allowed, result.reason)

    def test_real_opa_denies_wrong_owner(self):
        self.assertFalse(self.opa.evaluate(self.input_doc(owner="u2")).allowed)

    def test_real_opa_denies_cross_tenant(self):
        self.assertFalse(self.opa.evaluate(self.input_doc(resource_tenant="t2")).allowed)

    def test_real_opa_denies_inactive_subject_and_unknown_action(self):
        self.assertFalse(self.opa.evaluate(self.input_doc(status="disabled")).allowed)
        self.assertFalse(self.opa.evaluate(self.input_doc(action="file.delete")).allowed)


if __name__ == "__main__":
    unittest.main()
