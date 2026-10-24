from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from paca_mvp.opa import OPAPolicyDecisionPoint


OPA_URL = os.environ.get("PACA_OPA_BASE_URL")


@unittest.skipUnless(OPA_URL, "Set PACA_OPA_BASE_URL to run live OPA policy integration tests")
class LiveOPAPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pdp = OPAPolicyDecisionPoint(base_url=OPA_URL, required_policy_version="paca-baseline-v1")
        cls.pdp.preflight()

    @staticmethod
    def input_document(*, owner="db-user-1", tenant="tenant-1", status="active",
                       action="file.read", resource_path="reports/q1.csv",
                       argument_path="reports/q1.csv", role="analyst"):
        return {
            "subject": {
                "id": "oidc:fixture-principal",
                "user_id": "db-user-1",
                "issuer": "https://identity.example",
                "status": status,
                "role": role,
                "tenant_id": "tenant-1",
            },
            "action": action,
            "resource": {
                "id": "file:r1",
                "owner_id": owner,
                "tenant_id": tenant,
                "canonical_path": resource_path,
            },
            "arguments": {"path": argument_path},
            "environment": {},
        }

    def test_live_opa_allows_active_owner_same_tenant_and_canonical_path(self):
        decision = self.pdp.evaluate(self.input_document())
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "permitted")
        self.assertEqual(decision.policy_version, "paca-baseline-v1")

    def test_live_opa_denies_other_owner(self):
        decision = self.pdp.evaluate(self.input_document(owner="db-user-2"))
        self.assertFalse(decision.allowed)

    def test_live_opa_does_not_compare_owner_to_raw_oidc_subject(self):
        decision = self.pdp.evaluate(
            self.input_document(owner="user-1")
        )
        self.assertFalse(decision.allowed)

    def test_live_opa_denies_missing_internal_user_id(self):
        document = self.input_document()
        del document["subject"]["user_id"]
        self.assertFalse(self.pdp.evaluate(document).allowed)

    def test_live_opa_denies_cross_tenant(self):
        decision = self.pdp.evaluate(self.input_document(tenant="tenant-2"))
        self.assertFalse(decision.allowed)

    def test_live_opa_denies_inactive_subject(self):
        decision = self.pdp.evaluate(self.input_document(status="disabled"))
        self.assertFalse(decision.allowed)

    def test_live_opa_denies_unknown_action(self):
        decision = self.pdp.evaluate(self.input_document(action="file.delete"))
        self.assertFalse(decision.allowed)

    def test_live_opa_denies_path_substitution(self):
        decision = self.pdp.evaluate(self.input_document(argument_path="secrets.csv"))
        self.assertFalse(decision.allowed)

    def test_live_opa_denies_missing_subject_and_resource_attributes(self):
        decision = self.pdp.evaluate({"action": "file.read", "arguments": {}})
        self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
