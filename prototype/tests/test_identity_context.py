from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import unittest

from paca_mvp.identity import (
    AuthenticatedPrincipal,
    CallbackContextProvider,
    ContextRetrievalError,
)


class TrustedContextTests(unittest.TestCase):
    def setUp(self):
        self.principal = AuthenticatedPrincipal(
            "user-1", "https://issuer.example", {"sub": "user-1"}
        )

    def test_context_is_copied_to_a_stable_json_snapshot(self):
        subject = {"status": "active", "roles": ["analyst"], "user_id": "db-user-1"}
        resource = {"owner_id": "db-user-1", "canonical_path": "report.csv"}
        provider = CallbackContextProvider(
            subject_lookup=lambda _principal: subject,
            resource_lookup=lambda _p, _a, _r, _args: resource,
        )
        snapshot = provider.load(self.principal, "file.read", "file:r1", {})
        subject["roles"].append("admin")
        resource["canonical_path"] = "private.csv"
        self.assertEqual(snapshot.subject_attributes["roles"], ["analyst"])
        self.assertEqual(snapshot.resource_attributes["canonical_path"], "report.csv")

    def test_non_finite_values_are_rejected(self):
        provider = CallbackContextProvider(
            subject_lookup=lambda _principal: {"status": "active", "weight": float("nan")},
            resource_lookup=lambda _p, _a, _r, _args: {"owner_id": "db-user-1"},
        )
        with self.assertRaises(ContextRetrievalError):
            provider.load(self.principal, "file.read", "file:r1", {})

    def test_unserializable_values_are_rejected(self):
        provider = CallbackContextProvider(
            subject_lookup=lambda _principal: {"role": object()},
            resource_lookup=lambda _p, _a, _r, _args: {"owner_id": "user-1"},
        )
        with self.assertRaises(ContextRetrievalError):
            provider.load(self.principal, "file.read", "file:r1", {})

    def test_lookup_failure_is_not_converted_to_empty_context(self):
        def fail(_principal):
            raise RuntimeError("database unavailable")
        provider = CallbackContextProvider(
            subject_lookup=fail,
            resource_lookup=lambda _p, _a, _r, _args: {"owner_id": "user-1"},
        )
        with self.assertRaisesRegex(ContextRetrievalError, "trusted_context_lookup_failed"):
            provider.load(self.principal, "file.read", "file:r1", {})


if __name__ == "__main__":
    unittest.main()
