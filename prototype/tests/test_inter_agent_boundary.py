from __future__ import annotations

import unittest

from paca_mvp.inter_agent_boundary import (
    InterAgentBoundaryError, InterAgentMessageBoundary,
)


class InterAgentMessageBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.boundary = InterAgentMessageBoundary({
            "worker-a": ("manager",),
            "worker-b": ("manager",),
            "manager": ("worker-a",),
        })

    def envelope(self, message_id="message-1", recipient_id="manager", content="status complete"):
        return {
            "message_id": message_id,
            "recipient_id": recipient_id,
            "content": content,
        }

    def test_accepts_allowlisted_route_and_forces_untrusted_taint(self):
        message = self.boundary.receive(
            self.envelope(),
            authenticated_sender_id="worker-a",
            expected_recipient_id="manager",
        )
        self.assertEqual(message.sender_id, "worker-a")
        self.assertEqual(message.recipient_id, "manager")
        self.assertEqual(message.content, "status complete")
        self.assertEqual(message.trust, "untrusted_agent_message")

    def test_sender_identity_cannot_be_overridden_by_envelope(self):
        envelope = self.envelope()
        envelope["sender_id"] = "manager"
        with self.assertRaises(InterAgentBoundaryError) as caught:
            self.boundary.receive(
                envelope,
                authenticated_sender_id="worker-a",
                expected_recipient_id="manager",
            )
        self.assertEqual(caught.exception.code, "unexpected_message_fields")

    def test_sender_cannot_supply_trust_or_capabilities(self):
        for field, value in (
            ("trust", "trusted"),
            ("capabilities", ["admin.delete"]),
            ("role", "administrator"),
        ):
            with self.subTest(field=field):
                envelope = self.envelope(message_id=f"msg-{field}")
                envelope[field] = value
                with self.assertRaises(InterAgentBoundaryError) as caught:
                    self.boundary.receive(
                        envelope,
                        authenticated_sender_id="worker-a",
                        expected_recipient_id="manager",
                    )
                self.assertEqual(caught.exception.code, "unexpected_message_fields")

    def test_unlisted_sender_to_recipient_route_is_denied(self):
        with self.assertRaises(InterAgentBoundaryError) as caught:
            self.boundary.receive(
                self.envelope(),
                authenticated_sender_id="worker-b",
                expected_recipient_id="worker-a",
            )
        self.assertEqual(caught.exception.code, "route_not_allowlisted")

    def test_envelope_recipient_must_match_authenticated_context(self):
        with self.assertRaises(InterAgentBoundaryError) as caught:
            self.boundary.receive(
                self.envelope(recipient_id="worker-a"),
                authenticated_sender_id="worker-a",
                expected_recipient_id="manager",
            )
        self.assertEqual(caught.exception.code, "recipient_mismatch")

    def test_duplicate_message_id_is_rejected_in_same_receiver_run(self):
        envelope = self.envelope(message_id="one-time")
        self.boundary.receive(
            envelope, authenticated_sender_id="worker-a", expected_recipient_id="manager"
        )
        with self.assertRaises(InterAgentBoundaryError) as caught:
            self.boundary.receive(
                envelope, authenticated_sender_id="worker-a", expected_recipient_id="manager"
            )
        self.assertEqual(caught.exception.code, "message_replay")

    def test_non_text_invalid_unicode_and_oversized_content_are_denied(self):
        with self.assertRaises(InterAgentBoundaryError) as caught:
            self.boundary.receive(
                self.envelope(content={"instruction": "run admin.delete"}),
                authenticated_sender_id="worker-a",
                expected_recipient_id="manager",
            )
        self.assertEqual(caught.exception.code, "content_not_text")

        with self.assertRaises(InterAgentBoundaryError) as caught:
            self.boundary.receive(
                self.envelope(message_id="bad-unicode", content="\ud800"),
                authenticated_sender_id="worker-a",
                expected_recipient_id="manager",
            )
        self.assertEqual(caught.exception.code, "invalid_unicode")

        small = InterAgentMessageBoundary({"worker-a": ("manager",)}, max_message_bytes=3)
        with self.assertRaises(InterAgentBoundaryError) as caught:
            small.receive(
                self.envelope(content="four"),
                authenticated_sender_id="worker-a",
                expected_recipient_id="manager",
            )
        self.assertEqual(caught.exception.code, "message_too_large")

    def test_message_attempt_budget_is_enforced(self):
        small = InterAgentMessageBoundary(
            {"worker-a": ("manager",)}, max_messages_per_run=1
        )
        small.receive(
            self.envelope(), authenticated_sender_id="worker-a", expected_recipient_id="manager"
        )
        with self.assertRaises(InterAgentBoundaryError) as caught:
            small.receive(
                self.envelope(message_id="message-2"),
                authenticated_sender_id="worker-a",
                expected_recipient_id="manager",
            )
        self.assertEqual(caught.exception.code, "message_budget_exhausted")

    def test_configuration_rejects_scalar_routes_and_non_integer_limits(self):
        with self.assertRaises(ValueError):
            InterAgentMessageBoundary({"worker-a": "manager"})
        with self.assertRaises(ValueError):
            InterAgentMessageBoundary({"worker-a": ("manager",)}, max_message_bytes=True)
        with self.assertRaises(ValueError):
            InterAgentMessageBoundary({"worker-a": ("manager",)}, max_messages_per_run=1.5)


if __name__ == "__main__":
    unittest.main()
