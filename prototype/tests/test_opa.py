from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import json
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError
from io import BytesIO

from paca_mvp.opa import OPAError, OPAPolicyDecisionPoint


class Response:
    def __init__(self, body, status=200):
        self.body = body
        self.status = status
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, _size=-1):
        return self.body


class OPATests(unittest.TestCase):
    def setUp(self):
        self.client = OPAPolicyDecisionPoint()

    @patch("paca_mvp.opa._open_request")
    def test_allow_only_on_boolean_true(self, mocked):
        mocked.return_value = Response(b'{"result":{"allow":true,"reason":"permitted"},"decision_id":"decision-123"}')
        result = self.client.evaluate({"action": "file.read"})
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "permitted")
        self.assertEqual(result.decision_id, "decision-123")
        sent = json.loads(mocked.call_args.args[0].data)
        self.assertEqual(sent, {"input": {"action": "file.read"}})

    @patch("paca_mvp.opa._open_request")
    def test_truthy_non_boolean_does_not_allow(self, mocked):
        mocked.return_value = Response(b'{"result":{"allow":"true","reason":"bad type"}}')
        self.assertFalse(self.client.evaluate({}).allowed)

    @patch("paca_mvp.opa._open_request")
    def test_undefined_decision_is_deny(self, mocked):
        mocked.return_value = Response(b'{}')
        decision = self.client.evaluate({})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "undefined_decision")

    @patch("paca_mvp.opa._open_request")
    def test_unreachable_opa_raises_for_fail_closed_gateway(self, mocked):
        mocked.side_effect = URLError("offline")
        with self.assertRaises(OPAError):
            self.client.evaluate({})

    @patch("paca_mvp.opa._open_request")
    def test_malformed_response_is_not_allowed(self, mocked):
        mocked.return_value = Response(b'not json')
        with self.assertRaises(OPAError):
            self.client.evaluate({})

    def test_remote_http_requires_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            OPAPolicyDecisionPoint(base_url="http://opa.example:8181")

    def test_loopback_http_is_accepted_for_sidecar_development(self):
        OPAPolicyDecisionPoint(base_url="http://127.0.0.1:8181")


    @patch("paca_mvp.opa._open_request")
    def test_invalid_decision_id_is_ignored(self, mocked):
        mocked.return_value = Response(
            ('{"result":{"allow":true,"reason":"permitted"},"decision_id":"' + ("x" * 129) + '"}').encode()
        )
        self.assertIsNone(self.client.evaluate({}).decision_id)


    @patch("paca_mvp.opa._open_request")
    def test_reason_is_replaced_when_it_is_not_a_bounded_code(self, mocked):
        mocked.return_value = Response(
            b'{"result":{"allow":true,"reason":"private data should not be returned"}}'
        )
        result = self.client.evaluate({})
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "permitted")

    def test_bearer_token_with_header_control_characters_is_rejected(self):
        with self.assertRaises(ValueError):
            OPAPolicyDecisionPoint(bearer_token="secret\r\nInjected: yes")


    @patch("paca_mvp.opa._open_request")
    def test_redirect_from_opa_is_fail_closed(self, mocked):
        from urllib.error import HTTPError
        mocked.side_effect = HTTPError(
            "https://opa.example/v1/data/paca/authz/decision", 302, "redirect", {}, None
        )
        with self.assertRaises(OPAError):
            self.client.evaluate({"action": "file.read"})


if __name__ == "__main__":
    unittest.main()
