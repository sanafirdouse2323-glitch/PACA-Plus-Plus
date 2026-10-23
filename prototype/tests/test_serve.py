from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import os
import unittest
from unittest.mock import patch

from paca_mvp.serve import _resolve_bind_host


class ServeConfigurationTests(unittest.TestCase):
    def test_default_bind_is_loopback(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_resolve_bind_host(), "127.0.0.1")

    def test_blank_bind_host_is_rejected(self):
        with patch.dict(os.environ, {"PACA_BIND_HOST": "  "}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "must not be blank"):
                _resolve_bind_host()

    def test_non_loopback_bind_requires_explicit_trusted_ingress_acknowledgement(self):
        with patch.dict(os.environ, {"PACA_BIND_HOST": "0.0.0.0"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "trusted TLS-terminating ingress"):
                _resolve_bind_host()

    def test_non_loopback_bind_is_allowed_only_after_explicit_acknowledgement(self):
        with patch.dict(os.environ, {
            "PACA_BIND_HOST": "0.0.0.0",
            "PACA_TRUSTED_INGRESS_TERMINATES_TLS": "true",
        }, clear=True):
            self.assertEqual(_resolve_bind_host(), "0.0.0.0")

    def test_loopback_bind_does_not_need_ingress_acknowledgement(self):
        for host in ("127.0.0.1", "::1", "localhost"):
            with self.subTest(host=host), patch.dict(os.environ, {"PACA_BIND_HOST": host}, clear=True):
                self.assertEqual(_resolve_bind_host(), host)


if __name__ == "__main__":
    unittest.main()
