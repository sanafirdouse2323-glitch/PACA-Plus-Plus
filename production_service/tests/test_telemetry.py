import unittest
from paca_service.telemetry import TraceparentParser, TraceContext

class TraceparentParserTests(unittest.TestCase):
    def test_valid_incoming_traceparent_propagates_trace_id(self):
        incoming = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        ctx = TraceparentParser.parse_or_create(incoming)
        self.assertEqual(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736")
        self.assertNotEqual(ctx.parent_id, "00f067aa0ba902b7") # new child span
        self.assertEqual(ctx.trace_flags, "01")
        header = ctx.to_header()
        self.assertTrue(header.startswith("00-4bf92f3577b34da6a3ce929d0e0e4736-"))

    def test_missing_header_generates_fresh_trace_context(self):
        ctx = TraceparentParser.parse_or_create(None)
        self.assertEqual(len(ctx.trace_id), 32)
        self.assertEqual(len(ctx.parent_id), 16)
        self.assertEqual(ctx.trace_flags, "01")

    def test_all_zeros_trace_id_rejected_and_regenerated(self):
        incoming = "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
        ctx = TraceparentParser.parse_or_create(incoming)
        self.assertNotEqual(ctx.trace_id, "0" * 32)

if __name__ == "__main__":
    unittest.main()
