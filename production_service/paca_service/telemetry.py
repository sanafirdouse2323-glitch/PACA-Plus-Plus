from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")

@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    parent_id: str
    trace_flags: str = "01"

    def to_header(self) -> str:
        return f"00-{self.trace_id}-{self.parent_id}-{self.trace_flags}"

class TraceparentParser:
    """Parses and generates W3C traceparent headers according to W3C Trace Context spec."""

    @staticmethod
    def parse_or_create(header_value: str | None) -> TraceContext:
        if isinstance(header_value, str):
            clean = header_value.strip().lower()
            match = _TRACEPARENT_RE.match(clean)
            if match:
                trace_id, parent_id, flags = match.groups()
                # Trace ID and Parent ID must not be all zeros
                if trace_id != "0" * 32 and parent_id != "0" * 16:
                    # Create child span for this gateway invocation
                    child_span = secrets.token_hex(8)
                    return TraceContext(trace_id=trace_id, parent_id=child_span, trace_flags=flags)
        
        # Missing or invalid: generate root trace context
        new_trace = secrets.token_hex(16)
        new_span = secrets.token_hex(8)
        return TraceContext(trace_id=new_trace, parent_id=new_span, trace_flags="01")
