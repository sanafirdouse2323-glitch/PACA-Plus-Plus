"""Bounded inter-agent message ingress with explicit untrusted-data taint.

This boundary validates routing and message metadata. It does not authenticate
the transport or semantically detect prompt injection. Pass a sender identity
only after the host has authenticated it independently.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import threading
from typing import Mapping, Sequence, Any


_PRINCIPAL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MESSAGE_FIELDS = frozenset({"message_id", "recipient_id", "content"})
_UNTRUSTED_MESSAGE_LABEL = "untrusted_agent_message"


class InterAgentBoundaryError(ValueError):
    """An inter-agent message failed trusted ingress policy."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class InterAgentMessage:
    """Message accepted by the boundary; content is always untrusted data."""

    message_id: str
    sender_id: str
    recipient_id: str
    content: str

    @property
    def trust(self) -> str:
        """Fixed taint label; it cannot be supplied by the sender."""
        return _UNTRUSTED_MESSAGE_LABEL


class InterAgentMessageBoundary:
    """Validate routes, bind sender identity to the authenticated transport, and taint.

    Construct one boundary per receiver run. The application must authenticate
    the transport before calling receive(); message contents cannot authenticate
    or elevate their sender. This class never grants tool permissions.
    """

    def __init__(
        self,
        allowed_routes: Mapping[str, Sequence[str]],
        *,
        max_message_bytes: int = 32_768,
        max_messages_per_run: int = 100,
    ) -> None:
        if not isinstance(allowed_routes, Mapping) or not allowed_routes:
            raise ValueError("allowed_routes must be a non-empty administrator mapping")
        if (
            isinstance(max_message_bytes, bool)
            or not isinstance(max_message_bytes, int)
            or max_message_bytes < 1
        ):
            raise ValueError("max_message_bytes must be a positive integer")
        if (
            isinstance(max_messages_per_run, bool)
            or not isinstance(max_messages_per_run, int)
            or max_messages_per_run < 1
        ):
            raise ValueError("max_messages_per_run must be a positive integer")

        routes: dict[str, frozenset[str]] = {}
        for sender, recipients in allowed_routes.items():
            if not isinstance(sender, str) or not _PRINCIPAL_ID.fullmatch(sender):
                raise ValueError("configured sender IDs must be valid bounded identifiers")
            if isinstance(recipients, (str, bytes)) or not isinstance(recipients, Sequence):
                raise ValueError("each route must list recipient IDs, not a scalar string")
            if not recipients:
                raise ValueError("each configured sender route must have at least one recipient")
            checked_recipients: set[str] = set()
            for recipient in recipients:
                if not isinstance(recipient, str) or not _PRINCIPAL_ID.fullmatch(recipient):
                    raise ValueError("configured recipient IDs must be valid bounded identifiers")
                checked_recipients.add(recipient)
            routes[sender] = frozenset(checked_recipients)

        self._allowed_routes = routes
        self._max_message_bytes = max_message_bytes
        self._max_messages_per_run = max_messages_per_run
        self._receive_attempts = 0
        self._seen_message_ids: set[tuple[str, str, str]] = set()
        self._lock = threading.RLock()

    @staticmethod
    def _validate_principal(value: Any, label: str) -> str:
        if not isinstance(value, str) or not _PRINCIPAL_ID.fullmatch(value):
            raise InterAgentBoundaryError(f"{label} must be a valid authenticated identifier", "invalid_principal")
        return value

    def receive(
        self,
        envelope: Mapping[str, Any],
        *,
        authenticated_sender_id: str,
        expected_recipient_id: str,
    ) -> InterAgentMessage:
        """Accept one message after external transport authentication.

        Envelope fields are exactly message_id, recipient_id, and content.
        Sender identity comes from the authenticated transport and is not
        accepted from the envelope. Sender trust, capabilities, and roles cannot
        be supplied in message data.
        """
        sender = self._validate_principal(authenticated_sender_id, "authenticated sender")
        recipient = self._validate_principal(expected_recipient_id, "expected recipient")

        with self._lock:
            if self._receive_attempts >= self._max_messages_per_run:
                raise InterAgentBoundaryError("inter-agent message budget exhausted", "message_budget_exhausted")
            self._receive_attempts += 1

        if not isinstance(envelope, Mapping):
            raise InterAgentBoundaryError("message envelope must be an object", "invalid_envelope")
        keys = tuple(envelope.keys())
        if any(not isinstance(key, str) for key in keys) or set(keys) != _MESSAGE_FIELDS:
            raise InterAgentBoundaryError(
                "message envelope must contain only message_id, recipient_id, and content",
                "unexpected_message_fields",
            )

        if recipient not in self._allowed_routes.get(sender, frozenset()):
            raise InterAgentBoundaryError(
                "sender-to-recipient route is not allowlisted",
                "route_not_allowlisted",
            )

        message_id = envelope.get("message_id")
        if not isinstance(message_id, str) or not _PRINCIPAL_ID.fullmatch(message_id):
            raise InterAgentBoundaryError("message_id must be a valid bounded identifier", "invalid_message_id")
        envelope_recipient = envelope.get("recipient_id")
        if envelope_recipient != recipient:
            raise InterAgentBoundaryError(
                "message recipient does not match the authenticated receiving context",
                "recipient_mismatch",
            )
        content = envelope.get("content")
        if not isinstance(content, str):
            raise InterAgentBoundaryError("message content must be text", "content_not_text")
        try:
            raw_content = content.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise InterAgentBoundaryError("message content contains invalid Unicode", "invalid_unicode") from exc
        if len(raw_content) > self._max_message_bytes:
            raise InterAgentBoundaryError("message exceeds the byte limit", "message_too_large")

        replay_key = (sender, recipient, message_id)
        with self._lock:
            if replay_key in self._seen_message_ids:
                raise InterAgentBoundaryError("message ID was already accepted in this run", "message_replay")
            self._seen_message_ids.add(replay_key)

        return InterAgentMessage(
            message_id=message_id,
            sender_id=sender,
            recipient_id=recipient,
            content=content,
        )
