"""Deterministic content boundaries for retrieval and agent output.

These controls enforce application policy; they are not an LLM prompt-injection detector.
Provenance must be assigned by trusted ingestion/authentication code, never by model output.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit
import html
import re

TRUST_LEVELS = frozenset({"trusted", "internal", "untrusted", "unknown"})
_URL_RE = re.compile(r"https?://[^\s<>]+", re.IGNORECASE)
_MD_IMAGE_RE = re.compile(r"!\s*\[[^\]]*\]\s*(?:\([^)]*\)|\[[^]]*\])?", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"(?is)<\s*/?\s*[a-z][^>]*>")
_MARKDOWN_DESTINATION_RE = re.compile(r"\[[^]]*\]\(\s*<?([^\s)>]+)", re.IGNORECASE)
_MARKDOWN_REFERENCE_DESTINATION_RE = re.compile(
    r"(?im)^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*<?([^\s>]+)"
)
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


class ContentBoundaryError(ValueError):
    """A content item or output failed a deterministic boundary check."""


@dataclass(frozen=True)
class ProvenancedDocument:
    """A document with HMAC-authenticated provenance from trusted ingestion."""
    document_id: str
    source: str
    trust: str
    content: str
    content_sha256: str
    provenance_signature: str


class ProvenanceAuthority:
    """HMAC-based provenance issuer/verifier.

    Hold the authority/key only in trusted ingestion and retrieval code. Do not
    pass it to an LLM, tool output parser, or untrusted plugin. For separate
    ingestion/retrieval services use an asymmetric signing service instead.
    """
    def __init__(self, key: bytes, source_trust_levels: Mapping[str, str]):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ContentBoundaryError("provenance HMAC key must be at least 32 bytes")
        if not isinstance(source_trust_levels, Mapping):
            raise ContentBoundaryError("source_trust_levels must be an administrator-configured mapping")
        configured: dict[str, str] = {}
        for source, trust in source_trust_levels.items():
            if not isinstance(source, str) or not source.strip() or len(source) > 512:
                raise ContentBoundaryError("configured source IDs must be non-empty bounded strings")
            try:
                source.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise ContentBoundaryError("configured source ID contains invalid Unicode") from exc
            if any(ord(ch) < 32 for ch in source):
                raise ContentBoundaryError("configured source IDs must not contain control characters")
            if not isinstance(trust, str) or trust not in TRUST_LEVELS:
                raise ContentBoundaryError("configured source trust level is invalid")
            configured[source] = trust
        self._key = bytes(key)
        self._source_trust_levels = configured

    @staticmethod
    def _validate_fields(document_id: str, source: str, trust: str, content: str) -> bytes:
        if not isinstance(document_id, str) or not document_id.strip() or len(document_id) > 256:
            raise ContentBoundaryError("document_id must be a non-empty bounded string")
        if not isinstance(source, str) or not source.strip() or len(source) > 512:
            raise ContentBoundaryError("source must be a non-empty bounded string")
        for field, label in ((document_id, "document_id"), (source, "source")):
            try:
                field.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise ContentBoundaryError(f"{label} contains invalid Unicode") from exc
            if any(ord(ch) < 32 for ch in field):
                raise ContentBoundaryError(f"{label} must not contain control characters")
        if not isinstance(trust, str) or trust not in TRUST_LEVELS:
            raise ContentBoundaryError("unknown provenance trust level")
        if not isinstance(content, str):
            raise ContentBoundaryError("document content must be text")
        try:
            return content.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ContentBoundaryError("document contains invalid Unicode") from exc

    @staticmethod
    def _payload(document_id: str, source: str, trust: str, content_sha256: str) -> bytes:
        return json.dumps(
            [document_id, source, trust, content_sha256],
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")

    def issue(self, document_id: str, source: str, content: str) -> ProvenancedDocument:
        """Issue provenance using trust fixed by administrator source configuration."""
        if not isinstance(source, str) or not source.strip() or len(source) > 512:
            raise ContentBoundaryError("source must be a non-empty bounded string")
        trust = self._source_trust_levels.get(source, "unknown")
        raw = self._validate_fields(document_id, source, trust, content)
        digest = sha256(raw).hexdigest()
        signature = hmac.new(
            self._key, self._payload(document_id, source, trust, digest), sha256
        ).hexdigest()
        return ProvenancedDocument(document_id, source, trust, content, digest, signature)

    def verify(self, document: ProvenancedDocument) -> bool:
        """Verify provenance signature and content digest; malformed objects fail."""
        if not isinstance(document, ProvenancedDocument):
            return False
        try:
            raw = self._validate_fields(
                document.document_id, document.source, document.trust, document.content
            )
            expected_trust = self._source_trust_levels.get(document.source, "unknown")
            if document.trust != expected_trust:
                return False
            actual_digest = sha256(raw).hexdigest()
            if not hmac.compare_digest(actual_digest, document.content_sha256):
                return False
            expected = hmac.new(
                self._key,
                self._payload(document.document_id, document.source, document.trust, actual_digest),
                sha256,
            ).hexdigest()
            return isinstance(document.provenance_signature, str) and hmac.compare_digest(
                expected, document.provenance_signature
            )
        except (ContentBoundaryError, TypeError, ValueError, UnicodeEncodeError):
            return False

@dataclass(frozen=True)
class RetrievalResult:
    included: tuple[ProvenancedDocument, ...]
    excluded: tuple[tuple[str, str], ...]
    total_characters: int


def filter_retrieval(
    documents: Iterable[ProvenancedDocument],
    *,
    authority: ProvenanceAuthority,
    allowed_trust_levels: frozenset[str] = frozenset({"trusted", "internal"}),
    max_documents: int = 20,
    max_total_characters: int = 40_000,
) -> RetrievalResult:
    """Apply retrieval-time provenance policy before content enters model context."""
    if not isinstance(authority, ProvenanceAuthority):
        raise ContentBoundaryError("a trusted ProvenanceAuthority verifier is required")
    if (not isinstance(allowed_trust_levels, (set, frozenset))
            or not allowed_trust_levels or not allowed_trust_levels.issubset(TRUST_LEVELS)):
        raise ContentBoundaryError("allowed_trust_levels contains invalid or no trust levels")
    if (
        isinstance(max_documents, bool) or not isinstance(max_documents, int)
        or isinstance(max_total_characters, bool) or not isinstance(max_total_characters, int)
        or max_documents < 0 or max_total_characters < 0
    ):
        raise ContentBoundaryError("retrieval budgets must be non-negative integers")
    included: list[ProvenancedDocument] = []
    excluded: list[tuple[str, str]] = []
    total = 0
    for doc in documents:
        if not isinstance(doc, ProvenancedDocument):
            raise ContentBoundaryError("retrieval input must contain ProvenancedDocument values")
        if not authority.verify(doc):
            excluded.append((getattr(doc, "document_id", "<invalid>"), "invalid_provenance_signature"))
            continue
        if doc.trust not in allowed_trust_levels:
            excluded.append((doc.document_id, "trust_level_not_allowed"))
            continue
        if len(included) >= max_documents:
            excluded.append((doc.document_id, "document_budget_exceeded"))
            continue
        if total + len(doc.content) > max_total_characters:
            excluded.append((doc.document_id, "character_budget_exceeded"))
            continue
        included.append(doc)
        total += len(doc.content)
    return RetrievalResult(tuple(included), tuple(excluded), total)


@dataclass(frozen=True)
class OutputDecision:
    allowed: bool
    reason_codes: tuple[str, ...]
    text: str | None


class OutputBoundary:
    """Fail-closed output policy for known-secret leakage and remote fetch vectors."""
    def __init__(
        self, *, allowed_link_hosts: Sequence[str] = (),
        sensitive_values: Sequence[str] = (), max_output_characters: int = 20_000,
    ):
        if (
            isinstance(max_output_characters, bool)
            or not isinstance(max_output_characters, int)
            or max_output_characters < 1
        ):
            raise ValueError("max_output_characters must be a positive integer")
        if isinstance(allowed_link_hosts, (str, bytes)) or not isinstance(allowed_link_hosts, Sequence):
            raise ValueError("allowed_link_hosts must be a sequence of hostnames")
        if isinstance(sensitive_values, (str, bytes)) or not isinstance(sensitive_values, Sequence):
            raise ValueError("sensitive_values must be a sequence of strings")

        hosts: set[str] = set()
        for host in allowed_link_hosts:
            if (
                not isinstance(host, str) or not host.strip() or host != host.strip()
                or any(character.isspace() for character in host)
            ):
                raise ValueError("allowed link hosts must be non-empty hostnames without whitespace")
            parsed = urlsplit("//" + host)
            try:
                port = parsed.port
            except ValueError as exc:
                raise ValueError("allowed link host contains an invalid port") from exc
            if (
                not parsed.hostname or parsed.username is not None or parsed.password is not None
                or port is not None or parsed.path or parsed.query or parsed.fragment
            ):
                raise ValueError("allowed link host must be a hostname only")
            hosts.add(parsed.hostname.rstrip(".").lower())
        values = []
        for value in sensitive_values:
            if not isinstance(value, str):
                raise ValueError("sensitive values must be strings")
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise ValueError("sensitive values must contain valid Unicode") from exc
            if value:
                values.append(value)
        self.allowed_link_hosts = frozenset(hosts)
        self.sensitive_values = tuple(values)
        self.max_output_characters = max_output_characters

    def inspect(self, output: str) -> OutputDecision:
        if not isinstance(output, str):
            return OutputDecision(False, ("output_not_text",), None)
        try:
            output.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return OutputDecision(False, ("invalid_unicode",), None)
        if len(output) > self.max_output_characters:
            return OutputDecision(False, ("output_too_large",), None)

        decoded = html.unescape(output)
        reasons: set[str] = set()
        # Deny all Markdown images, including reference-style images.
        if _MD_IMAGE_RE.search(decoded):
            reasons.add("markdown_image_forbidden")
        # This boundary accepts plain text/Markdown, not HTML.
        if _HTML_TAG_RE.search(decoded):
            reasons.add("raw_html_forbidden")
        # Also catch dangerous URI schemes in reference-style Markdown links, where
        # the destination may be declared on a separate line.
        if re.search(r"(?i)\b(?:javascript|data|file|vbscript)\s*:", decoded):
            reasons.add("unsafe_link_scheme")
        for pattern in (_MARKDOWN_DESTINATION_RE, _MARKDOWN_REFERENCE_DESTINATION_RE):
            for match in pattern.finditer(decoded):
                destination = match.group(1).strip("<>")
                scheme = destination.split(":", 1)[0].lower() if ":" in destination else ""
                if scheme and scheme not in {"http", "https"}:
                    reasons.add("unsafe_link_scheme")
                elif destination.startswith("//"):
                    reasons.add("protocol_relative_link_forbidden")
        for match in _URL_RE.finditer(decoded):
            raw_url = match.group(0).rstrip(".,;:!?) ]}")
            try:
                parsed = urlsplit(raw_url)
                host = (parsed.hostname or "").rstrip(".").lower()
                port = parsed.port
            except ValueError:
                reasons.add("malformed_url")
                continue
            if parsed.scheme.lower() not in {"http", "https"} or not host:
                reasons.add("malformed_url")
            elif parsed.username is not None or parsed.password is not None:
                reasons.add("url_credentials_forbidden")
            elif parsed.scheme.lower() != "https":
                reasons.add("insecure_link_forbidden")
            elif port not in {None, 443}:
                reasons.add("nonstandard_link_port_forbidden")
            elif host not in self.allowed_link_hosts:
                reasons.add("external_link_not_allowlisted")
        for pattern in _SECRET_PATTERNS:
            if pattern.search(decoded):
                reasons.add("credential_pattern_detected")
        if any(value in decoded for value in self.sensitive_values):
            reasons.add("configured_sensitive_value_detected")
        if reasons:
            return OutputDecision(False, tuple(sorted(reasons)), None)
        return OutputDecision(True, (), output)


class OutputBlocked(ContentBoundaryError):
    """A generated response was blocked before delivery or rendering."""
    def __init__(self, reason_codes: Sequence[str]):
        self.reason_codes = tuple(reason_codes)
        super().__init__("generated output was blocked by the content boundary")


class GuardedAgentPipeline:
    """Single orchestration facade for retrieval, tool effects, and final output.

    The actual LLM orchestration loop remains in the host application. It should
    use this facade for each retrieval, proposed tool call, and user-visible output.
    This class composes existing guards; it does not duplicate their enforcement
    logic or create a second authorization engine.
    """
    def __init__(
        self,
        *,
        provenance_authority: ProvenanceAuthority,
        tool_boundary: Any,
        output_boundary: OutputBoundary,
        allowed_trust_levels: frozenset[str] = frozenset({"trusted", "internal"}),
    ):
        if not isinstance(provenance_authority, ProvenanceAuthority):
            raise ContentBoundaryError("a configured ProvenanceAuthority is required")
        if not callable(getattr(tool_boundary, "invoke", None)):
            raise ContentBoundaryError("tool_boundary must expose invoke()")
        if not isinstance(output_boundary, OutputBoundary):
            raise ContentBoundaryError("an OutputBoundary is required")
        if (not isinstance(allowed_trust_levels, (set, frozenset))
                or not allowed_trust_levels or not allowed_trust_levels.issubset(TRUST_LEVELS)):
            raise ContentBoundaryError("allowed_trust_levels contains invalid or no trust levels")
        self._provenance_authority = provenance_authority
        self._tool_boundary = tool_boundary
        self._output_boundary = output_boundary
        self._allowed_trust_levels = frozenset(allowed_trust_levels)

    def describe_tools(self) -> tuple[dict[str, Any], ...]:
        """Return model-facing schemas from the exact boundary used for invocation."""
        describe = getattr(self._tool_boundary, "describe_tools", None)
        if not callable(describe):
            raise ContentBoundaryError("tool_boundary must expose describe_tools() for guarded orchestration")
        return describe()

    def retrieve(
        self,
        documents: Iterable[ProvenancedDocument],
        *,
        max_documents: int = 20,
        max_total_characters: int = 40_000,
    ) -> RetrievalResult:
        return filter_retrieval(
            documents,
            authority=self._provenance_authority,
            allowed_trust_levels=self._allowed_trust_levels,
            max_documents=max_documents,
            max_total_characters=max_total_characters,
        )

    def invoke_tool(
        self,
        tool_call: Mapping[str, Any],
        *,
        call_id: str,
        approval_token: str | None = None,
        approval_subject: str | None = None,
    ) -> Any:
        return self._tool_boundary.invoke(
            tool_call,
            call_id=call_id,
            approval_token=approval_token,
            approval_subject=approval_subject,
        )

    def release_output(self, generated_text: str) -> str:
        """Return only approved text; never return the original after a denial."""
        decision = self._output_boundary.inspect(generated_text)
        if not decision.allowed or decision.text is None:
            raise OutputBlocked(decision.reason_codes)
        return decision.text
