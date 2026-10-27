"""Deterministic content boundaries for retrieval and agent output.

These controls enforce application policy; they are not an LLM prompt-injection detector.
Provenance must be assigned by trusted ingestion/authentication code, never by model output.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable, Sequence
from urllib.parse import urlsplit
import html
import re

TRUST_LEVELS = frozenset({"trusted", "internal", "untrusted", "unknown"})
_URL_RE = re.compile(r"https?://[^\s<>]+", re.IGNORECASE)
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(\s*<?(https?://[^\s)>]+)", re.IGNORECASE)
_HTML_ACTIVE_RE = re.compile(r"(?is)<\s*(img|iframe|script|source|video|audio|object|embed|svg|form|input|link|meta)\b")
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


class ContentBoundaryError(ValueError):
    """A content item or output failed a deterministic boundary check."""


@dataclass(frozen=True)
class ProvenancedDocument:
    """A document plus provenance assigned by a trusted ingestion component."""
    document_id: str
    source: str
    trust: str
    content: str
    content_sha256: str

    @classmethod
    def create(cls, document_id: str, source: str, trust: str, content: str) -> "ProvenancedDocument":
        if not isinstance(document_id, str) or not document_id.strip() or len(document_id) > 256:
            raise ContentBoundaryError("document_id must be a non-empty bounded string")
        if not isinstance(source, str) or not source.strip() or len(source) > 512:
            raise ContentBoundaryError("source must be a non-empty bounded string")
        if trust not in TRUST_LEVELS:
            raise ContentBoundaryError("unknown provenance trust level")
        if not isinstance(content, str):
            raise ContentBoundaryError("document content must be text")
        try:
            raw = content.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ContentBoundaryError("document contains invalid Unicode") from exc
        return cls(document_id, source, trust, content, sha256(raw).hexdigest())


@dataclass(frozen=True)
class RetrievalResult:
    included: tuple[ProvenancedDocument, ...]
    excluded: tuple[tuple[str, str], ...]
    total_characters: int


def filter_retrieval(
    documents: Iterable[ProvenancedDocument],
    *,
    allowed_trust_levels: frozenset[str] = frozenset({"trusted", "internal"}),
    max_documents: int = 20,
    max_total_characters: int = 40_000,
) -> RetrievalResult:
    """Apply retrieval-time provenance policy before content enters model context."""
    if not allowed_trust_levels or not allowed_trust_levels.issubset(TRUST_LEVELS):
        raise ContentBoundaryError("allowed_trust_levels contains invalid or no trust levels")
    if max_documents < 0 or max_total_characters < 0:
        raise ContentBoundaryError("retrieval budgets must be non-negative")
    included: list[ProvenancedDocument] = []
    excluded: list[tuple[str, str]] = []
    total = 0
    for doc in documents:
        if not isinstance(doc, ProvenancedDocument):
            raise ContentBoundaryError("retrieval input must contain ProvenancedDocument values")
        try:
            actual = sha256(doc.content.encode("utf-8", errors="strict")).hexdigest()
        except (AttributeError, UnicodeEncodeError) as exc:
            raise ContentBoundaryError("invalid document content") from exc
        if actual != doc.content_sha256:
            excluded.append((doc.document_id, "provenance_digest_mismatch"))
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
        if max_output_characters < 1:
            raise ValueError("max_output_characters must be positive")
        hosts: set[str] = set()
        for host in allowed_link_hosts:
            if not isinstance(host, str) or not host.strip():
                raise ValueError("allowed link hosts must be non-empty hostnames")
            parsed = urlsplit("//" + host.strip())
            if not parsed.hostname or parsed.port is not None or parsed.path or parsed.query or parsed.fragment:
                raise ValueError("allowed link host must be a hostname only")
            hosts.add(parsed.hostname.rstrip(".").lower())
        values = []
        for value in sensitive_values:
            if not isinstance(value, str):
                raise ValueError("sensitive values must be strings")
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
        if _MD_IMAGE_RE.search(decoded):
            reasons.add("remote_image_beacon")
        if _HTML_ACTIVE_RE.search(decoded):
            reasons.add("active_html_content")
        for match in _URL_RE.finditer(decoded):
            raw_url = match.group(0).rstrip(".,;:!?) ]}")
            try:
                parsed = urlsplit(raw_url)
                host = (parsed.hostname or "").rstrip(".").lower()
            except ValueError:
                reasons.add("malformed_url")
                continue
            if parsed.scheme.lower() not in {"http", "https"} or not host:
                reasons.add("malformed_url")
            elif parsed.username is not None or parsed.password is not None:
                reasons.add("url_credentials_forbidden")
            elif parsed.scheme.lower() != "https":
                reasons.add("insecure_link_forbidden")
            elif parsed.port not in {None, 443}:
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
