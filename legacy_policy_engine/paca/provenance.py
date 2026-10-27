"""Provenance tracking for legacy PACA++ policies.

Recovered from the embedded source snapshot in archive/paca-plus-plus-new.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List

from .ast import ProvenanceRecord


@dataclass
class ProvenanceGraph:
    """Stores provenance records for a policy evaluation."""

    records: List[ProvenanceRecord] = field(default_factory=list)

    def add(self, source: str, entity: str, attribute: str, value: Any,
            explanation: str = "") -> ProvenanceRecord:
        record = ProvenanceRecord(source=source, entity=entity, attribute=attribute,
                                  value=value, explanation=explanation)
        self.records.append(record)
        return record

    def extend(self, records: Iterable[ProvenanceRecord]) -> None:
        self.records.extend(records)

    def from_context(self, context: Dict[str, Any], source: str = "context") -> None:
        if not isinstance(context, dict):
            return
        for key, value in context.items():
            if isinstance(value, dict):
                for attribute, nested_value in value.items():
                    self.add(source, str(key), str(attribute), nested_value,
                             f"context value for {key}.{attribute}")
            else:
                self.add(source, str(key), "value", value,
                         f"context value for {key}")

    def __iter__(self) -> Iterator[ProvenanceRecord]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)


__all__ = ["ProvenanceGraph"]
