from __future__ import annotations

import hashlib
import json
from typing import Any


class InvalidCanonicalValue(ValueError):
    """Raised when a value cannot be represented as finite canonical JSON."""


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise InvalidCanonicalValue("value_must_be_finite_json") from exc


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
