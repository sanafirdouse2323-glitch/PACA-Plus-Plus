from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[index], 3)


class SecurityBenchmarkRecorder:
    """Collect measured outcomes from the repository's real-service integration run.

    Attack success means a forbidden request reached a successful permit or protected
    effect. Legitimate utility means an authorized task completed successfully. The
    unguarded and deny-all controls in the report are analytical reference models, not
    executed competing products or independent evaluations.
    """

    def __init__(self) -> None:
        self._attacks: list[dict[str, Any]] = []
        self._legitimate: list[dict[str, Any]] = []
        self._reliability: list[dict[str, Any]] = []

    @staticmethod
    def _observation(
        scenario_id: str, status_code: int, success: bool, latency_ms: float
    ) -> dict[str, Any]:
        if (
            not isinstance(scenario_id, str)
            or not scenario_id
            or isinstance(status_code, bool)
            or not isinstance(status_code, int)
            or not 100 <= status_code <= 599
            or not isinstance(success, bool)
            or isinstance(latency_ms, bool)
            or not isinstance(latency_ms, (int, float))
            or not math.isfinite(float(latency_ms))
            or latency_ms < 0
        ):
            raise ValueError("invalid_benchmark_observation")
        return {
            "scenario_id": scenario_id,
            "status_code": status_code,
            "success": success,
            "latency_ms": round(float(latency_ms), 3),
        }

    def record_attack(
        self, scenario_id: str, *, status_code: int, attack_succeeded: bool, latency_ms: float
    ) -> None:
        self._attacks.append(
            self._observation(scenario_id, status_code, attack_succeeded, latency_ms)
        )

    def record_legitimate(
        self, scenario_id: str, *, status_code: int, task_succeeded: bool, latency_ms: float
    ) -> None:
        self._legitimate.append(
            self._observation(scenario_id, status_code, task_succeeded, latency_ms)
        )

    def record_reliability(
        self, scenario_id: str, *, passed: bool, status_code: int, latency_ms: float
    ) -> None:
        self._reliability.append(
            self._observation(scenario_id, status_code, passed, latency_ms)
        )

    def report(self) -> dict[str, Any]:
        attack_count = len(self._attacks)
        legitimate_count = len(self._legitimate)
        attack_successes = sum(item["success"] for item in self._attacks)
        legitimate_successes = sum(item["success"] for item in self._legitimate)
        reliability_passes = sum(item["success"] for item in self._reliability)
        all_latencies = [
            item["latency_ms"]
            for item in (*self._attacks, *self._legitimate, *self._reliability)
        ]
        return {
            "schema_version": 1,
            "benchmark_type": "repository_real_service_integration",
            "independent_evaluation": False,
            "third_party_competitor_comparison": False,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "metric_definitions": {
                "attack_success_rate": (
                    "Successful forbidden permit or protected effect / adversarial attempts."
                ),
                "legitimate_task_success_rate": (
                    "Successful authorized tasks / authorized task attempts."
                ),
                "latency_ms": "Client-observed end-to-end request or task latency.",
            },
            "paca_plus_plus": {
                "attack_attempts": attack_count,
                "attack_successes": attack_successes,
                "attack_success_rate": (
                    attack_successes / attack_count if attack_count else None
                ),
                "legitimate_task_attempts": legitimate_count,
                "legitimate_task_successes": legitimate_successes,
                "legitimate_task_success_rate": (
                    legitimate_successes / legitimate_count if legitimate_count else None
                ),
                "reliability_checks": len(self._reliability),
                "reliability_passes": reliability_passes,
                "latency_ms_p50": _percentile(all_latencies, 0.50),
                "latency_ms_p95": _percentile(all_latencies, 0.95),
            },
            "modeled_reference_controls": {
                "unguarded_no_authorization": {
                    "executed_in_this_run": False,
                    "attack_success_rate": 1.0,
                    "legitimate_task_success_rate": 1.0,
                    "assumption": "All proposed actions pass directly to their effect handler.",
                },
                "deny_all": {
                    "executed_in_this_run": False,
                    "attack_success_rate": 0.0,
                    "legitimate_task_success_rate": 0.0,
                    "assumption": "Every request is refused, including legitimate tasks.",
                },
            },
            "observations": {
                "attacks": self._attacks,
                "legitimate_tasks": self._legitimate,
                "reliability": self._reliability,
            },
            "interpretation_limit": (
                "This is an in-repository integration benchmark using the configured "
                "test identity provider, OPA and PostgreSQL. Reference controls are "
                "modeled, not measured competitor implementations. It is not independent "
                "penetration testing or a production security certification."
            ),
        }

    def write(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.report(), sort_keys=True, indent=2, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        return target
