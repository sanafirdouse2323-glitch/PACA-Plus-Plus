from __future__ import annotations

from paca_service.benchmarks.security_benchmark import SecurityBenchmarkRecorder
import pytest


def test_benchmark_reports_measured_rates_and_labeled_reference_controls():
    benchmark = SecurityBenchmarkRecorder()
    benchmark.record_attack(
        "wrong_audience", status_code=401, attack_succeeded=False, latency_ms=8.2
    )
    benchmark.record_attack(
        "permit_rebind", status_code=409, attack_succeeded=False, latency_ms=12.4
    )
    benchmark.record_legitimate(
        "file_read", status_code=200, task_succeeded=True, latency_ms=24.2
    )
    benchmark.record_reliability(
        "same_key_replay", status_code=200, passed=True, latency_ms=3.1
    )

    report = benchmark.report()
    paca = report["paca_plus_plus"]
    assert paca["attack_attempts"] == 2
    assert paca["attack_successes"] == 0
    assert paca["attack_success_rate"] == 0
    assert paca["legitimate_task_success_rate"] == 1
    assert paca["reliability_passes"] == 1
    assert paca["latency_ms_p50"] == 8.2
    assert paca["latency_ms_p95"] == 24.2
    assert report["modeled_reference_controls"]["unguarded_no_authorization"][
        "executed_in_this_run"
    ] is False
    assert report["independent_evaluation"] is False
    assert report["third_party_competitor_comparison"] is False


def test_benchmark_rejects_non_finite_latency():
    benchmark = SecurityBenchmarkRecorder()
    with pytest.raises(ValueError, match="invalid_benchmark_observation"):
        benchmark.record_attack(
            "bad_latency", status_code=403, attack_succeeded=False, latency_ms=float("nan")
        )
