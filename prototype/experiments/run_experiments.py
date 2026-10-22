import json
import pathlib
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from paca_mvp import AuthorizationEngine, Policy
from paca_mvp.engine import AuthorizationError

POLICY = {
    "version": "experiment-v1",
    "rules": [
        {"id": "read_owned", "effect": "permit", "action": "file.read", "conditions": [
            {"path": "user.role", "op": "eq", "value": "analyst"},
            {"path": "resource.owner", "op": "eq", "value_from_path": "user.id"},
        ]},
        {"id": "deny_suspended", "effect": "deny", "action": "file.read", "conditions": [
            {"path": "user.suspended", "op": "eq", "value": True},
        ]},
        {"id": "deny_delete", "effect": "deny", "action": "file.delete", "conditions": []},
    ],
}


def main():
    scenarios = json.loads((ROOT / "experiments" / "scenarios.json").read_text())
    outcomes = []
    by_family = defaultdict(lambda: {"n": 0, "authorization_correct": 0, "effect_correct": 0})
    for scenario in scenarios["scenarios"]:
        engine = AuthorizationEngine(Policy.from_dict(POLICY))
        principal_id = scenario.get("context", {}).get("user", {}).get("id")
        operation_args = {
            "scenario_id": scenario["id"],
            "requested_action": scenario["action"],
            "requested_resource": scenario["resource"],
        }
        decision = engine.authorize_operation(
            principal_id, scenario["action"], scenario["resource"], operation_args, scenario["context"]
        )
        effect_calls = []
        if decision.allowed:
            if scenario.get("advance_state_before_execute"):
                engine.advance_state()
            if scenario.get("update_policy_before_execute"):
                engine.update_policy(Policy.from_dict({**POLICY, "version": "experiment-v2"}))
            exec_action = scenario.get("execute_action_override", scenario["action"])
            exec_resource = scenario.get("execute_resource_override", scenario["resource"])
            try:
                engine.execute_operation(
                    decision.permit_id, principal_id, exec_action, exec_resource, operation_args, scenario["context"],
                    lambda: effect_calls.append("committed"),
                )
                if scenario.get("replay"):
                    try:
                        engine.execute_operation(
                            decision.permit_id, principal_id, exec_action, exec_resource, operation_args, scenario["context"],
                            lambda: effect_calls.append("replayed"),
                        )
                    except AuthorizationError:
                        pass
            except AuthorizationError:
                pass
        authorization_correct = decision.allowed == scenario["expected_allowed"]
        if "expected_effect_count" in scenario:
            effect_correct = len(effect_calls) == scenario["expected_effect_count"]
        else:
            effect_correct = (len(effect_calls) > 0) == scenario["expected_effect"]
        family = scenario["family"]
        by_family[family]["n"] += 1
        by_family[family]["authorization_correct"] += int(authorization_correct)
        by_family[family]["effect_correct"] += int(effect_correct)
        outcomes.append({
            "id": scenario["id"], "family": family, "decision_allowed": decision.allowed,
            "expected_allowed": scenario["expected_allowed"], "effect_occurred": len(effect_calls) > 0,
            "expected_effect": scenario["expected_effect"],
            "expected_effect_count": scenario.get("expected_effect_count"),
            "observed_effect_count": len(effect_calls),
            "authorization_correct": authorization_correct, "effect_correct": effect_correct,
            "decision_reason": decision.reason,
        })
    total = len(outcomes)
    summary = {
        "n": total,
        "authorization_decision_accuracy": sum(x["authorization_correct"] for x in outcomes) / total,
        "effect_outcome_accuracy": sum(x["effect_correct"] for x in outcomes) / total,
    }
    print("Scenarios:", total)
    print("Authorization decision accuracy:", sum(x["authorization_correct"] for x in outcomes), "/", total)
    print("Effect outcome accuracy:", sum(x["effect_correct"] for x in outcomes), "/", total)
    print("\nPer scenario:")
    for item in outcomes:
        print(f'{item["id"]} {item["family"]}: decision={item["decision_allowed"]}, '
              f'effect={item["effect_occurred"]}, decision_ok={item["authorization_correct"]}, '
              f'effect_ok={item["effect_correct"]}')
    out = ROOT / "experiments" / "results.json"
    out.write_text(json.dumps({"summary": summary, "by_family": dict(by_family), "scenarios": outcomes}, indent=2) + "\n")
    print("\nSaved:", out.relative_to(ROOT))


if __name__ == "__main__":
    main()
