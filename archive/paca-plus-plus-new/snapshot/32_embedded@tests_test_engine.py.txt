from paca import Policy, PolicySet, PolicyEngine, evaluate_policy


def test_policy_engine_deny_overrides():
    allow_manager = Policy(
        name="allow-manager",
        action="readFile",
        expressions=[
            {"entity": "user", "attribute": "role", "operator": "==", "value": "admin"}.get("entity") and None
        ],
        effect="permit",
    )

    # Keep the test oriented to real API usage.
    policy = Policy(
        name="admin-read",
        action="readFile",
        expressions=[],
        effect="permit",
    )

    engine = PolicyEngine(strategy="deny_overrides", default_decision="deny")
    result = engine.evaluate(policy, {"user": {"role": "admin"}})
    assert result.decision == "permit"
    assert result.passed is True

    policy_set = PolicySet(
        name="ops",
        policies=[
            Policy(
                name="deny-guest",
                action="deleteFile",
                expressions=[],
                effect="deny",
            ),
            Policy(
                name="allow-admin",
                action="deleteFile",
                expressions=[],
                effect="permit",
            ),
        ],
        strategy="deny_overrides",
    )

    set_result = engine.evaluate_set(policy_set, {"user": {"role": "guest"}})
    assert set_result.decision == "deny"


def test_evaluate_policy_with_or_logic():
    policy = evaluate_policy(
        "permit readFile when user.role == admin or user.role == auditor",
        {"user": {"role": "auditor"}},
    )
    assert policy.decision == "permit"
    assert policy.passed is True
