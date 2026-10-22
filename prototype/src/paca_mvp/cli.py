"""Command-line entry point for the local PACA++ research MVP."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from .engine import AuthorizationEngine, Policy, PolicyError, AuthorizationError


def _read_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read {path!r}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path!r}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate a JSON policy and optionally run a simulated protected effect."
    )
    parser.add_argument("--policy", required=True, help="Path to a policy JSON file")
    parser.add_argument("--context", required=True, help="Path to a request context JSON file")
    parser.add_argument("--action", required=True, help="Exact action identifier, e.g. file.read")
    parser.add_argument("--resource", required=True, help="Exact resource identifier, e.g. file:report-1")
    parser.add_argument("--principal-id", required=True, help="Authenticated principal identifier supplied by the trusted caller")
    parser.add_argument("--arguments-json", default="{}", help="JSON object/value representing the exact operation arguments (default: {})")
    parser.add_argument("--execute", action="store_true",
                        help="Run a simulated effect if authorized; never calls an external tool")
    parser.add_argument("--ttl-seconds", type=float, default=30.0,
                        help="Permit lifetime (default: 30 seconds)")
    args = parser.parse_args(argv)

    try:
        policy = Policy.from_dict(_read_json(args.policy))
        context = _read_json(args.context)
        try:
            operation_arguments = json.loads(args.arguments_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in --arguments-json: {exc}") from exc
        engine = AuthorizationEngine(policy)
        decision = engine.authorize_operation(
            args.principal_id, args.action, args.resource, operation_arguments, context, args.ttl_seconds
        )
        result: dict[str, Any] = {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "matched_rules": list(decision.matched_rules),
            "policy_version": decision.policy_version,
            "effect": "not_requested",
        }
        if args.execute and decision.allowed:
            try:
                effect_result = engine.execute(
                    decision.permit_id, args.principal_id, args.action, args.resource, operation_arguments,
                    lambda: {"simulated": True, "action": args.action, "resource": args.resource},
                )
                result["effect"] = "simulated_success"
                result["effect_result"] = effect_result
            except AuthorizationError as exc:
                result["effect"] = "blocked"
                result["effect_error"] = str(exc)
        elif args.execute:
            result["effect"] = "not_run_authorization_denied"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ValueError, PolicyError, TypeError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
