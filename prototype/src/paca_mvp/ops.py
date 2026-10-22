"""Privileged local operations for durable recovery and audit verification.

Only run this CLI from an operator-controlled host with restricted database credentials.
It intentionally does not expose an unauthenticated network reconciliation endpoint.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from .durable import FernetResponseProtector, PostgresOperationStore, SQLiteOperationStore


def _store(args: argparse.Namespace):
    raw_keys = os.environ.get("PACA_RESULT_ENCRYPTION_KEYS", "").strip()
    protector = None
    if raw_keys:
        protector = FernetResponseProtector([key.strip() for key in raw_keys.split(",") if key.strip()])
    if args.backend == "postgres":
        dsn = args.dsn or os.environ.get("PACA_POSTGRES_DSN", "")
        if not dsn:
            raise ValueError("Use --dsn or set PACA_POSTGRES_DSN")
        if protector is None:
            raise ValueError("Set PACA_RESULT_ENCRYPTION_KEYS to the current response-encryption key and any retiring decrypt keys")
        return PostgresOperationStore(dsn, response_protector=protector, initialize_schema=False)
    path = args.path or os.environ.get("PACA_SQLITE_PATH", "")
    if not path:
        raise ValueError("Use --path or set PACA_SQLITE_PATH")
    return SQLiteOperationStore(path, response_protector=protector)


def _print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Privileged PACA++ durable-store operations")
    parser.add_argument("--backend", choices=("postgres", "sqlite"), required=True)
    parser.add_argument("--dsn", help="PostgreSQL DSN; alternatively PACA_POSTGRES_DSN")
    parser.add_argument("--path", help="SQLite database path; alternatively PACA_SQLITE_PATH")
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser("verify-audit", help="Verify the complete local audit hash chain")
    verify.set_defaults(handler="verify_audit")

    recover = commands.add_parser("recover-incomplete", help="Mark stale in-progress operations unknown")
    recover.add_argument("--older-than-seconds", type=float, default=60.0)
    recover.set_defaults(handler="recover_incomplete")

    show = commands.add_parser("show-operation", help="Show non-sensitive operation metadata")
    show.add_argument("--operation-id", required=True)
    show.set_defaults(handler="show_operation")

    reconcile = commands.add_parser("reconcile-unknown", help="Record a manually verified downstream outcome")
    reconcile.add_argument("--operation-id", required=True)
    reconcile.add_argument("--outcome", choices=("succeeded", "failed"), required=True)
    reconcile.add_argument("--reason", required=True,
                           help="Concise reference to independently verified downstream evidence")
    reconcile.add_argument("--response-stdin", action="store_true",
                           help="Read verified JSON response from stdin when outcome=succeeded")
    reconcile.set_defaults(handler="reconcile_unknown")

    args = parser.parse_args(argv)
    try:
        store = _store(args)
        if args.handler == "verify_audit":
            valid = store.verify_audit_chain()
            _print({"audit_chain_valid": valid})
            return 0 if valid else 2
        if args.handler == "recover_incomplete":
            recovered = store.recover_incomplete(args.older_than_seconds)
            _print({"recovered_as_unknown": recovered})
            return 0
        if args.handler == "show_operation":
            operation = store.get_operation(args.operation_id)
            if operation is None:
                _print({"error": "operation_not_found"})
                return 1
            _print({
                "operation_id": operation.operation_id,
                "principal_id": operation.principal_id,
                "action": operation.action,
                "resource": operation.resource,
                "status": operation.status,
                "created_at": operation.created_at,
                "expires_at": operation.expires_at,
                "started_at": operation.started_at,
                "finished_at": operation.finished_at,
                "error_code": operation.error_code,
                "arguments_digest": operation.arguments_digest,
                "context_digest": operation.context_digest,
            })
            return 0
        if args.handler == "reconcile_unknown":
            if args.outcome == "succeeded" and not args.response_stdin:
                raise ValueError("--response-stdin is required for outcome=succeeded")
            if args.outcome == "failed" and args.response_stdin:
                raise ValueError("--response-stdin is valid only for outcome=succeeded")
            response = None
            if args.response_stdin:
                try:
                    raw_response = sys.stdin.read(1_048_577)
                    if len(raw_response.encode("utf-8")) > 1_048_576:
                        raise ValueError("response exceeds 1 MiB")
                    response = json.loads(
                        raw_response,
                        parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)),
                    )
                except (json.JSONDecodeError, ValueError) as exc:
                    raise ValueError("--response-stdin must contain finite JSON up to 1 MiB") from exc
            operation = store.reconcile_unknown(
                args.operation_id, outcome=args.outcome, reason=args.reason, response=response
            )
            _print({"operation_id": operation.operation_id, "status": operation.status,
                    "finished_at": operation.finished_at, "error_code": operation.error_code})
            return 0
        raise RuntimeError("unhandled_command")
    except ValueError as exc:
        print(json.dumps({"error": "invalid_input", "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 2
    except Exception as exc:
        # Database exceptions may contain DSNs, SQL, or data. Do not print them to stdout/stderr.
        print(json.dumps({"error": type(exc).__name__, "message": "operation_failed; consult protected operator logs"}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
