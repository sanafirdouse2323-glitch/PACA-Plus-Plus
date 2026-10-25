"""Apply ordered PostgreSQL migrations using an explicit migration DSN.

Migrations run in order and are recorded in paca_schema_migrations. The
migration DSN is intentionally separate from the runtime service DSN.
"""
from __future__ import annotations

import os
from pathlib import Path

from paca_mvp.postgres import PostgresPermitStore


def main() -> None:
    dsn = os.environ.get("PACA_MIGRATION_DSN", "").strip()
    if not dsn:
        raise SystemExit("Set PACA_MIGRATION_DSN to the intended PostgreSQL database")

    # Validate the DSN (including TLS verification for non-loopback hosts)
    # without automatically applying schema changes.
    store = PostgresPermitStore(dsn, initialize_schema=False)
    migration_dir = Path(__file__).resolve().parents[1] / "migrations"
    migrations = sorted(
        path for path in migration_dir.glob("[0-9][0-9][0-9]_*.sql")
        if path.is_file()
    )
    if not migrations:
        raise SystemExit(f"No numbered SQL migrations found in {migration_dir}")

    with store._connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS paca_schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

    applied: list[str] = []
    skipped: list[str] = []
    for migration in migrations:
        version = migration.stem
        sql = migration.read_text(encoding="utf-8")
        lines = [
            line for line in sql.splitlines()
            if line.strip().upper() not in {"BEGIN;", "COMMIT;"}
        ]
        statements = [
            statement.strip()
            for statement in "\n".join(lines).split(";")
            if statement.strip()
        ]

        # Serialize migration runners and commit each migration plus its version
        # marker in one transaction. Existing installations without a version
        # table safely re-apply the idempotent initial migration once.
        with store._connect() as db:
            db.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                ("paca-schema-migration-runner",),
            )
            exists = db.execute(
                "SELECT 1 FROM paca_schema_migrations WHERE version = %s",
                (version,),
            ).fetchone()
            if exists:
                skipped.append(version)
                continue
            for statement in statements:
                db.execute(statement)
            db.execute(
                "INSERT INTO paca_schema_migrations(version) VALUES (%s)",
                (version,),
            )
        applied.append(version)

    # Verify the local chain and enqueue pre-outbox audit history after all
    # migration tables exist. The exporter subsequently delivers at least once.
    queued = store.backfill_audit_outbox()
    print(f"Applied migrations: {', '.join(applied) if applied else 'none'}")
    print(f"Already applied: {', '.join(skipped) if skipped else 'none'}")
    print(f"Queued retained audit events for independent delivery: {queued}")


if __name__ == "__main__":
    main()
