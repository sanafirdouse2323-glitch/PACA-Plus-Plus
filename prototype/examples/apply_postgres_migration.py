"""Apply the checked-in PostgreSQL schema migration using a dedicated migration DSN.

Set PACA_MIGRATION_DSN explicitly to avoid accidentally running schema changes
against a production database via a runtime service environment variable.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from paca_mvp.postgres import PostgresPermitStore


def main() -> None:
    dsn = os.environ.get("PACA_MIGRATION_DSN", "").strip()
    if not dsn:
        raise SystemExit("Set PACA_MIGRATION_DSN to the intended PostgreSQL database")

    # Constructing this store with schema initialization disabled validates the
    # DSN (including TLS verification for non-loopback hosts) without applying DDL.
    store = PostgresPermitStore(dsn, initialize_schema=False)
    migration = Path(__file__).resolve().parents[1] / "migrations" / "001_postgres_schema.sql"
    sql = migration.read_text(encoding="utf-8")
    lines = [
        line for line in sql.splitlines()
        if line.strip().upper() not in {"BEGIN;", "COMMIT;"}
    ]
    statements = [statement.strip() for statement in "\n".join(lines).split(";")
                  if statement.strip()]

    with store._connect() as db:
        for statement in statements:
            db.execute(statement)
    print(f"Applied {migration.name} to the explicitly configured PostgreSQL database")


if __name__ == "__main__":
    main()
