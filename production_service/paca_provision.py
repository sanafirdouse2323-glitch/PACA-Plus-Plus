from __future__ import annotations

import argparse
import csv
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SERVICE_DIR = Path(__file__).resolve().parent
ENV_FILE = SERVICE_DIR / ".env"
COMPOSE_FILE = SERVICE_DIR / "compose.yaml"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_RESOURCES = 500
MAX_ATTRIBUTES_BYTES = 64 * 1024


class ProvisionError(RuntimeError):
    """A safe, actionable resource-provisioning error."""


def _identifier(value: Any, field: str, limit: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > limit
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ProvisionError(f"{field} must be a non-empty string of at most {limit} safe characters.")
    return value


def validate_manifest(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or set(document) != {"resources"}:
        raise ProvisionError("Manifest must be an object containing only a 'resources' array.")
    resources = document["resources"]
    if not isinstance(resources, list) or not 1 <= len(resources) <= MAX_RESOURCES:
        raise ProvisionError(f"Manifest must contain between 1 and {MAX_RESOURCES} resources.")

    validated: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    allowed_fields = {
        "tenant_id", "resource_id", "owner_id", "kind", "status", "attributes"
    }
    for index, item in enumerate(resources, 1):
        if not isinstance(item, dict) or not set(item).issubset(allowed_fields):
            raise ProvisionError(f"Resource {index} contains invalid or unsupported fields.")
        required = {"tenant_id", "resource_id", "owner_id", "kind"}
        if not required.issubset(item):
            raise ProvisionError(f"Resource {index} is missing one or more required fields.")

        tenant_id = _identifier(item["tenant_id"], f"Resource {index} tenant_id", 512)
        resource_id = _identifier(item["resource_id"], f"Resource {index} resource_id", 256)
        owner_id = _identifier(item["owner_id"], f"Resource {index} owner_id", 512)
        kind = _identifier(item["kind"], f"Resource {index} kind", 128)
        status = item.get("status", "active")
        if not isinstance(status, str) or status not in {"active", "inactive"}:
            raise ProvisionError(f"Resource {index} status must be 'active' or 'inactive'.")
        attributes = item.get("attributes", {})
        if not isinstance(attributes, dict):
            raise ProvisionError(f"Resource {index} attributes must be a JSON object.")
        try:
            attributes_json = json.dumps(
                attributes, ensure_ascii=True, allow_nan=False, separators=(",", ":")
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise ProvisionError(f"Resource {index} attributes must contain finite JSON values.") from exc
        if len(attributes_json.encode("utf-8")) > MAX_ATTRIBUTES_BYTES:
            raise ProvisionError(f"Resource {index} attributes exceed the 64 KiB limit.")

        identity = (tenant_id, resource_id)
        if identity in seen:
            raise ProvisionError(f"Manifest contains duplicate tenant/resource identity at resource {index}.")
        seen.add(identity)
        validated.append(
            {
                "tenant_id": tenant_id,
                "resource_id": resource_id,
                "owner_id": owner_id,
                "kind": kind,
                "status": status,
                "attributes_json": attributes_json,
            }
        )
    return validated


def read_manifest(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProvisionError(f"Could not read manifest: {exc}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ProvisionError("Manifest exceeds the 4 MiB size limit.")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ProvisionError("Manifest must be valid UTF-8 JSON within the supported nesting depth.") from exc
    return validate_manifest(document)


def _actor(value: str) -> str:
    return _identifier(value, "Operator actor", 128)


def _csv_payload(resources: list[dict[str, Any]], actor: str) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for resource in resources:
        writer.writerow(
            [
                resource["tenant_id"],
                resource["resource_id"],
                resource["owner_id"],
                resource["kind"],
                resource["status"],
                resource["attributes_json"],
                actor,
            ]
        )
    return stream.getvalue()


def _copy_sql() -> str:
    return """\
DO $paca_admin_check$
DECLARE
    v_can_bypass_rls BOOLEAN;
    v_can_insert_resources BOOLEAN;
    v_can_insert_audit BOOLEAN;
    v_can_use_audit_sequence BOOLEAN;
BEGIN
    SELECT (r.rolsuper OR r.rolbypassrls),
           has_table_privilege(current_user, 'public.protected_resources', 'INSERT'),
           has_table_privilege(current_user, 'public.audit_events', 'INSERT'),
           has_sequence_privilege(current_user, 'public.audit_events_event_id_seq', 'USAGE')
      INTO v_can_bypass_rls, v_can_insert_resources, v_can_insert_audit,
           v_can_use_audit_sequence
      FROM pg_catalog.pg_roles AS r
     WHERE r.rolname = current_user;
    IF current_user = 'paca_runtime'
       OR NOT COALESCE(v_can_bypass_rls, FALSE)
       OR NOT COALESCE(v_can_insert_resources, FALSE)
       OR NOT COALESCE(v_can_insert_audit, FALSE)
       OR NOT COALESCE(v_can_use_audit_sequence, FALSE) THEN
        RAISE EXCEPTION 'resource provisioning requires a dedicated BYPASSRLS/superuser administrator with INSERT privileges';
    END IF;
END
$paca_admin_check$;

CREATE TEMP TABLE paca_provision_input (
    tenant_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    attributes_json TEXT NOT NULL,
    operator_actor TEXT NOT NULL
) ON COMMIT DROP;

COPY paca_provision_input
    (tenant_id, resource_id, owner_id, kind, status, attributes_json, operator_actor)
FROM STDIN WITH (FORMAT csv);
"""


def build_psql_script(resources: list[dict[str, Any]], actor: str) -> str:
    return (
        _copy_sql()
        + _csv_payload(resources, _actor(actor))
        + """\\.
INSERT INTO public.protected_resources
    (tenant_id, resource_id, owner_id, kind, status, attributes)
SELECT tenant_id, resource_id, owner_id, kind, status, attributes_json::jsonb
FROM paca_provision_input
ORDER BY tenant_id, resource_id;

INSERT INTO public.audit_events
    (tenant_id, principal_id, event_type, resource_id, details)
SELECT tenant_id, NULL, 'resource_provisioned', resource_id,
       jsonb_build_object(
           'source', 'paca_admin_cli',
           'operator', operator_actor,
           'resource_kind', kind
       )
FROM paca_provision_input
ORDER BY tenant_id, resource_id;
"""
    )


def _provision_over_direct_dsn(
    dsn: str, resources: list[dict[str, Any]], actor: str
) -> None:
    try:
        parameters = conninfo_to_dict(dsn)
    except Exception as exc:
        raise ProvisionError("PACA_ADMIN_DATABASE_URL is not a valid PostgreSQL connection string.") from exc
    if parameters.get("sslmode") != "verify-full":
        raise ProvisionError(
            "PACA_ADMIN_DATABASE_URL must set sslmode=verify-full for direct database connections."
        )

    try:
        with psycopg.connect(dsn, connect_timeout=5, row_factory=dict_row) as connection, connection.transaction():
            role = connection.execute(
                """
                SELECT current_user AS role_name,
                       (r.rolsuper OR r.rolbypassrls) AS can_bypass_rls,
                       has_table_privilege(current_user, 'public.protected_resources', 'INSERT')
                           AS can_insert_resources,
                       has_table_privilege(current_user, 'public.audit_events', 'INSERT')
                           AS can_insert_audit
                FROM pg_catalog.pg_roles AS r
                WHERE r.rolname = current_user
                """
            ).fetchone()
            if (
                not role
                or role["role_name"] == "paca_runtime"
                or not role["can_bypass_rls"]
                or not role["can_insert_resources"]
                or not role["can_insert_audit"]
            ):
                raise ProvisionError(
                    "Database role lacks the required administrator/BYPASSRLS and INSERT privileges."
                )
            for resource in resources:
                connection.execute(
                    """
                    INSERT INTO public.protected_resources
                        (tenant_id, resource_id, owner_id, kind, status, attributes)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        resource["tenant_id"],
                        resource["resource_id"],
                        resource["owner_id"],
                        resource["kind"],
                        resource["status"],
                        Jsonb(json.loads(resource["attributes_json"])),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO public.audit_events
                        (tenant_id, principal_id, event_type, resource_id, details)
                    VALUES (%s, NULL, 'resource_provisioned', %s, %s)
                    """,
                    (
                        resource["tenant_id"],
                        resource["resource_id"],
                        Jsonb(
                            {
                                "source": "paca_admin_cli",
                                "operator": actor,
                                "resource_kind": resource["kind"],
                            }
                        ),
                    ),
                )
    except ProvisionError:
        raise
    except psycopg.Error as exc:
        raise ProvisionError(
            "PostgreSQL rejected provisioning; the transaction was rolled back. "
            "Check the administrator role, schema/grants, duplicate resource IDs and database health."
        ) from exc


def _provision_over_compose(
    resources: list[dict[str, Any]], actor: str
) -> None:
    if not ENV_FILE.is_file():
        raise ProvisionError(
            "No production_service/.env found. Run paca_deploy.py init or provide "
            "PACA_ADMIN_DATABASE_URL with sslmode=verify-full."
        )
    command = [
        "docker",
        "compose",
        "--env-file",
        str(ENV_FILE),
        "-f",
        str(COMPOSE_FILE),
        "exec",
        "-T",
        "database",
        "psql",
        "--no-psqlrc",
        "--no-password",
        "--quiet",
        "--set=ON_ERROR_STOP=1",
        "--single-transaction",
        "--username",
        "paca",
        "--dbname",
        "paca",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=SERVICE_DIR,
            input=build_psql_script(resources, actor),
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ProvisionError("Docker Compose v2 is required for local Compose provisioning.") from exc
    if result.returncode:
        raise ProvisionError(
            "The database rejected resource provisioning; the single transaction was rolled back. "
            "Confirm the database is running and the paca bootstrap administrator can connect."
        ) from None


def provision(manifest_path: Path, actor: str) -> int:
    validated = read_manifest(manifest_path)
    operator = _actor(actor)
    admin_dsn = os.getenv("PACA_ADMIN_DATABASE_URL", "").strip()
    if admin_dsn:
        _provision_over_direct_dsn(admin_dsn, validated, operator)
    else:
        _provision_over_compose(validated, operator)
    print(
        f"Provisioned {len(validated)} protected resource(s); "
        "one append-only administrative audit event was recorded for each."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision trusted PACA++ resource records using a database administrator identity."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    resource_parser = subparsers.add_parser(
        "resources", help="Create protected resource facts from a reviewed JSON manifest."
    )
    resource_parser.add_argument("--manifest", required=True, type=Path)
    resource_parser.add_argument(
        "--actor",
        required=True,
        help="Operator identity label recorded in the administrative audit event.",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "resources":
            return provision(args.manifest, args.actor)
    except ProvisionError as exc:
        print(f"Provisioning error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
