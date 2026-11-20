from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

import paca_provision


def resource(**overrides):
    item = {
        "tenant_id": "tenant-a",
        "resource_id": "file-001",
        "owner_id": "subject-123",
        "kind": "file",
        "attributes": {"relative_path": "tenant-a/file-001.txt"},
    }
    item.update(overrides)
    return item


def manifest(*items):
    return {"resources": list(items)}


def test_manifest_defaults_status_and_empty_attributes():
    rows = paca_provision.validate_manifest(
        manifest({"tenant_id": "t", "resource_id": "r", "owner_id": "s", "kind": "file"})
    )
    assert rows == [
        {
            "tenant_id": "t",
            "resource_id": "r",
            "owner_id": "s",
            "kind": "file",
            "status": "active",
            "attributes_json": "{}",
        }
    ]


def test_manifest_rejects_duplicate_resource_identity():
    with pytest.raises(paca_provision.ProvisionError, match="duplicate"):
        paca_provision.validate_manifest(manifest(resource(), resource(owner_id="another-subject")))


@pytest.mark.parametrize(
    "item",
    [
        resource(status="deleted"),
        resource(status="unknown"),
        resource(owner_id=""),
        resource(tenant_id=" tenant-a"),
        resource(attributes=[]),
        resource(unexpected="not-accepted"),
        resource(attributes={"not_finite": float("nan")}),
    ],
)
def test_manifest_rejects_unsafe_or_unsupported_values(item):
    with pytest.raises(paca_provision.ProvisionError):
        paca_provision.validate_manifest(manifest(item))


def test_manifest_rejects_json_object_larger_than_limit():
    with pytest.raises(paca_provision.ProvisionError, match="64 KiB"):
        paca_provision.validate_manifest(
            manifest(resource(attributes={"blob": "x" * (65 * 1024)}))
        )


def test_csv_script_keeps_operator_values_in_copy_data_and_audits_each_row():
    rows = paca_provision.validate_manifest(
        manifest(resource(resource_id="id,with,commas", owner_id="owner' ; DROP TABLE audit_events; --"))
    )
    script = paca_provision.build_psql_script(rows, "operator 'quoted'")
    copy_header = "FROM STDIN WITH (FORMAT csv);\n"
    payload_start = script.index(copy_header) + len(copy_header)
    marker = "\n\\.\n"
    copy_end = script.index(marker, payload_start)
    csv_payload = script[payload_start:copy_end]
    sql_header = script[:payload_start]
    sql_tail = script[copy_end + len(marker):]

    assert "COPY paca_provision_input" in sql_header
    assert "owner' ; DROP TABLE" in csv_payload
    assert "owner' ; DROP TABLE" not in sql_tail
    assert "INSERT INTO public.protected_resources" in sql_tail
    assert "INSERT INTO public.audit_events" in sql_tail
    assert "'resource_provisioned'" in sql_tail
    assert "ON CONFLICT" not in script
    assert "UPDATE public.protected_resources" not in script


def test_local_compose_provisioning_uses_one_transaction_and_admin_socket(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("POSTGRES_PASSWORD=not-used-by-socket-auth\n", encoding="utf-8")
    monkeypatch.setattr(paca_provision, "ENV_FILE", env_file)
    monkeypatch.setattr(paca_provision, "COMPOSE_FILE", tmp_path / "compose.yaml")
    subprocess = Mock(return_value=Mock(returncode=0))
    monkeypatch.setattr(paca_provision.subprocess, "run", subprocess)

    rows = paca_provision.validate_manifest(manifest(resource()))
    paca_provision._provision_over_compose(rows, "operator@example.test")

    command = subprocess.call_args.args[0]
    script = subprocess.call_args.kwargs["input"]
    assert command[:3] == ["docker", "compose", "--env-file"]
    assert "--single-transaction" in command
    assert "--username" in command and command[command.index("--username") + 1] == "paca"
    assert "paca_runtime" in script  # explicitly rejected by the SQL administrator gate
    assert "BYPASSRLS" in script
    assert "\\." in script


def test_direct_admin_connection_requires_full_tls_before_connect(monkeypatch):
    connect = Mock()
    monkeypatch.setattr(paca_provision.psycopg, "connect", connect)
    rows = paca_provision.validate_manifest(manifest(resource()))

    with pytest.raises(paca_provision.ProvisionError, match="sslmode=verify-full"):
        paca_provision._provision_over_direct_dsn(
            "postgresql://admin:secret@db.example.test/paca?sslmode=require",
            rows,
            "operator",
        )
    connect.assert_not_called()


def test_direct_admin_role_check_rejects_runtime_or_non_bypass_role(monkeypatch):
    class Transaction:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Cursor:
        def fetchone(self):
            return {
                "role_name": "paca_runtime",
                "can_bypass_rls": False,
                "can_insert_resources": True,
                "can_insert_audit": True,
            }

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def transaction(self):
            return Transaction()

        def execute(self, *_args):
            return Cursor()

    connect = Mock(return_value=Connection())
    monkeypatch.setattr(paca_provision.psycopg, "connect", connect)
    rows = paca_provision.validate_manifest(manifest(resource()))

    with pytest.raises(paca_provision.ProvisionError, match="BYPASSRLS"):
        paca_provision._provision_over_direct_dsn(
            "postgresql://admin:secret@db.example.test/paca?sslmode=verify-full",
            rows,
            "operator",
        )


def test_read_manifest_requires_exact_top_level_shape(tmp_path: Path):
    path = tmp_path / "resources.json"
    path.write_text(json.dumps({"resources": [resource()], "tenant": "not-supported"}))
    with pytest.raises(paca_provision.ProvisionError, match="only a 'resources'"):
        paca_provision.read_manifest(path)
