from __future__ import annotations

import os
import socket
from pathlib import Path

from paca_client import PACAClient


def expect_unreachable(host: str, port: int, label: str) -> None:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            raise AssertionError(f"direct_{label}_bypass_was_reachable")
    except OSError:
        print(f"PASS: direct {label} connection is blocked")


def main() -> None:
    assert os.geteuid() != 0, "agent_host_must_not_run_as_root"

    for name in ("PACA_DATABASE_URL", "PACA_API_BEARER_TOKEN", "PACA_OPA_BEARER_TOKEN"):
        assert not os.environ.get(name), f"agent_host_must_not_receive_{name}"

    protected_file = Path("/srv/paca-protected/secret.txt")
    try:
        protected_file.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        print("PASS: protected file is not mounted into the agent container")
    else:
        raise AssertionError("direct_protected_file_bypass_was_reachable")

    try:
        Path("/opt/paca-host/rootfs-write-probe").write_text("must fail", encoding="utf-8")
    except OSError:
        print("PASS: container root filesystem is read-only")
    else:
        raise AssertionError("agent_container_root_filesystem_is_writable")

    expect_unreachable("protected-db", 5432, "PostgreSQL")
    expect_unreachable("downstream-api", 8080, "downstream API")
    expect_unreachable("1.1.1.1", 443, "unapproved internet egress")

    client = PACAClient(
        base_url=os.environ["PACA_BASE_URL"],
        access_token="harness-only-agent-token",
    )
    action = "file.read"
    resource_id = "protected-document-1"
    arguments = {"format": "text"}
    permit = client.authorize(
        action=action,
        resource_id=resource_id,
        arguments=arguments,
    )
    result = client.execute(
        action=action,
        resource_id=resource_id,
        arguments=arguments,
        permit_id=permit["permit_id"],
        idempotency_key="host-isolation-harness-001",
    )
    assert result.get("status") == "succeeded", result
    print("PASS: PACA HTTPS authorize/execute path is reachable")
    print("PASS: host isolation boundary checks completed")


if __name__ == "__main__":
    main()
