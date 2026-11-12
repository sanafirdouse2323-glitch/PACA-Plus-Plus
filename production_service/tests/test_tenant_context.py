from __future__ import annotations

from paca_service.tenant_context import (
    TenantContextError,
    sign_tenant_context,
    tenant_context_message,
)

KEY = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")


def test_signature_is_stable_for_the_same_transaction_context():
    args = ("tenant-a", "principal-a", 1234, "987654", 1_800_000_000, 1_800_000_030, "v1")
    first = sign_tenant_context(KEY, *args)
    second = sign_tenant_context(KEY, *args)
    assert first == second
    assert len(first) == 64


def test_signature_changes_when_any_authorization_binding_changes():
    args = ["tenant-a", "principal-a", 1234, "987654", 1_800_000_000, 1_800_000_030, "v1"]
    original = sign_tenant_context(KEY, *args)
    for index, replacement in (
        (0, "tenant-b"),
        (1, "principal-b"),
        (2, 5678),
        (3, "987655"),
        (4, 1_800_000_001),
        (5, 1_800_000_031),
        (6, "v2"),
    ):
        changed = list(args)
        changed[index] = replacement
        assert sign_tenant_context(KEY, *changed) != original


def test_context_rejects_invalid_key_size_and_lifetime():
    with pytest.raises(TenantContextError, match="32 bytes"):
        sign_tenant_context(b"short", "t", "p", 1, "1", 100, 130, "v1")
    with pytest.raises(TenantContextError, match="lifetime"):
        tenant_context_message("t", "p", 1, "1", 100, 161, "v1")


def test_context_rejects_control_characters_and_invalid_transaction_ids():
    with pytest.raises(TenantContextError):
        tenant_context_message("tenant\nforged", "p", 1, "1", 100, 130, "v1")
    with pytest.raises(TenantContextError, match="transaction ID"):
        tenant_context_message("t", "p", 1, "not-an-xid", 100, 130, "v1")
