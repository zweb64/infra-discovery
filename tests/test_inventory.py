import json
from pathlib import Path

import pytest

from infra_discovery.inventory import InventoryError, load_inventory
from infra_discovery.models import Target, TargetKind


def write_inventory(tmp_path: Path, content: object) -> Path:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


def valid_entry() -> dict[str, str]:
    return {"id": "switch-01", "host": "switch.example.com", "kind": "network"}


@pytest.mark.parametrize("string_path", [False, True])
def test_load_mixed_inventory(tmp_path: Path, string_path: bool) -> None:
    path = write_inventory(tmp_path, [
        valid_entry(),
        {"id": "linux-01", "host": "192.0.2.2", "kind": "linux"},
        {"id": "linux-02", "host": "2001:db8::2", "kind": "linux"},
    ])
    assert load_inventory(str(path) if string_path else path) == [
        Target("switch-01", "switch.example.com", TargetKind.NETWORK),
        Target("linux-01", "192.0.2.2", TargetKind.LINUX),
        Target("linux-02", "2001:db8::2", TargetKind.LINUX),
    ]


def test_empty_inventory(tmp_path: Path) -> None:
    assert load_inventory(write_inventory(tmp_path, [])) == []


@pytest.mark.parametrize("content", [{}, {"targets": []}, None, True, 1, "text"])
def test_reject_non_array_root(tmp_path: Path, content: object) -> None:
    with pytest.raises(InventoryError, match="JSON array"):
        load_inventory(write_inventory(tmp_path, content))


@pytest.mark.parametrize("entry", [None, True, 1, "text", [], {}])
def test_reject_invalid_entry(tmp_path: Path, entry: object) -> None:
    with pytest.raises(InventoryError, match="entry 2"):
        load_inventory(write_inventory(tmp_path, [valid_entry(), entry]))


@pytest.mark.parametrize("field", ["id", "host", "kind"])
def test_reject_missing_field(tmp_path: Path, field: str) -> None:
    entry = valid_entry()
    del entry[field]
    with pytest.raises(InventoryError, match="exactly id, host, and kind"):
        load_inventory(write_inventory(tmp_path, [entry]))


@pytest.mark.parametrize("field", ["id", "host", "kind"])
@pytest.mark.parametrize("value", [None, True, 123, 1.5, [], {}, "", " ", "\t\n",
                                     " leading", "trailing "])
def test_reject_invalid_field_values(
    tmp_path: Path, field: str, value: object
) -> None:
    entry = {**valid_entry(), field: value}
    with pytest.raises(InventoryError, match=field):
        load_inventory(write_inventory(tmp_path, [entry]))


def test_reject_unknown_field_without_echoing_data(tmp_path: Path) -> None:
    entry = {**valid_entry(), "unexpected-marker": "private-marker"}
    with pytest.raises(InventoryError) as error:
        load_inventory(write_inventory(tmp_path, [entry]))
    assert "unexpected-marker" not in str(error.value)
    assert "private-marker" not in str(error.value)


@pytest.mark.parametrize("kind", ["windows", "NETWORK", "Linux", "private-marker"])
def test_reject_unsupported_kind(tmp_path: Path, kind: str) -> None:
    with pytest.raises(InventoryError, match="unsupported target kind") as error:
        load_inventory(write_inventory(tmp_path, [{**valid_entry(), "kind": kind}]))
    assert kind not in str(error.value)


def test_reject_duplicate_id_across_kinds(tmp_path: Path) -> None:
    entries = [valid_entry(), {**valid_entry(), "kind": "linux"}]
    with pytest.raises(InventoryError, match="entry 2 has a duplicate id"):
        load_inventory(write_inventory(tmp_path, entries))


def test_allow_shared_host_and_preserve_unicode_id(tmp_path: Path) -> None:
    entries = [valid_entry(), {**valid_entry(), "id": "linux-\u00e9", "kind": "linux"}]
    targets = load_inventory(write_inventory(tmp_path, entries))
    assert targets[1].id == "linux-\u00e9"
    assert targets[0].host == targets[1].host


@pytest.mark.parametrize("raw", [
    "", "[", "[{},]", "[] []", "// comment\n[]",
    '[{"id":"first","id":"second","host":"host.example.com","kind":"linux"}]',
    "[NaN]", "[Infinity]", "[-Infinity]",
])
def test_reject_malformed_json(tmp_path: Path, raw: str) -> None:
    path = tmp_path / "targets.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(InventoryError):
        load_inventory(path)


def test_reject_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "targets.json"
    path.write_bytes(b'["\xff"]')
    with pytest.raises(InventoryError, match="UTF-8 JSON"):
        load_inventory(path)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_inventory(tmp_path / "missing.json")


def test_file_access_error_propagates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def deny_access(*args: object, **kwargs: object) -> None:
        raise PermissionError("Access denied")

    monkeypatch.setattr(Path, "open", deny_access)
    with pytest.raises(PermissionError):
        load_inventory(tmp_path / "targets.json")


def test_sanitized_example() -> None:
    path = Path(__file__).resolve().parents[1] / "examples" / "inventory.example.json"
    assert load_inventory(path) == [
        Target("switch-01", "switch-01.example.com", TargetKind.NETWORK),
        Target("router-01", "192.0.2.1", TargetKind.NETWORK),
        Target("linux-01", "linux-01.example.com", TargetKind.LINUX),
        Target("linux-02", "2001:db8::2", TargetKind.LINUX),
    ]
