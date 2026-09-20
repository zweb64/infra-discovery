"""Load validated target inventories from UTF-8 JSON files."""

import json
from pathlib import Path

from infra_discovery.models import Target, TargetKind


class InventoryError(ValueError):
    """The inventory is not valid JSON or violates the inventory schema."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("Inventory contains a duplicate object key.")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise InventoryError("Inventory contains a non-JSON numeric constant.")


def load_inventory(path: str | Path) -> list[Target]:
    """Load a JSON array of targets, or raise InventoryError for invalid content.

    Entries must contain exactly id, host, and kind. Strings must be nonempty
    without surrounding whitespace; IDs must be unique. An empty array is valid.
    File access errors propagate as OSError. No network operations are performed.
    """
    try:
        with Path(path).open(encoding="utf-8") as inventory_file:
            entries = json.load(
                inventory_file,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
    except (json.JSONDecodeError, UnicodeError):
        raise InventoryError("Inventory must contain valid UTF-8 JSON.") from None

    if not isinstance(entries, list):
        raise InventoryError("Inventory must be a JSON array.")

    targets = []
    seen_ids = set()
    for index, entry in enumerate(entries):
        location = f"Inventory entry {index + 1}"
        if not isinstance(entry, dict) or set(entry) != {"id", "host", "kind"}:
            raise InventoryError(
                f"{location} must be an object with exactly id, host, and kind."
            )
        for field in ("id", "host", "kind"):
            value = entry[field]
            if not isinstance(value, str) or not value or value != value.strip():
                raise InventoryError(
                    f"{location}: {field} must be a nonempty string "
                    "without surrounding whitespace."
                )
        try:
            kind = TargetKind(entry["kind"])
        except ValueError:
            raise InventoryError(f"{location} has an unsupported target kind.") from None
        if entry["id"] in seen_ids:
            raise InventoryError(f"{location} has a duplicate id.")
        seen_ids.add(entry["id"])
        targets.append(Target(id=entry["id"], host=entry["host"], kind=kind))
    return targets
