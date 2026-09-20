# Infrastructure Discovery

Requires Python 3.11 or newer.

## Inventory loading

Use a UTF-8 JSON array, as shown in
[`examples/inventory.example.json`](examples/inventory.example.json). The example
uses reserved example names and documentation addresses, with no credentials.

```python
from infra_discovery.inventory import load_inventory

targets = load_inventory("examples/inventory.example.json")
```

Each entry must contain exactly `id`, `host`, and `kind`, all nonempty strings
without surrounding whitespace. Kinds are case-sensitive: `network` or `linux`.
IDs must be unique; multiple entries may share a host. Host strings are preserved
without address validation, name resolution, or network access.

The loader returns existing `Target` objects in inventory order, with `TargetKind`
enum values. An empty array returns an empty list. Invalid content raises
`InventoryError` (a `ValueError`) without returning a partial inventory. Unknown
fields, duplicate JSON keys, and nonstandard JSON constants are rejected. File
access errors propagate as `OSError`. Validation messages identify entry positions
and field names without echoing inventory values.

## Development

From the repository root, create and activate a virtual environment (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
```

The `dev` extra installs pytest. Installing the project makes its `src` package
available to Python and the tests.

## Continuous integration

GitHub Actions runs on pull requests targeting `main` and pushes to `main`.
It uses Python 3.14 on Ubuntu, installs the project and test dependencies with
`python -m pip install ".[dev]"`, and runs the complete suite with
`python -m pytest`.
