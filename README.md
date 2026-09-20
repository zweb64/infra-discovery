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

## Offline discovery

```python
from infra_discovery.collectors import FakeLinuxCollector, FakeNetworkCollector
from infra_discovery.discovery import discover
from infra_discovery.models import TargetKind

outcomes = discover(targets, {
    TargetKind.NETWORK: FakeNetworkCollector(),
    TargetKind.LINUX: FakeLinuxCollector(),
}, max_workers=4)
for outcome in outcomes:
    if outcome.succeeded:
        print(outcome.target.id, outcome.facts)
    else:
        print(outcome.target.id, outcome.error.value)
```

The fake collectors return fixed synthetic facts, independent of the host, and
perform no network access. Network facts contain a platform and interface names;
Linux facts contain a distribution and kernel release. A future collector only
needs to implement the `Collector` protocol: declare `kind` and implement
`collect(target)` to return the matching facts type or raise an exception.
Collectors must not mutate targets. With concurrency enabled, the same collector
instance can receive simultaneous calls; its state and resources must be safe for
that use. Callers must also leave targets unchanged until discovery returns.

`discover` accepts any finite iterable of `Target` objects, returning one
outcome per input in order, including repeated targets. Each outcome retains the
original target reference and exactly one of facts or a `DiscoveryError` enum.
The keyword-only `max_workers` defaults to `1`, preserving sequential calls on the
calling thread. Set it above one to use a bounded standard-library thread pool,
suitable for future blocking SSH/network collectors. Collection start and finish
order are unspecified in concurrent mode; returned outcomes always follow input
order. A nonpositive integer, boolean, or non-integer raises `ValueError` before
target iteration, even for empty input. No values are coerced.

The worker count bounds active collection calls, not the pending work queue:
concurrent discovery eagerly submits the finite input and returns a complete list.
It waits for workers on exit and provides no timeout or forced cancellation;
future network collectors must enforce their own I/O timeouts.

Facts and outcomes are frozen dataclasses; existing targets remain mutable.
There is no default collector or fallback route. Invalid registry keys, mismatched
collector kinds, and missing callable methods raise `ValueError` before iteration.
Missing routes, invalid target kinds, invalid result types, and ordinary collector
exceptions instead produce failed outcomes and processing continues. Exception
messages and tracebacks are not retained, to avoid exposing sensitive diagnostics.
Process-control exceptions such as `KeyboardInterrupt`, and errors advancing the
input iterable, propagate. Inventory validation remains the loader's responsibility.

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
