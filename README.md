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

## Linux discovery over SSH

`LinuxSSHCollector` implements the same collector protocol and returns the
existing `LinuxFacts(distribution, kernel_release)`. Register it explicitly:

```python
import os

from infra_discovery.linux_ssh import LinuxSSHCollector, SSHCredentials

# Supply these values at runtime, separately from inventory.
credentials = SSHCredentials(
    username=os.environ["DISCOVERY_SSH_USERNAME"],
    key_filename=os.environ["DISCOVERY_SSH_KEY_FILE"],
    passphrase=os.environ.get("DISCOVERY_SSH_KEY_PASSPHRASE"),
)
linux = LinuxSSHCollector(
    credentials=credentials,
    known_hosts=os.environ["DISCOVERY_SSH_KNOWN_HOSTS"],
    connection_timeout=10,
    command_timeout=10,
)
outcomes = discover(targets, {TargetKind.LINUX: linux}, max_workers=4)
```

Alternatively supply `password=` instead of `key_filename=`/`passphrase=`.
Exactly one authentication method is required. Credentials and the known-hosts
path are excluded from object representations; they are never added to targets,
facts, or outcomes. Do not serialize the runtime credential object. This module
does not load environment variables itself, prompt, or store credentials.

Paramiko is the sole added direct dependency. Each call creates and closes its
own client and channel. The collector's configuration is immutable, so it can be
shared across discovery workers. One collector uses one credential set and SSH
port (default 22); per-target credential lookup is outside v1. SSH agents, implicit
key searches, and SSH client configuration files are not used. An explicit
OpenSSH known-hosts file is required; provision trusted host keys beforehand.
Unknown and changed keys fail without automatic enrollment.

The fixed, unprivileged command checks `uname -s`, reads `uname -r`, and reads
`/etc/os-release`, falling back to `/usr/lib/os-release` when the former is not
readable. Distribution is `NAME`, with `ID` as fallback. Parsing never executes
the release file. A POSIX-compatible login shell, `uname`, `cat`, and a valid
UTF-8 os-release file are required; unsupported or malformed hosts fail without
partial facts. No additional facts or real network-device collector are included.

TCP connection, banner, and authentication each have an explicit timeout;
channel opening has its own timeout. A separate command deadline covers the
exec acknowledgement, both output streams, EOF, and exit status, including
trickling output. Combined stdout/stderr is limited to 64 KiB. Nonzero or missing
exit status fails. These are phase limits, not a single whole-target deadline:
OS hostname resolution and local key/known-hosts file access remain subject to
OS behavior. Use IP targets when predictable DNS-independent timing is needed.

All ordinary collection failures, including authentication, host-key checks,
connection errors, command failures, malformed data, and cleanup errors, raise
a generic `LinuxSSHError`. Existing discovery maps it to `COLLECTION_FAILED`
and continues other targets. Raw exception chains, stderr, and this collector's
Paramiko transport logs are suppressed to keep connection diagnostics private.
Process-control exceptions still propagate after cleanup.

SSH tests replace every client with fakes, exercise real deadline timers, and
check concurrent session isolation. They require no SSH server, keys, credentials,
or infrastructure access. Actual SSH interoperability is not tested by this suite.

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
