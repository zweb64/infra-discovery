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
partial facts. No additional Linux facts are collected.

TCP connection, banner, and authentication each have an explicit timeout;
an independent `connection_timeout` deadline also spans all TCP address attempts
and SSH setup/authentication after DNS resolution. It closes the owned socket
directly, including packet-writing retries before Paramiko's auth timer begins.
Channel opening has its own timeout. A command deadline also covers channel
opening, exec acknowledgement, both output streams, EOF, and exit status, including
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

## Network discovery over SSH

`NetworkSSHCollector` uses the existing Paramiko dependency and collector route.
It supports two explicit platform profiles, selected by target ID in runtime
configuration. Inventory still contains exactly `id`, `host`, and `kind`; neither
`Target` nor `NetworkFacts` has changed.

```python
from infra_discovery.network_ssh import NetworkSSHCollector
from infra_discovery.ssh import SSHCredentials

# Reuse runtime credentials and the trusted known-hosts path from the example above.
network = NetworkSSHCollector(
    credentials=credentials,
    known_hosts=os.environ["DISCOVERY_SSH_KNOWN_HOSTS"],
    platforms={"switch-1": "arista_eos", "router-1": "juniper_junos"},
    connection_timeout=10,
    command_timeout=10,
)
outcomes = discover(targets, {
    TargetKind.NETWORK: network,
    TargetKind.LINUX: linux,
}, max_workers=4)
```

| Platform | Fixed read-only command | Interface names |
| --- | --- | --- |
| `arista_eos` | `show interfaces \| json` | Keys of the `interfaces` object |
| `juniper_junos` | `show interfaces terse \| display xml \| no-more` | Physical and logical interface names |

The returned `NetworkFacts.platform` is the configured OS family identifier,
not a detected OS version or hardware model. Interface names are validated,
unique, and sorted. Other response fields (addresses, descriptions, counters,
banners) are discarded. Empty interface lists, malformed or ambiguous data,
command errors, and missing/unsupported platform selections fail the target;
there is no automatic platform detection or fallback. Junos XML namespaces are
handled without depending on a particular release; DTDs/entities are rejected.
These profiles require noninteractive SSH exec support, UTF-8 structured output,
and an account authorized to run the command directly. Interactive-only devices,
other vendors, privilege escalation, and large responses above 64 KiB are outside
v1. Device interoperability still needs validation against your OS releases;
the suite uses sanitized examples, not hardware certification.

Paramiko is appropriate here because both profiles use SSH exec with structured
output; interactive terminal negotiation and another automation dependency are
unnecessary. Credentials and bounded SSH execution live in `infra_discovery.ssh`
and are shared with Linux. The original `linux_ssh.SSHCredentials` import remains
supported. There are no new dependencies.

Each call owns its SSH client, transport, channel, buffer, and deadline timer.
The collector is frozen and copies the platform mapping into a read-only snapshot.
One collector uses one runtime credential set, known-hosts file, and port; no
credentials or connection configuration are attached to inventory or facts.
No agent, implicit key lookup, enable secrets, or credential persistence is used.

Unknown and changed SSH host keys are rejected against the explicit provisioned
known-hosts file; there is no trust-on-first-use or insecure opt-out. TCP connect,
banner, and authentication retain explicit Paramiko timeouts. Independently,
`connection_timeout` bounds all TCP address attempts and SSH setup/authentication
after DNS resolution. Each call creates and owns its TCP sockets before calling
`socket.connect`, and supplies the connected socket to `SSHClient.connect`.
Paramiko uses that socket but the runner retains cleanup responsibility, including
on `KeyboardInterrupt` before a Transport exists. Failed attempts are closed
immediately; final cleanup closes all owned sockets before closing the client.
Cancellation propagates even if secondary cleanup raises an ordinary exception.

The connection deadline callback only shuts down and closes the socket: it never
takes Paramiko locks, which authentication may hold while retrying packet writes.
Collection stays on its calling thread until the interrupted SSH operation exits;
no blocked connection task is abandoned. Timers are cancelled and their joins
are bounded to 0.1 seconds. A separate
`command_timeout` deadline covers channel opening, exec acknowledgement, output,
EOF, and exit status. It shuts down the call's socket and transport to interrupt
protocol/rekey stalls. Combined stdout/stderr is capped at 64 KiB. Cleanup runs
on success, errors, and cancellation. DNS resolution and local file access remain
subject to OS behavior; these phase bounds are not a whole-target deadline.
Closing a socket cannot interrupt local private-key file reads or CPU-bound key
processing inside Paramiko; an expired deadline is checked again when connect
returns. Normal OS socket shutdown/close semantics are required.

Ordinary failures raise generic `NetworkSSHError` with no original exception
chain; discovery maps them to `COLLECTION_FAILED` while other targets continue.
The shared transport uses a private diagnostic sink and context-local suppression
of host-key parser messages; unrelated Paramiko/application logging is preserved.
No root logger configuration or process-wide logging disable is introduced.

Offline tests replace SSH clients and sockets, and exercise real Paramiko channel
and transport methods against simulated stalled peers. They cover both profiles,
authentication/connection/command failures, output validation, cleanup, concurrent
use of one collector, credential boundaries, and diagnostic isolation.

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
