# infra-discovery

Read-only infrastructure discovery over SSH for Linux hosts and supported network
devices. Supply a validated JSON inventory and separate connection settings to
collect Linux distribution/kernel information or network interface names.

## Capabilities

- Linux discovery and explicit Arista EOS / Juniper Junos network profiles.
- Bounded concurrent collection with independent success or failure per target.
- Strict inventory validation and structured domain models.
- Explicit SSH host-key verification, password or key authentication, phase
  timeouts, bounded command output, and session cleanup.
- Human-readable summaries or deterministic, versioned JSON in inventory order.
- Installable CLI and an offline pytest suite using simulated SSH sessions.

Data flows from **inventory + connection configuration** through validation and
credential prompting, then into the discovery worker pool. Each target is routed
to its Linux or network collector, which uses the shared SSH transport. Results
become structured outcomes and are formatted as text or JSON after all work ends.

## Requirements and installation

Python **3.11 or newer** is required. CI currently runs Python 3.14 on Ubuntu;
this is not a claim that every Python/OS/device combination has been tested.
Paramiko is the runtime dependency and is installed automatically by pip.

From a cloned repository, create and activate a virtual environment:

**Windows PowerShell**

```powershell
cd infra-discovery
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
infra-discovery --help
```

**Linux/macOS**

```sh
cd infra-discovery
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
infra-discovery --help
```

Once installed, the command works outside the checkout while that environment is
active. Installation requires dependencies available from a package index or a
local wheelhouse. Discovery itself does not require Internet access, but does
require SSH access to the configured targets.

## CLI usage

```text
infra-discovery [-h] [--config CONFIG] [--max-workers MAX_WORKERS] [--json] inventory
```

`infra-discovery --help` describes these arguments:

| Argument | Meaning |
| --- | --- |
| `inventory` | Path to a UTF-8 JSON inventory. |
| `--config CONFIG` | Non-secret JSON connection configuration; required for nonempty inventories. |
| `--max-workers MAX_WORKERS` | Positive integer; defaults to `1` (sequential). |
| `--json` | Emit a single versioned JSON document to stdout. |
| `-h`, `--help` | Show help and exit. |

After preparing your local inventory, trusted host keys, and connection settings:

```sh
infra-discovery inventory.json --config connections.local.json
infra-discovery inventory.json --config connections.local.json --max-workers 4 --json
infra-discovery inventory.json --config connections.local.json --json > results.json
```

These commands contact the inventory targets. The examples below are placeholders
and must be adapted before live use. For a safe offline CLI check, create an empty
inventory (no configuration or credentials needed):

```sh
python -c "from pathlib import Path; Path('empty.json').write_text('[]', encoding='utf-8')"
infra-discovery empty.json --json
```

## Inventory

[`examples/inventory.example.json`](examples/inventory.example.json) contains:

```json
[
  {"id": "switch-01", "host": "switch-01.example.com", "kind": "network"},
  {"id": "router-01", "host": "192.0.2.1", "kind": "network"},
  {"id": "linux-01", "host": "linux-01.example.com", "kind": "linux"},
  {"id": "linux-02", "host": "2001:db8::2", "kind": "linux"}
]
```

All names and addresses above are reserved for documentation. Copy the example
to `inventory.json` and replace them with targets you are authorized to access.

Each object must contain **exactly** `id`, `host`, and `kind`, all nonempty strings
without surrounding whitespace. IDs must be unique. Kinds are case-sensitive:
`linux` or `network`. Multiple entries may share a host. Host strings are preserved;
the loader does not validate addresses, resolve names, or perform network access.
Unknown fields, duplicate JSON keys, nonstandard constants, and malformed JSON are
rejected before discovery. An empty array is valid. Do not add credentials, ports,
or platforms to inventory entries; connection settings are separate.

## Connection settings and credentials

Copy [`examples/connections.example.json`](examples/connections.example.json) to
`connections.local.json` alongside your local inventory:

```json
{
  "linux": {
    "username": "discovery",
    "known_hosts": "known_hosts.local"
  },
  "network": {
    "username": "discovery",
    "known_hosts": "known_hosts.local",
    "port": 22,
    "connection_timeout": 10,
    "command_timeout": 10,
    "platforms": {
      "switch-01": "arista_eos",
      "router-01": "juniper_junos"
    }
  }
}
```

Provision `known_hosts.local` separately with trusted OpenSSH host-key entries.
Verify keys through a trusted channel before using them. Unknown or changed keys
fail the target; there is no automatic enrollment or insecure bypass.

Only target kinds present in inventory need a section or credentials. All supplied
sections are validated before prompting; unknown fields and duplicate keys are
rejected. The supported section fields are:

| Field | Requirement/default |
| --- | --- |
| `username` | Required nonblank string. |
| `known_hosts` | Required readable host-key file. |
| `key_filename` | Optional readable private-key file; otherwise prompt for a password. |
| `prompt_passphrase` | Boolean, default `false`; `true` requires `key_filename` and prompts for its passphrase. |
| `port` | Integer from 1 to 65535; default `22`. |
| `connection_timeout` | Finite positive seconds; default `10`. |
| `command_timeout` | Finite positive seconds; default `10`. |
| `platforms` | Network section only: required object mapping every network target ID to `arista_eos` or `juniper_junos`. |

Relative key and known-hosts paths resolve against the configuration file's
directory, and `~` is expanded. For key authentication, add `key_filename` to the
appropriate section; add `"prompt_passphrase": true` if the key is encrypted.

Passwords and passphrases are entered through a non-echoing terminal prompt.
They cannot be supplied through inventory, configuration, or CLI flags. Echoing
fallback is rejected and prompts do not enter JSON stdout. Credentials remain in
memory and are not automatically persisted or serialized; protect private keys
with OS permissions. Unattended use requires an explicitly configured key that
does not need a prompt. The CLI has no environment-secret or stdin-secret protocol.
SSH agents, implicit key searches, and SSH client configuration files are not used.

## Supported targets

**Linux** requires a POSIX-compatible login shell, `uname`, `cat`, and a readable,
valid UTF-8 `/etc/os-release` (or `/usr/lib/os-release` when the former is not
readable). The fixed unprivileged command checks `uname -s`, reads `uname -r`, and
reads the release file as data. Distribution comes from `NAME`, falling back to
`ID`. Unsupported or malformed responses fail without partial facts.

**Network devices** require an explicit platform selection for each target ID,
noninteractive SSH exec support, and an account authorized to run the fixed
read-only command directly:

| Platform | Command | Returned interface names |
| --- | --- | --- |
| `arista_eos` | `show interfaces \| json` | Keys of the JSON `interfaces` object. |
| `juniper_junos` | `show interfaces terse \| display xml \| no-more` | Physical and logical interfaces. |

The returned platform is the configured family, not a detected OS version or
hardware model. Interface names are validated, unique, and sorted. Empty interface
lists, malformed responses, and command errors fail the target. Addresses,
descriptions, and counters are discarded. There is no platform auto-detection,
interactive terminal negotiation, privilege escalation, or other device support.

## Output and exit codes

Illustrative human-readable output (synthetic facts):

```text
SUCCESS "linux-01" (linux, "linux-01.example.com") {"distribution": "Example Linux", "kernel_release": "6.1-example"}
SUCCESS "switch-01" (network, "switch-01.example.com") {"interfaces": ["Ethernet1", "Ethernet2"], "platform": "arista_eos"}
FAILURE "router-01" (network, "192.0.2.1") Collector raised an exception.
3 targets: 2 succeeded, 1 failed.
```

Strings are quoted and control characters escaped. `--json` emits sorted object
keys and retains inventory order for results. A single-target success is:

```json
{
  "results": [
    {
      "error": null,
      "facts": {
        "distribution": "Example Linux",
        "kernel_release": "6.1-example"
      },
      "status": "success",
      "target": {
        "host": "linux-01.example.com",
        "id": "linux-01",
        "kind": "linux"
      }
    }
  ],
  "schema_version": 1,
  "summary": {
    "failed": 0,
    "succeeded": 1,
    "total": 1
  }
}
```

Network `facts` contain `interfaces` (an array of strings) and `platform`. A failed
result has `status: "failure"`, `facts: null`, and an `error` object, for example:
`{"code": "COLLECTION_FAILED", "message": "Collector raised an exception."}`.
Other domain error codes are `INVALID_TARGET_KIND`, `MISSING_COLLECTOR`, and
`INVALID_RESULT`; normal validated CLI routing uses the matching collectors.
No raw SSH exceptions or credentials are included. Every target appears once.
Empty input produces an empty results array and zero totals. Input errors and
interruption diagnostics go to stderr without a JSON result document.

| Exit code | Meaning |
| --- | --- |
| `0` | All targets succeeded, inventory was empty, or help was displayed. |
| `1` | At least one target failed; results still include other targets. |
| `2` | Invocation, input/configuration, or output I/O error. |
| `130` | Keyboard interruption (Ctrl+C). |

## Concurrency, security, and v1 limitations

`--max-workers` bounds active collection calls. Values above one use a thread pool;
returned results remain in inventory order regardless of completion order. Each
call owns its SSH session and resources. Work is submitted eagerly and results are
buffered, so this is not a streaming or memory-bounded inventory processor.

Connection timing covers TCP address attempts and SSH setup/authentication after
DNS resolution. The separate command deadline covers channel opening, exec
acknowledgement, output, EOF, and exit status. Combined stdout/stderr is capped at
64 KiB per target; nonzero or missing exit status fails. These are phase limits,
not a whole-target deadline: OS DNS resolution, local file access, and private-key
processing retain OS/library timing behavior. Ctrl+C may wait for concurrent
workers to finish or time out.

Use accounts with only the permissions needed for the listed commands. Keep real
inventories, connection settings, trusted-host files, private keys, and results
out of version control. Output includes host identifiers and discovered facts and
may itself be sensitive. Raw transport diagnostics are suppressed and errors are
normalized, which intentionally limits troubleshooting detail.

V1 supports one credential set, port, known-hosts file, and timeout configuration
per target kind. It collects only the facts described above. There is no automatic
retry, persistence, scheduling, cloud discovery, GUI, or API service. The offline
suite checks behavior with simulated peers; it does not certify interoperability
with particular Linux distributions or device OS releases. Validate those in your
authorized environment before operational adoption.

## Development and verification

In an activated virtual environment at the repository root:

```sh
python -m pip install -e ".[dev]"
python -m pytest
git diff --check
```

On Windows, if the default pytest temporary directory is inaccessible, use:

```powershell
python -m pytest --basetemp=.pytest-temp
```

The suite uses mocks and fixtures and must not contact real infrastructure.
`dev` installs pytest and the build tools separately from runtime dependencies.
No static-check tooling is configured. GitHub Actions runs the suite on pull
requests targeting `main` and pushes to `main`, using Python 3.14 on Ubuntu.
See [AGENTS.md](AGENTS.md) for contribution and review requirements.

Build both a source distribution and a wheel:

```sh
python -m build
```

Artifacts are written to `dist/`; by default the wheel is built from the source
distribution. For an offline build with build dependencies already installed:

```sh
python -m build --no-isolation
```

To evaluate the packaged application, create a fresh virtual environment, install
`dist/infra_discovery-1.0.0-py3-none-any.whl`, run `python -m pip check`, then change
to a directory outside the repository and run `infra-discovery --help` and the
empty-inventory example. Do not set `PYTHONPATH` to the checkout. Offline wheel
installation requires the runtime dependency wheels in a local wheelhouse; use
pip's `--no-index --find-links` options in that case.

## Project layout

| Path | Responsibility |
| --- | --- |
| `src/infra_discovery/cli.py` | Argument handling, orchestration, exit codes. |
| `inventory.py`, `configuration.py` | Strict input loading, connection settings, secret prompts. |
| `models.py` | Targets, facts, errors, structured outcomes. |
| `discovery.py`, `collectors.py` | Worker orchestration, collector protocol, offline fake collectors. |
| `ssh.py` | Credentials, host verification, bounded SSH execution and cleanup. |
| `linux_ssh.py`, `network_ssh.py` | Fixed commands and response parsing. |
| `output.py` | Human-readable and versioned JSON serialization. |
| `tests/` | Offline validation, CLI, concurrency, and SSH regression coverage. |
| `examples/` | Sanitized inventory and connection templates. |

Module filenames above are relative to `src/infra_discovery/`.
