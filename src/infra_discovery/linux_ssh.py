"""Small Linux collector using the shared bounded SSH transport."""

from dataclasses import dataclass
import re
import shlex
import socket

# Preserve the original credential import and transport test seams.
import paramiko

from infra_discovery.models import LinuxFacts, Target, TargetKind
from infra_discovery.ssh import SSHCommandRunner, SSHCredentials, _MAX_OUTPUT


_COMMAND = (
    "LC_ALL=C; export LC_ALL; uname -s && uname -r && "
    "if [ -r /etc/os-release ]; then cat /etc/os-release; "
    "else cat /usr/lib/os-release; fi"
)


class LinuxSSHError(Exception):
    """Sanitized collection failure, safe to expose without library details."""


@dataclass(frozen=True)
class LinuxSSHCollector(SSHCommandRunner):
    kind = TargetKind.LINUX

    def collect(self, target: Target) -> LinuxFacts:
        if target.kind is not self.kind:
            raise LinuxSSHError("Linux SSH collection requires a Linux target.")
        try:
            return _parse_response(self._run_command(target, _COMMAND))
        except Exception:
            pass
        raise LinuxSSHError("Linux SSH collection failed.")


def _parse_response(data: bytes) -> LinuxFacts:
    lines = data.decode("utf-8", errors="strict").splitlines()
    if (
        len(lines) < 3
        or lines[0] != "Linux"
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,255}", lines[1])
    ):
        raise ValueError("Invalid Linux response.")
    fields = {}
    for line in lines[2:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError("Invalid OS release data.")
        # Parse as data only. Never source os-release in a shell.
        values = shlex.split(value, comments=False, posix=True)
        if len(values) > 1 or key in fields:
            raise ValueError("Invalid OS release data.")
        fields[key] = values[0] if values else ""
    distribution = fields.get("NAME") or fields.get("ID")
    if (
        not distribution
        or len(distribution) > 256
        or not distribution.isprintable()
        or distribution != distribution.strip()
    ):
        raise ValueError("Invalid distribution name.")
    return LinuxFacts(distribution=distribution, kernel_release=lines[1])
