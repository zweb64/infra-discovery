"""Small, synchronous Linux collector with call-local SSH resources."""

from contextvars import ContextVar
from dataclasses import dataclass, field
import logging
import math
import re
import shlex
import socket
from threading import Event, Timer
from time import monotonic

import paramiko

from infra_discovery.models import LinuxFacts, Target, TargetKind


# Paramiko diagnostics can include usernames, addresses, and key paths. Route
# only this collector's transports to a sink, including their child loggers.
_LOG_NAME = __name__ + ".transport"
_logger = logging.getLogger(_LOG_NAME)
# Suppress diagnostics even when application tooling attaches handlers here.
# Descendant transport loggers inherit this level.
_logger.setLevel(logging.CRITICAL + 1)
_logger.addHandler(logging.NullHandler())
_logger.propagate = False

_loading_host_keys = ContextVar("linux_ssh_loading_host_keys", default=False)


class _HostKeyLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not _loading_host_keys.get()


# Paramiko's parser uses a fixed logger. Suppress only this call's records;
# other threads and other users of Paramiko retain their logging configuration.
logging.getLogger("paramiko.hostkeys").addFilter(_HostKeyLogFilter())


def _abort_transport(transport: paramiko.Transport) -> None:
    """Break socket I/O before asking Paramiko to stop; send no SSH packets."""
    try:
        transport.sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass  # Already disconnected.
    finally:
        transport.sock.close()
    transport.close()


_COMMAND = (
    "LC_ALL=C; export LC_ALL; uname -s && uname -r && "
    "if [ -r /etc/os-release ]; then cat /etc/os-release; "
    "else cat /usr/lib/os-release; fi"
)
_MAX_OUTPUT = 65536


class LinuxSSHError(Exception):
    """Sanitized collection failure, safe to expose without library details."""


@dataclass(frozen=True, repr=False)
class SSHCredentials:
    """Runtime-only credentials; never attach these to targets or outcomes."""

    username: str
    password: str | None = None
    key_filename: str | None = None
    passphrase: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.username, str) or not self.username.strip():
            raise ValueError("SSH username is required.")
        for value in (self.password, self.key_filename, self.passphrase):
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError("Invalid SSH credential configuration.")
        if (self.password is None) == (self.key_filename is None):
            raise ValueError("Supply exactly one SSH authentication method.")
        if self.passphrase is not None and self.key_filename is None:
            raise ValueError("A passphrase requires a key file.")


@dataclass(frozen=True)
class LinuxSSHCollector:
    """One credential set per collector; concurrent calls share no sessions."""

    credentials: SSHCredentials = field(repr=False)
    known_hosts: str = field(repr=False)
    port: int = 22
    connection_timeout: float = 10.0
    command_timeout: float = 10.0

    kind = TargetKind.LINUX

    def __post_init__(self) -> None:
        if not isinstance(self.credentials, SSHCredentials):
            raise ValueError("SSH credentials are required.")
        if not isinstance(self.known_hosts, str) or not self.known_hosts.strip():
            raise ValueError("An explicit known-hosts file is required.")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("Invalid SSH port.")
        for value in (self.connection_timeout, self.command_timeout):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError("SSH timeouts must be finite positive numbers.")

    def collect(self, target: Target) -> LinuxFacts:
        """Collect facts or raise a generic error without retaining diagnostics."""
        if target.kind is not self.kind:
            raise LinuxSSHError("Linux SSH collection requires a Linux target.")
        # Raise outside the handler so even __context__ does not retain the
        # original exception (which may contain credentials or remote output).
        try:
            return self._collect(target)
        except Exception:
            pass
        raise LinuxSSHError("Linux SSH collection failed.")

    def _collect(self, target: Target) -> LinuxFacts:
        client = paramiko.SSHClient()
        try:
            client.set_log_channel(_LOG_NAME)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            token = _loading_host_keys.set(True)
            try:
                client.load_host_keys(self.known_hosts)
            finally:
                _loading_host_keys.reset(token)
            client.connect(
                hostname=target.host,
                port=self.port,
                username=self.credentials.username,
                password=self.credentials.password,
                key_filename=self.credentials.key_filename,
                passphrase=self.credentials.passphrase,
                allow_agent=False,
                look_for_keys=False,
                timeout=self.connection_timeout,
                banner_timeout=self.connection_timeout,
                auth_timeout=self.connection_timeout,
                channel_timeout=self.command_timeout,
            )
            transport = client.get_transport()
            if transport is None:
                raise LinuxSSHError("SSH transport unavailable.")
            channel = transport.open_session(timeout=self.command_timeout)
            try:
                return _parse_response(self._read_command(channel, transport))
            finally:
                # This connection is call-local and will never be reused.
                # Terminate it before channel.close can send EOF/CLOSE packets.
                _abort_transport(transport)
                channel.close()
        finally:
            client.close()

    def _read_command(
        self, channel: paramiko.Channel, transport: paramiko.Transport
    ) -> bytes:
        expired = Event()

        def expire() -> None:
            expired.set()
            try:
                _abort_transport(transport)
                channel.close()
            except Exception:
                # Never send library diagnostics to threading.excepthook.
                # The owning call still closes the client in its finally block.
                pass

        # Channel timeouts do not bound exec-request acknowledgement waits.
        # Socket shutdown interrupts writes/reads without waiting for rekeying;
        # transport closure releases channel acknowledgement waits.
        timer = Timer(self.command_timeout, expire)
        timer.daemon = True
        deadline = monotonic() + self.command_timeout
        output = bytearray()
        total = 0
        try:
            timer.start()
            channel.settimeout(self.command_timeout)
            channel.exec_command(_COMMAND)
            channel.shutdown_write()
            while True:
                if expired.is_set() or monotonic() >= deadline:
                    raise TimeoutError()
                for ready, receive, retain in (
                    (channel.recv_ready, channel.recv, True),
                    (channel.recv_stderr_ready, channel.recv_stderr, False),
                ):
                    if ready():
                        data = receive(4096)
                        total += len(data)
                        if total > _MAX_OUTPUT:
                            raise LinuxSSHError("SSH response exceeds limit.")
                        if retain:
                            output.extend(data)
                # Drain both streams before checking status to avoid SSH window
                # deadlocks. EOF is needed even if exit status arrives first.
                if channel.closed or channel.eof_received:
                    if channel.recv_ready() or channel.recv_stderr_ready():
                        continue
                    if channel.exit_status_ready():
                        if channel.recv_exit_status() != 0:
                            raise LinuxSSHError("SSH command failed.")
                        return bytes(output)
                expired.wait(0.01)
        finally:
            timer.cancel()
            timer.join(timeout=0.1)


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
