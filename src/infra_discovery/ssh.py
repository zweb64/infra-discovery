"""Shared SSH credentials and bounded, call-local command transport."""

from contextvars import ContextVar
from dataclasses import dataclass, field
import logging
import math
import socket
import sys
from threading import Event, Timer
from time import monotonic

import paramiko

from infra_discovery.models import Target


# Paramiko diagnostics can include usernames, addresses, and key paths. Route
# only this collector's transports to a sink, including their child loggers.
_LOG_NAME = __name__ + ".transport"
_logger = logging.getLogger(_LOG_NAME)
# Suppress diagnostics even when application tooling attaches handlers here.
# Descendant transport loggers inherit this level.
_logger.setLevel(logging.CRITICAL + 1)
_logger.addHandler(logging.NullHandler())
_logger.propagate = False

_loading_host_keys = ContextVar("ssh_loading_host_keys", default=False)


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


_MAX_OUTPUT = 65536


def _close_socket(sock: socket.socket) -> None:
    """Interrupt I/O even before Paramiko has constructed a Transport."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass  # Includes sockets whose TCP connect has not completed.
    finally:
        sock.close()


class SSHError(Exception):
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
class SSHCommandRunner:
    """One credential set per collector; concurrent calls share no sessions."""

    credentials: SSHCredentials = field(repr=False)
    known_hosts: str = field(repr=False)
    port: int = 22
    connection_timeout: float = 10.0
    command_timeout: float = 10.0

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

    def _run_command(self, target: Target, command: str) -> bytes:
        """Execute a trusted command; callers must sanitize transport errors."""
        client = paramiko.SSHClient()
        sockets = []
        try:
            client.set_log_channel(_LOG_NAME)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            token = _loading_host_keys.set(True)
            try:
                client.load_host_keys(self.known_hosts)
            finally:
                _loading_host_keys.reset(token)
            self._connect(client, target, sockets)
            transport = client.get_transport()
            if transport is None:
                raise SSHError("SSH transport unavailable.")
            return self._read_command(transport, command)
        finally:
            # Keep cancellation (and the original failure) even if secondary
            # cleanup fails. Always close sockets before Paramiko cleanup.
            unwinding = sys.exc_info()[0] is not None
            cleanup_error = None
            for sock in sockets:
                try:
                    _close_socket(sock)
                except Exception as error:
                    cleanup_error = error
            try:
                client.close()
            except Exception as error:
                cleanup_error = error
            if cleanup_error is not None and not unwinding:
                raise cleanup_error

    def _connect(
        self, client: paramiko.SSHClient, target: Target,
        sockets: list[socket.socket],
    ) -> None:
        # Resolution is OS-controlled. All address attempts and SSH setup share
        # one budget after resolution; a failed address does not reset it.
        addresses = socket.getaddrinfo(
            target.host, self.port, type=socket.SOCK_STREAM
        )
        deadline = monotonic() + self.connection_timeout
        for family, socktype, proto, _, address in addresses:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError()
            sock = socket.socket(family, socktype, proto)
            sockets.append(sock)  # Own it before settimeout/connect can raise.
            expired = Event()

            def expire(sock: socket.socket = sock, expired: Event = expired) -> None:
                expired.set()
                try:
                    # No Paramiko calls/locks here: auth may hold those locks
                    # while Packetizer.write_all retries socket timeouts.
                    _close_socket(sock)
                except Exception:
                    pass  # Never emit connection diagnostics from the timer.

            timer = Timer(remaining, expire)
            timer.daemon = True
            try:
                timer.start()
                sock.settimeout(remaining)
                try:
                    sock.connect(address)
                except OSError:
                    _close_socket(sock)
                    if expired.is_set() or monotonic() >= deadline:
                        raise TimeoutError() from None
                    continue
                self._authenticate(client, target, sock)
                if expired.is_set() or monotonic() >= deadline:
                    raise TimeoutError()
                return
            finally:
                timer.cancel()
                timer.join(timeout=0.1)
        raise SSHError("SSH connection failed.")

    def _authenticate(
        self, client: paramiko.SSHClient, target: Target, sock: socket.socket,
    ) -> None:
        client.connect(
            sock=sock,
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

    def _read_command(
        self, transport: paramiko.Transport, command: str
    ) -> bytes:
        expired = Event()
        channel = None

        def expire() -> None:
            expired.set()
            try:
                _abort_transport(transport)
                if channel is not None:
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
            channel = transport.open_session(timeout=self.command_timeout)
            channel.settimeout(self.command_timeout)
            channel.exec_command(command)
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
                            raise SSHError("SSH response exceeds limit.")
                        if retain:
                            output.extend(data)
                # Drain both streams before checking status to avoid SSH window
                # deadlocks. EOF is needed even if exit status arrives first.
                if channel.closed or channel.eof_received:
                    if channel.recv_ready() or channel.recv_stderr_ready():
                        continue
                    if channel.exit_status_ready():
                        if channel.recv_exit_status() != 0:
                            raise SSHError("SSH command failed.")
                        return bytes(output)
                expired.wait(0.01)
        finally:
            unwinding = sys.exc_info()[0] is not None
            timer.cancel()
            timer.join(timeout=0.1)
            # Break protocol I/O before sending any channel cleanup packets,
            # including when opening the channel itself failed or stalled.
            try:
                try:
                    _abort_transport(transport)
                finally:
                    if channel is not None:
                        channel.close()
            except Exception:
                if not unwinding:
                    raise

