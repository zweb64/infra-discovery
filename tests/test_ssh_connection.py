"""Connection ownership and deadlines through real Paramiko auth/packet code."""

from dataclasses import replace
import errno
from threading import Barrier, Event, Thread
from time import monotonic
from unittest.mock import Mock

import paramiko
from paramiko.client import SSHClient as RealSSHClient
from paramiko.transport import Transport as RealTransport
import pytest

from infra_discovery import ssh
from infra_discovery.discovery import discover
from infra_discovery.linux_ssh import LinuxSSHCollector, LinuxSSHError
from infra_discovery.models import DiscoveryError, Target, TargetKind
from infra_discovery.network_ssh import NetworkSSHCollector, NetworkSSHError
from tests.ssh_fakes import install_tcp_fakes
from tests.test_linux_ssh import Channel, RESPONSE
from tests.test_network_ssh import EOS


class Socket:
    """A socket peer that times out writes until actual shutdown/close."""

    def __init__(self):
        self.closed = Event()
        self.writing = Event()
        self.sends = 0
        self.connected = False
        self._closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.address = address
        self.connected = True

    def send(self, data):
        self.writing.set()
        self.sends += 1
        if self.closed.wait(0.005):
            raise OSError(errno.EBADF, "synthetic-private-diagnostic")
        # Real Packetizer.write_all retries these indefinitely, before the
        # authentication wait loop (and auth_timeout) is ever entered.
        raise ssh.socket.timeout("synthetic-private-diagnostic")

    def shutdown(self, how):
        self.closed.set()

    def close(self):
        self._closed = True
        self.closed.set()


@pytest.fixture(params=["linux", "network"])
def setup(request, monkeypatch):
    install_tcp_fakes(monkeypatch)
    credentials = ssh.SSHCredentials("example-user", password="synthetic-secret")
    if request.param == "linux":
        collector = LinuxSSHCollector(credentials, "example-known-hosts",
                                      connection_timeout=0.08)
        error_type, response = LinuxSSHError, RESPONSE
    else:
        collector = NetworkSSHCollector(
            credentials, "example-known-hosts", connection_timeout=0.08,
            platforms={"first": "arista_eos", "second": "arista_eos"},
        )
        error_type, response = NetworkSSHError, EOS
    item = Target("first", "device.example.com", collector.kind)
    monkeypatch.setattr(ssh.socket, "getaddrinfo", lambda host, port, *args, **kwargs: [
        (ssh.socket.AF_INET, ssh.socket.SOCK_STREAM, 6, "", (host, port)),
    ])
    sockets, clients, transports = [], [], []
    key = Mock()
    key.get_name.return_value = "ssh-rsa"

    def socket_factory(*args):
        sock = Socket()
        sockets.append(sock)
        return sock

    def client_factory():
        client = RealSSHClient()
        # Provision a synthetic trusted key while retaining real host-key
        # selection, RejectPolicy, comparison, and authentication dispatch.
        def load(path):
            for host in [item.host, "healthy.example.com"]:
                client.get_host_keys().add(host, "ssh-rsa", key)
        client.load_host_keys = Mock(side_effect=load)
        clients.append(client)
        return client

    def transport_factory(sock, **kwargs):
        transport = RealTransport(sock, **kwargs)

        def handshake(timeout=None):
            # No network reader thread or cryptographic handshake is needed
            # to reproduce the authentication service-request write path.
            transport.active = True
            transport.initial_kex_done = True

        transport.start_client = handshake
        transport.get_remote_server_key = lambda: key
        transport.open_session = Mock(return_value=Channel(response))
        transports.append(transport)
        return transport

    monkeypatch.setattr(ssh.socket, "socket", socket_factory)
    monkeypatch.setattr(ssh.paramiko, "SSHClient", client_factory)
    monkeypatch.setattr(paramiko.client, "Transport", transport_factory)
    return collector, item, error_type, sockets, clients, transports


@pytest.mark.parametrize("max_workers", [1, 2])
def test_auth_service_request_retry_is_interrupted_and_isolated(
    setup, monkeypatch, caplog, max_workers,
):
    collector, item, _, sockets, clients, transports = setup
    original_auth = RealTransport.auth_password
    barrier = Barrier(2)

    def authenticate(self, *args, **kwargs):
        if max_workers == 2:
            barrier.wait(timeout=1)
        if self.sock.address[0] == item.host:
            return original_auth(self, *args, **kwargs)
        return []  # The second target reaches command collection successfully.

    monkeypatch.setattr(RealTransport, "auth_password", authenticate)
    results, failures = [], []
    finished = Event()

    def run():
        try:
            results.extend(discover(
                [item, replace(item, id="second", host="healthy.example.com")],
                {collector.kind: collector}, max_workers=max_workers,
            ))
        except BaseException as error:
            failures.append(error)
        finally:
            finished.set()

    worker = Thread(target=run, daemon=True)
    worker.start()
    try:
        assert finished.wait(1.5), "Authentication packet writer outlived deadline"
        assert not failures
        assert sum(sock.sends for sock in sockets) > 1
        assert results[0].error is DiscoveryError.COLLECTION_FAILED
        assert results[1].succeeded
        assert "synthetic-secret" not in repr(results)
        assert "synthetic-private" not in caplog.text
        assert all(sock._closed for sock in sockets)
        assert all(client.get_transport() is None for client in clients)
        assert all(not transport.is_active() for transport in transports)
    finally:
        # Make the pre-fix regression fail promptly without stranding its
        # packet writer in the test process.
        for sock in sockets:
            sock.close()
        worker.join(timeout=1)
    assert not worker.is_alive()


@pytest.mark.parametrize("cancellation", [KeyboardInterrupt, SystemExit])
def test_cancellation_during_tcp_connect_closes_unattached_socket(
    setup, monkeypatch, cancellation,
):
    collector, item, _, sockets, clients, transports = setup
    original = cancellation("synthetic-cancellation")

    def connect(self, address):
        assert clients[0].get_transport() is None
        raise original

    monkeypatch.setattr(Socket, "connect", connect)
    with pytest.raises(cancellation) as caught:
        collector.collect(item)
    assert caught.value is original
    assert len(sockets) == 1
    assert sockets[0]._closed
    assert not transports


def test_cancellation_survives_secondary_client_cleanup_failure(setup, monkeypatch):
    collector, item, _, sockets, _, _ = setup

    def connect(self, address):
        raise KeyboardInterrupt()

    monkeypatch.setattr(Socket, "connect", connect)
    monkeypatch.setattr(RealSSHClient, "close", Mock(side_effect=OSError("private")))
    with pytest.raises(KeyboardInterrupt):
        collector.collect(item)
    assert sockets[0]._closed


def test_connect_stall_is_interrupted_before_transport_exists(setup, monkeypatch):
    collector, item, error_type, sockets, _, transports = setup

    def connect(self, address):
        assert self.closed.wait(1), "Connecting socket was not interrupted"
        raise OSError(errno.EBADF, "closed socket")

    monkeypatch.setattr(Socket, "connect", connect)
    start = monotonic()
    with pytest.raises(error_type):
        collector.collect(item)
    assert monotonic() - start < 0.8
    assert sockets[0]._closed
    assert not transports


@pytest.mark.parametrize("trust", ["unknown", "changed"])
def test_real_host_key_verification_is_preserved(setup, monkeypatch, trust):
    collector, item, error_type, sockets, clients, _ = setup
    factory = ssh.paramiko.SSHClient

    def client_factory():
        client = factory()
        def load(path):
            if trust == "changed":
                different_key = Mock()
                different_key.get_name.return_value = "ssh-rsa"
                client.get_host_keys().add(item.host, "ssh-rsa", different_key)
        client.load_host_keys = load
        return client

    monkeypatch.setattr(ssh.paramiko, "SSHClient", client_factory)
    with pytest.raises(error_type) as caught:
        collector.collect(item)
    assert caught.value.__context__ is None
    assert not sockets[0].writing.is_set()
    assert sockets[0]._closed
    assert clients[0].get_transport() is None


def test_success_cancels_timers_and_closes_explicit_socket(setup, monkeypatch):
    collector, item, _, sockets, clients, _ = setup
    timers = []
    real_timer = ssh.Timer

    def timer_factory(*args):
        timer = real_timer(*args)
        timers.append(timer)
        return timer

    monkeypatch.setattr(ssh, "Timer", timer_factory)
    monkeypatch.setattr(RealTransport, "auth_password", lambda *args, **kwargs: [])
    assert discover([item], {collector.kind: collector})[0].succeeded
    assert len(timers) == 2
    assert all(not timer.is_alive() for timer in timers)
    assert sockets[0]._closed
    assert clients[0].get_transport() is None


def test_command_cancellation_survives_channel_cleanup_error(setup, monkeypatch):
    collector, item, _, sockets, clients, _ = setup
    monkeypatch.setattr(RealTransport, "auth_password", lambda *args, **kwargs: [])
    monkeypatch.setattr(Channel, "exec_command", Mock(side_effect=KeyboardInterrupt()))
    monkeypatch.setattr(Channel, "close", Mock(side_effect=OSError("private")))
    with pytest.raises(KeyboardInterrupt):
        collector.collect(item)
    assert sockets[0]._closed
    assert clients[0].get_transport() is None


def test_address_fallback_closes_failed_socket_and_shares_budget(setup, monkeypatch):
    collector, item, _, sockets, _, _ = setup
    intervals = []
    real_timer = ssh.Timer

    def timer_factory(interval, callback):
        intervals.append(interval)
        return real_timer(interval, callback)

    def connect(self, address):
        if len(sockets) == 1:
            raise ConnectionRefusedError()
        assert sockets[0]._closed
        self.connected = True

    addresses = ssh.socket.getaddrinfo(item.host, 22)
    monkeypatch.setattr(ssh.socket, "getaddrinfo", lambda *a, **kw: addresses * 2)
    monkeypatch.setattr(ssh, "Timer", timer_factory)
    monkeypatch.setattr(Socket, "connect", connect)
    monkeypatch.setattr(RealTransport, "auth_password", lambda *args, **kwargs: [])
    assert collector.collect(item) is not None
    assert len(sockets) == 2
    assert all(sock._closed for sock in sockets)
    assert 0 < intervals[1] < intervals[0] <= collector.connection_timeout
