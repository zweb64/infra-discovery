"""Offline SSH contract tests: every client is replaced before collection."""

from dataclasses import FrozenInstanceError
import logging
from threading import Barrier, Event, Lock, Thread
from unittest.mock import Mock

import paramiko
from paramiko.client import SSHClient as RealSSHClient
import pytest

from infra_discovery import linux_ssh as ssh
from infra_discovery.collectors import FakeNetworkCollector
from infra_discovery.discovery import discover
from infra_discovery.models import DiscoveryError, LinuxFacts, Target, TargetKind


RESPONSE = b'Linux\n6.1.0-example\nNAME="Example Linux"\nID=example\n'


class Channel:
    def __init__(self, output=RESPONSE, stderr=b"", status=0):
        self.output = output
        self.stderr = stderr
        self.status = status
        self.closed = False
        self.eof_received = True
        self.close_event = Event()
        self.command = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def exec_command(self, command):
        self.command = command

    def shutdown_write(self):
        pass

    def recv_ready(self):
        return bool(self.output)

    def recv_stderr_ready(self):
        return bool(self.stderr)

    def recv(self, size):
        chunk, self.output = self.output[:size], self.output[size:]
        return chunk

    def recv_stderr(self, size):
        chunk, self.stderr = self.stderr[:size], self.stderr[size:]
        return chunk

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return self.status

    def close(self):
        self.closed = True
        self.close_event.set()


@pytest.fixture(autouse=True)
def forbid_real_clients(monkeypatch):
    monkeypatch.setattr(ssh.paramiko, "SSHClient", Mock(
        side_effect=AssertionError("Real SSH is forbidden in tests")))


@pytest.fixture
def setup(monkeypatch):
    channel = Channel()
    client = Mock()
    client.get_transport.return_value.open_session.return_value = channel
    factory = Mock(return_value=client)
    monkeypatch.setattr(ssh.paramiko, "SSHClient", factory)
    collector = ssh.LinuxSSHCollector(
        ssh.SSHCredentials("example-user", password="synthetic-test-value"),
        "example-known-hosts", connection_timeout=2, command_timeout=1,
    )
    return collector, client, channel, factory


def target(identifier="example", kind=TargetKind.LINUX):
    return Target(identifier, "host.example.com", kind)


def test_success_and_explicit_security_options(setup):
    collector, client, channel, factory = setup
    item = target()
    assert collector.collect(item) == LinuxFacts("Example Linux", "6.1.0-example")
    assert item == target()
    factory.assert_called_once_with()
    client.load_host_keys.assert_called_once_with("example-known-hosts")
    assert isinstance(client.set_missing_host_key_policy.call_args.args[0],
                      paramiko.RejectPolicy)
    client.connect.assert_called_once_with(
        hostname=item.host, port=22, username="example-user",
        password="synthetic-test-value", key_filename=None, passphrase=None,
        allow_agent=False, look_for_keys=False, timeout=2, banner_timeout=2,
        auth_timeout=2, channel_timeout=1,
    )
    client.get_transport.return_value.open_session.assert_called_once_with(timeout=1)
    assert channel.command == ssh._COMMAND
    assert item.host not in channel.command
    assert channel.closed
    client.close.assert_called_once()


def test_explicit_key_authentication(setup):
    _, client, _, _ = setup
    collector = ssh.LinuxSSHCollector(
        ssh.SSHCredentials("example", key_filename="example-key",
                           passphrase="synthetic-passphrase"), "example-hosts", port=2222)
    collector.collect(target())
    options = client.connect.call_args.kwargs
    assert options["key_filename"] == "example-key"
    assert options["passphrase"] == "synthetic-passphrase"
    assert options["password"] is None
    assert options["port"] == 2222


@pytest.mark.parametrize("stage", ["load_host_keys", "connect", "open", "exec", "read", "close"])
@pytest.mark.parametrize("error", [
    paramiko.AuthenticationException, paramiko.SSHException, OSError,
    TimeoutError, ValueError,
])
def test_failures_are_sanitized_and_cleaned_up(setup, stage, error, caplog):
    collector, client, channel, _ = setup
    failure = error("synthetic-private-diagnostic")
    if stage == "open":
        client.get_transport.return_value.open_session.side_effect = failure
    elif stage == "exec":
        channel.exec_command = Mock(side_effect=failure)
    elif stage == "read":
        channel.recv = Mock(side_effect=failure)
    else:
        getattr(client, stage).side_effect = failure
    with caplog.at_level(logging.DEBUG), pytest.raises(ssh.LinuxSSHError) as caught:
        collector.collect(target())
    assert str(caught.value) == "Linux SSH collection failed."
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    assert "synthetic-private-diagnostic" not in caplog.text
    client.close.assert_called_once()
    if stage in ("exec", "read", "close"):
        assert channel.closed


@pytest.mark.parametrize("response", [
    b"", b"Linux\n", b"Darwin\n1.0\nNAME=Example\n",
    b"Linux\ninvalid kernel\nNAME=Example\n",
    b"Linux\n1.0\nNAME=\xff\n", b"Linux\n1.0\nNAME=\"unterminated\n",
    b"Linux\n1.0\nnot-an-assignment\n", b"Linux\n1.0\nVERSION=1\n",
    b"Linux\n1.0\nNAME=\n", b"Linux\n1.0\nNAME=one two\n",
    b"Linux\n1.0\nNAME=one\nNAME=two\n",
    b"Linux\n1.0\nNAME=\"bad\x00value\"\n",
    b"Linux\n1.0\nNAME=" + b"x" * 257,
])
def test_malformed_responses_fail_without_partial_facts(setup, response):
    collector, client, channel, _ = setup
    channel.output = response
    outcome = discover([target()], {TargetKind.LINUX: collector})[0]
    assert outcome.error is DiscoveryError.COLLECTION_FAILED
    assert outcome.facts is None
    assert channel.closed
    client.close.assert_called_once()


@pytest.mark.parametrize("release, expected", [
    (b"# comment\nNAME='Example Linux'\nVERSION_ID=1\n", "Example Linux"),
    (b"ID=example\n", "example"),
    (b"NAME=\"\"\nID=example\n", "example"),
    (b'NAME="Example \\"Edition\\""\n', 'Example "Edition"'),
])
def test_release_variants(setup, release, expected):
    collector, _, channel, _ = setup
    channel.output = b"Linux\n1.0\n" + release
    assert collector.collect(target()).distribution == expected


@pytest.mark.parametrize("status", [1, 127, -1])
def test_command_failure_or_missing_status(setup, status):
    collector, _, channel, _ = setup
    channel.status = status
    channel.stderr = b"synthetic-private-stderr"
    with pytest.raises(ssh.LinuxSSHError, match="collection failed"):
        collector.collect(target())
    assert channel.closed


@pytest.mark.parametrize("stream", ["output", "stderr"])
def test_output_is_bounded(setup, stream):
    collector, _, channel, _ = setup
    setattr(channel, stream, b"x" * (ssh._MAX_OUTPUT + 1))
    with pytest.raises(ssh.LinuxSSHError):
        collector.collect(target())
    assert channel.closed


@pytest.mark.parametrize("mode", ["ack", "eof", "status", "trickle"])
def test_deadline_closes_stalled_command(setup, mode):
    original, client, channel, _ = setup
    collector = ssh.LinuxSSHCollector(original.credentials, "example-hosts",
                                      command_timeout=0.05)
    if mode == "ack":
        def wait_for_close(command):
            assert channel.close_event.wait(2), "Command deadline did not close channel"
        channel.exec_command = wait_for_close
    elif mode == "eof":
        channel.eof_received = False
    elif mode == "status":
        channel.exit_status_ready = lambda: False
    else:
        channel.eof_received = False
        channel.recv_ready = lambda: True
        channel.recv = lambda size: b"x"
    with pytest.raises(ssh.LinuxSSHError):
        collector.collect(target())
    assert channel.closed
    client.close.assert_called_once()


def test_stderr_is_drained_and_discarded(setup):
    collector, _, channel, _ = setup
    channel.stderr = b"synthetic-private-stderr" * 300
    assert collector.collect(target()) == LinuxFacts("Example Linux", "6.1.0-example")
    assert not channel.stderr


def test_concurrent_calls_have_distinct_sessions_and_isolated_failures(monkeypatch):
    barrier = Barrier(3)
    lock = Lock()
    clients = []

    def factory():
        client = Mock()
        channel = Channel()
        client.get_transport.return_value.open_session.return_value = channel

        def connect(**options):
            barrier.wait(timeout=3)
            if options["hostname"] == "broken.example.com":
                raise paramiko.AuthenticationException("synthetic-private-diagnostic")
            channel.output = (
                b"Linux\n1.0\nNAME=" + options["hostname"].encode() + b"\n")
        client.connect.side_effect = connect
        with lock:
            clients.append((client, channel))
        return client

    monkeypatch.setattr(ssh.paramiko, "SSHClient", factory)
    collector = ssh.LinuxSSHCollector(
        ssh.SSHCredentials("example", password="synthetic-value"), "example-hosts")
    targets = [Target(host, host, TargetKind.LINUX) for host in
               ("first.example.com", "broken.example.com", "last.example.com")]
    targets.append(target("network", TargetKind.NETWORK))
    outcomes = discover(targets, {TargetKind.LINUX: collector,
                                 TargetKind.NETWORK: FakeNetworkCollector()}, max_workers=3)
    assert [o.succeeded for o in outcomes] == [True, False, True, True]
    assert outcomes[0].facts.distribution == targets[0].host
    assert outcomes[2].facts.distribution == targets[2].host
    assert outcomes[1].error is DiscoveryError.COLLECTION_FAILED
    assert "synthetic" not in repr(outcomes)
    assert len(clients) == 3
    for client, channel in clients:
        client.close.assert_called_once()
        if client.connect.call_args.kwargs["hostname"] != "broken.example.com":
            assert channel.closed


def test_wrong_kind_rejected_before_client_creation(setup):
    collector, _, _, factory = setup
    with pytest.raises(ssh.LinuxSSHError):
        collector.collect(target(kind=TargetKind.NETWORK))
    factory.assert_not_called()


def test_credentials_are_private_in_repr_and_configuration_is_immutable(setup):
    collector, _, _, _ = setup
    for value in (collector, collector.credentials):
        assert "synthetic" not in repr(value)
        assert "example-user" not in repr(value)
        with pytest.raises(FrozenInstanceError):
            value.password = "replacement"


@pytest.mark.parametrize("options", [
    {"username": ""}, {"password": None}, {"password": ""},
    {"key_filename": "example-key"}, {"passphrase": "synthetic-value"},
])
def test_invalid_credentials(options):
    args = {"username": "example", "password": "synthetic-value"}
    args.update(options)
    with pytest.raises(ValueError):
        ssh.SSHCredentials(**args)


@pytest.mark.parametrize("options", [
    {"port": True}, {"port": 0}, {"port": 65536}, {"known_hosts": None},
    {"known_hosts": ""}, {"connection_timeout": 0}, {"command_timeout": -1},
    {"command_timeout": float("nan")}, {"connection_timeout": float("inf")},
    {"connection_timeout": True}, {"command_timeout": "10"},
])
def test_invalid_configuration(options):
    args = dict(credentials=ssh.SSHCredentials("example", password="synthetic-value"),
                known_hosts="example-hosts")
    args.update(options)
    with pytest.raises(ValueError):
        ssh.LinuxSSHCollector(**args)


def test_transport_diagnostics_do_not_reach_application_logs(setup, caplog):
    collector, client, _, _ = setup
    collector.collect(target())
    name = client.set_log_channel.call_args.args[0]
    with caplog.at_level(logging.DEBUG):
        logging.getLogger(name).error("synthetic-private-diagnostic")
        logging.getLogger(name + ".channel").error("synthetic-private-diagnostic")
    assert "synthetic-private-diagnostic" not in caplog.text


def test_process_control_exception_propagates_with_cleanup(setup):
    collector, client, channel, _ = setup
    channel.exec_command = Mock(side_effect=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        collector.collect(target())
    assert channel.closed
    client.close.assert_called_once()


def test_real_paramiko_channel_ack_wait_is_released_offline(setup):
    original, client, _, _ = setup
    # Exercise Paramiko's actual blocking acknowledgement implementation with
    # a fake transport. No socket, server, or real SSHClient is created.
    channel = paramiko.Channel(0)
    channel.active = True
    channel.transport = Mock()
    channel.transport.get_exception.return_value = None
    client.get_transport.return_value.open_session.return_value = channel
    collector = ssh.LinuxSSHCollector(original.credentials, "example-hosts",
                                      command_timeout=0.05)
    with pytest.raises(ssh.LinuxSSHError):
        collector.collect(target())
    assert channel.closed
    assert channel.event.is_set()
    client.close.assert_called_once()


def test_changed_host_key_is_a_sanitized_failure(setup):
    collector, client, _, _ = setup
    client.connect.side_effect = paramiko.BadHostKeyException(
        "private.example.com", Mock(), Mock())
    outcome = discover([target()], {TargetKind.LINUX: collector})[0]
    assert outcome.error is DiscoveryError.COLLECTION_FAILED
    assert "private.example.com" not in repr(outcome)
    client.close.assert_called_once()


def test_channel_cleanup_failure_still_closes_client(setup):
    collector, client, channel, _ = setup
    channel.close = Mock(side_effect=OSError("synthetic-private-diagnostic"))
    with pytest.raises(ssh.LinuxSSHError) as caught:
        collector.collect(target())
    assert caught.value.__context__ is None
    client.close.assert_called_once()


def test_missing_transport_closes_client(setup):
    collector, client, _, _ = setup
    client.get_transport.return_value = None
    with pytest.raises(ssh.LinuxSSHError):
        collector.collect(target())
    client.close.assert_called_once()


@pytest.mark.parametrize("stall", ["rekey", "socket_write"])
def test_deadline_aborts_protocol_stall_offline(setup, stall):
    original, client, _, _ = setup
    interrupted = Event()
    entered = Event()
    finished = Event()
    sock = Mock()
    sock.shutdown.side_effect = lambda how: interrupted.set()
    # Real Transport/Channel protocol paths, but no network socket or SSH peer.
    transport = paramiko.Transport(sock)
    transport.active = True
    transport.clear_to_send.set()
    channel = paramiko.Channel(0)
    channel._set_transport(transport)
    channel.active = True
    transport._channels.put(0, channel)
    client.get_transport.return_value = transport
    transport.open_session = Mock(return_value=channel)

    def send_message(message):
        entered.set()
        if stall == "rekey":
            # The exec packet was sent, but rekeying blocks subsequent CLOSE.
            transport.clear_to_send.clear()
        else:
            # Model a socket write that only shutdown can interrupt.
            assert interrupted.wait(3)
            raise OSError("synthetic stalled write")

    transport._send_message = send_message
    collector = ssh.LinuxSSHCollector(original.credentials, "example-hosts",
                                      command_timeout=0.05)
    failures = []

    def collect():
        try:
            collector.collect(target())
        except BaseException as error:
            failures.append(error)
        finally:
            finished.set()

    worker = Thread(target=collect, daemon=True)
    worker.start()
    try:
        assert entered.wait(1)
        assert finished.wait(1), "Deadline cleanup waited for protocol progress"
        assert len(failures) == 1
        assert isinstance(failures[0], ssh.LinuxSSHError)
        sock.shutdown.assert_called_with(ssh.socket.SHUT_RDWR)
        assert channel.closed
    finally:
        # Also release the old implementation when this regression fails.
        interrupted.set()
        transport.active = False
        transport.clear_to_send.set()
        channel._unlink()
        worker.join(timeout=1)
        transport.close()
    assert not worker.is_alive()


@pytest.mark.parametrize("line", [
    "synthetic-private-host",
    "host.example.com synthetic-private-key-type AAAA",
])
def test_real_known_hosts_parser_logs_are_call_local(setup, tmp_path, caplog, line):
    original, client, _, _ = setup
    path = tmp_path / "known_hosts"
    path.write_text(line + "\n", encoding="utf-8")
    real_client = RealSSHClient()
    parser_logger = logging.getLogger("paramiko.hostkeys")
    original_settings = (parser_logger.level, parser_logger.propagate,
                         parser_logger.disabled, tuple(parser_logger.handlers))

    def load(filename):
        # An unrelated caller logs while the collector's suppression is active.
        other = Thread(target=lambda: parser_logger.warning("unrelated-thread"))
        other.start()
        other.join(timeout=1)
        assert not other.is_alive()
        real_client.load_host_keys(filename)

    client.load_host_keys.side_effect = load
    collector = ssh.LinuxSSHCollector(original.credentials, str(path))
    with caplog.at_level(logging.DEBUG):
        collector.collect(target())
        assert "synthetic-private" not in caplog.text
        assert "unrelated-thread" in caplog.text
        # Prove the same real parser still logs outside the collector context.
        real_client.load_host_keys(str(path))
        assert "synthetic-private" in caplog.text
    assert original_settings == (parser_logger.level, parser_logger.propagate,
                                 parser_logger.disabled, tuple(parser_logger.handlers))
    assert len(real_client.get_host_keys()) == 0
