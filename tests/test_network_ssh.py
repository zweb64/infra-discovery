"""Network collection contracts, with no real sockets or external devices."""

from dataclasses import asdict, FrozenInstanceError, replace
import logging
from threading import Barrier, Event, Lock, Thread
from unittest.mock import ANY, Mock

import paramiko
import pytest

from infra_discovery import network_ssh as network
from infra_discovery import ssh
from infra_discovery.collectors import FakeLinuxCollector
from infra_discovery.discovery import discover
from infra_discovery.models import DiscoveryError, NetworkFacts, Target, TargetKind
from tests.test_linux_ssh import Channel
from tests.ssh_fakes import install_tcp_fakes


EOS = b'{"interfaces":{"Ethernet1":{},"Management1":{}},"ignored":"private-marker"}'
JUNOS = b'''<rpc-reply xmlns:junos="http://xml.juniper.net/junos/example">
<interface-information xmlns="http://xml.juniper.net/junos/example-interface">
<physical-interface><name>ge-0/0/0</name><admin-status>up</admin-status>
<logical-interface><name>ge-0/0/0.0</name></logical-interface>
</physical-interface></interface-information><cli><banner>private-marker</banner>
</cli></rpc-reply>'''


def target(identifier="switch", kind=TargetKind.NETWORK):
    return Target(identifier, "device.example.com", kind)


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    install_tcp_fakes(monkeypatch)
    monkeypatch.setattr(ssh.paramiko, "SSHClient", Mock(
        side_effect=AssertionError("Real SSH is forbidden")))
    monkeypatch.setattr(ssh.socket, "create_connection", Mock(
        side_effect=AssertionError("Real sockets are forbidden")))


@pytest.fixture
def setup(monkeypatch):
    channel = Channel(EOS)
    client = Mock()
    client.get_transport.return_value.open_session.return_value = channel
    factory = Mock(return_value=client)
    monkeypatch.setattr(ssh.paramiko, "SSHClient", factory)
    collector = network.NetworkSSHCollector(
        ssh.SSHCredentials("example-user", password="synthetic-private-marker"),
        "example-known-hosts", platforms={"switch": "arista_eos"},
        connection_timeout=2, command_timeout=0.1,
    )
    return collector, client, channel, factory


@pytest.mark.parametrize("platform,response,names,command", [
    ("arista_eos", EOS, ("Ethernet1", "Management1"), "show interfaces | json"),
    ("juniper_junos", JUNOS, ("ge-0/0/0", "ge-0/0/0.0"),
     "show interfaces terse | display xml | no-more"),
])
def test_success_and_security_contract(setup, platform, response, names, command):
    original, client, channel, factory = setup
    collector = replace(original, platforms={"switch": platform})
    channel.output = response
    item = target()
    assert collector.collect(item) == NetworkFacts(platform, names)
    assert item == target()
    assert channel.command == command
    factory.assert_called_once_with()
    client.load_host_keys.assert_called_once_with("example-known-hosts")
    assert isinstance(client.set_missing_host_key_policy.call_args.args[0],
                      paramiko.RejectPolicy)
    client.connect.assert_called_once_with(
        sock=ANY,
        hostname=item.host, port=22, username=collector.credentials.username,
        password=collector.credentials.password, key_filename=None, passphrase=None,
        allow_agent=False, look_for_keys=False, timeout=2, banner_timeout=2,
        auth_timeout=2, channel_timeout=0.1,
    )
    transport = client.get_transport.return_value
    transport.open_session.assert_called_once_with(timeout=0.1)
    transport.sock.shutdown.assert_called_with(ssh.socket.SHUT_RDWR)
    transport.sock.close.assert_called()
    assert channel.closed
    client.close.assert_called_once()


@pytest.mark.parametrize("stage,error", [
    ("load_host_keys", OSError),
    ("connect", paramiko.AuthenticationException),
    ("connect", ConnectionRefusedError),
    ("connect", TimeoutError),
    ("connect", paramiko.SSHException),
    ("open_session", TimeoutError),
    ("exec_command", paramiko.SSHException),
    ("exec_command", TimeoutError),
    ("recv", OSError),
    ("close", OSError),
])
def test_failures_are_sanitized_and_client_is_closed(setup, stage, error):
    collector, client, channel, _ = setup
    if stage == "open_session":
        method = client.get_transport.return_value.open_session
    elif stage in {"exec_command", "recv"}:
        method = Mock()
        setattr(channel, stage, method)
    else:
        method = getattr(client, stage)
    method.side_effect = error("synthetic-private-marker")
    with pytest.raises(network.NetworkSSHError) as caught:
        collector.collect(target())
    assert "private-marker" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    client.close.assert_called_once()
    if stage in {"exec_command", "recv", "close"}:
        assert channel.closed


@pytest.mark.parametrize("platform", [None, "", "cisco_ios", "arista_eos; bad", []])
def test_unsupported_platform_fails_before_connection(setup, platform):
    collector, _, _, factory = setup
    collector = replace(collector, platforms={"switch": platform})
    with pytest.raises(network.NetworkSSHError):
        collector.collect(target())
    factory.assert_not_called()


def test_missing_platform_and_wrong_kind(setup):
    collector, _, _, factory = setup
    for item in [target("missing"), target(kind=TargetKind.LINUX)]:
        with pytest.raises(network.NetworkSSHError):
            collector.collect(item)
    factory.assert_not_called()


@pytest.mark.parametrize("platform,response", [
    ("arista_eos", b"% Invalid command"),
    ("arista_eos", b"[]"),
    ("arista_eos", b'{"error":"private-marker","interfaces":{}}'),
    ("arista_eos", b'{"interfaces":{}}'),
    ("arista_eos", b'{"interfaces":[]}'),
    ("arista_eos", b'{"interfaces":{"Ethernet1":null}}'),
    ("arista_eos", b'{"interfaces":{"Ethernet1":{},"Ethernet1":{}}}'),
    ("arista_eos", b'{"interfaces":{"bad name":{}}}'),
    ("arista_eos", b'{"interfaces":{"Ethernet1":{}},"x":NaN}'),
    ("arista_eos", b"\xff"),
    ("juniper_junos", b"<broken>"),
    ("juniper_junos", b"<rpc-reply><rpc-error/></rpc-reply>"),
    ("juniper_junos", b"<rpc-reply/>"),
    ("juniper_junos", b"<rpc-reply><interface-information/></rpc-reply>"),
    ("juniper_junos", JUNOS.replace(b"<name>ge-0/0/0</name>", b"")),
    ("juniper_junos", JUNOS.replace(b"ge-0/0/0.0", b"ge-0/0/0")),
    ("juniper_junos", b'<!DOCTYPE rpc-reply [<!ENTITY x "value">]>' + JUNOS),
])
def test_malformed_output_is_isolated_and_cleaned_up(setup, platform, response):
    original, client, channel, _ = setup
    collector = replace(original, platforms={"switch": platform})
    channel.output = response
    outcome = discover([target()], {TargetKind.NETWORK: collector})[0]
    assert outcome.error is DiscoveryError.COLLECTION_FAILED
    assert channel.closed
    client.close.assert_called_once()
    assert "private-marker" not in repr(outcome)


@pytest.mark.parametrize("mode", ["status", "missing_status", "stall", "overflow"])
def test_command_failure_and_bounded_output(setup, mode):
    collector, client, channel, _ = setup
    if mode == "status":
        channel.status = 1
    elif mode == "missing_status":
        channel.status = -1
    elif mode == "stall":
        channel.eof_received = False
    else:
        channel.stderr = b"x" * (ssh._MAX_OUTPUT + 1)
    with pytest.raises(network.NetworkSSHError):
        collector.collect(target())
    assert channel.closed
    client.close.assert_called_once()


@pytest.mark.parametrize("stall", [
    "acknowledgement", "rekey", "socket_write", "channel_open",
])
def test_actual_paramiko_protocol_stalls_are_interrupted(setup, stall):
    collector, client, _, _ = setup
    entered, interrupted, finished = Event(), Event(), Event()
    sock = Mock()
    sock.shutdown.side_effect = lambda how: interrupted.set()
    transport = paramiko.Transport(sock)
    transport.active = True
    transport.clear_to_send.set()
    channel = paramiko.Channel(0)
    channel._set_transport(transport)
    channel.active = True
    transport._channels.put(0, channel)
    if stall != "channel_open":
        transport.open_session = Mock(return_value=channel)
    client.get_transport.return_value = transport

    def send_message(message):
        entered.set()
        if stall == "rekey":
            transport.clear_to_send.clear()
        elif stall == "socket_write":
            assert interrupted.wait(3)
            raise OSError("synthetic-private-marker")

    transport._send_message = send_message
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
        assert finished.wait(1), "Deadline failed to interrupt SSH protocol wait"
        assert len(failures) == 1
        assert isinstance(failures[0], network.NetworkSSHError)
        if stall != "channel_open":
            assert channel.closed
        assert not transport.is_active()
        sock.shutdown.assert_called_with(ssh.socket.SHUT_RDWR)
        client.close.assert_called_once()
    finally:
        interrupted.set()
        transport.active = False
        transport.clear_to_send.set()
        channel._unlink()
        worker.join(timeout=1)
        transport.close()
    assert not worker.is_alive()


def test_concurrent_sessions_and_discovery_failure_isolation(setup, monkeypatch):
    original, _, _, _ = setup
    platforms = {"eos": "arista_eos", "junos": "juniper_junos", "bad": "arista_eos"}
    collector = replace(original, platforms=platforms, command_timeout=2)
    platforms["eos"] = "unsupported"  # Constructor took its own snapshot.
    barrier = Barrier(3)
    lock = Lock()
    clients = []

    def factory():
        client = Mock()
        channel = Channel()
        client.get_transport.return_value.open_session.return_value = channel

        def connect(**options):
            host = options["hostname"]
            channel.output = JUNOS if host == "junos.example.com" else EOS
            barrier.wait(timeout=2)
            if host == "bad.example.com":
                raise paramiko.AuthenticationException("synthetic-private-marker")

        client.connect.side_effect = connect
        with lock:
            clients.append((client, channel))
        return client

    monkeypatch.setattr(ssh.paramiko, "SSHClient", factory)
    items = [Target(key, key + ".example.com", TargetKind.NETWORK) for key in platforms]
    items += [target("missing"), target("linux", TargetKind.LINUX)]
    outcomes = discover(items, {TargetKind.NETWORK: collector,
                               TargetKind.LINUX: FakeLinuxCollector()}, max_workers=3)
    assert [result.succeeded for result in outcomes] == [True, True, False, False, True]
    assert outcomes[0].facts == NetworkFacts("arista_eos", ("Ethernet1", "Management1"))
    assert outcomes[1].facts == NetworkFacts("juniper_junos", ("ge-0/0/0", "ge-0/0/0.0"))
    assert [result.target for result in outcomes] == items
    assert len(clients) == 3
    for client, channel in clients:
        client.close.assert_called_once()
        if channel.command:
            assert channel.closed


def test_credentials_and_configuration_boundaries(setup):
    collector, _, _, _ = setup
    assert network.SSHCredentials is ssh.SSHCredentials
    with pytest.raises(FrozenInstanceError):
        collector.port = 23
    with pytest.raises(TypeError):
        collector.platforms["switch"] = "juniper_junos"
    assert "synthetic-private-marker" not in repr(collector)
    assert "example-user" not in repr(collector.credentials)
    result = discover([target()], {TargetKind.NETWORK: collector})[0]
    assert set(asdict(result.facts)) == {"platform", "interfaces"}
    assert set(asdict(result.target)) == {"id", "host", "kind"}
    assert "private-marker" not in repr(asdict(result))


def test_transport_logs_are_private_and_unrelated_logging_survives(setup, caplog):
    collector, client, _, _ = setup
    library = logging.getLogger("paramiko.transport")
    settings = (library.level, library.propagate, library.disabled, tuple(library.handlers))

    def connect(**options):
        name = client.set_log_channel.call_args.args[0]
        logging.getLogger(name).warning("synthetic-private-marker")
        logging.getLogger(name + ".channel").warning("synthetic-private-marker")
        library.warning("unrelated-transport")
        raise paramiko.SSHException("synthetic-private-marker")

    client.connect.side_effect = connect
    with caplog.at_level(logging.DEBUG), pytest.raises(network.NetworkSSHError):
        collector.collect(target())
    assert "private-marker" not in caplog.text
    assert "unrelated-transport" in caplog.text
    assert settings == (library.level, library.propagate, library.disabled, tuple(library.handlers))


def test_host_key_failure_and_cancellation_close_session(setup):
    collector, client, _, _ = setup
    client.connect.side_effect = paramiko.BadHostKeyException(
        "private-marker", Mock(), Mock())
    with pytest.raises(network.NetworkSSHError):
        collector.collect(target())
    client.close.assert_called_once()
    client.reset_mock()
    client.connect.side_effect = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        collector.collect(target())
    client.close.assert_called_once()
