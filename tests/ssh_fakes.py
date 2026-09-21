"""Offline TCP boundary shared by SSH collector tests."""

from unittest.mock import Mock

from infra_discovery import ssh


def install_tcp_fakes(monkeypatch):
    monkeypatch.setattr(ssh.socket, "getaddrinfo", Mock(return_value=[
        (ssh.socket.AF_INET, ssh.socket.SOCK_STREAM, 6, "", ("192.0.2.1", 22)),
    ]))
    factory = Mock(side_effect=lambda *args: Mock())
    monkeypatch.setattr(ssh.socket, "socket", factory)
    return factory
