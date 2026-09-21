"""Offline CLI tests exercise real loading, construction, routing and parsing."""

import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
from unittest.mock import Mock
import warnings

import pytest

from infra_discovery import cli, configuration
from infra_discovery.models import DiscoveryError, DiscoveryOutcome, LinuxFacts, Target, TargetKind
from infra_discovery.output import format_human, format_json
from infra_discovery.ssh import SSHCommandRunner


@pytest.fixture
def setup_cli(tmp_path, monkeypatch):
    secret = "synthetic-" + "password-for-test"
    prompt = Mock(return_value=secret)
    monkeypatch.setattr(configuration.getpass, "getpass", prompt)
    calls = []

    def command(self, target, command):
        calls.append((self, target, command))
        if target.id.startswith("fail"):
            raise RuntimeError(secret)
        if target.kind is TargetKind.LINUX:
            return b'Linux\n6.1-example\nNAME="Example Linux"\n'
        return b'{"interfaces":{"Ethernet1":{}}}'

    monkeypatch.setattr(SSHCommandRunner, "_run_command", command)
    (tmp_path / "hosts").write_text("", encoding="utf-8")
    (tmp_path / "identity").write_text("synthetic key placeholder", encoding="utf-8")

    def prepare(kinds=("linux",), failures=(), key=False):
        entries = [{"id": ("fail" if index in failures else "target") + str(index),
                    "host": "host.example", "kind": kind}
                   for index, kind in enumerate(kinds)]
        inventory = tmp_path / "inventory with spaces.json"
        inventory.write_text(json.dumps(entries), encoding="utf-8")
        config = {}
        for kind in set(kinds):
            config[kind] = {"username": "example-user", "known_hosts": "hosts",
                            "port": 2222, "connection_timeout": 2, "command_timeout": 3}
            if key:
                config[kind]["key_filename"] = "identity"
            if kind == "network":
                config[kind]["platforms"] = {entry["id"]: "arista_eos" for entry in entries if entry["kind"] == kind}
        path = tmp_path / "connections.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        return [str(inventory), "--config", str(path)], path, config

    return prepare, prompt, calls, secret


@pytest.mark.parametrize("kinds", [("linux",), ("network",), ("network", "linux", "network"), ()])
@pytest.mark.parametrize("workers", [1, 3])
def test_real_collector_integration(setup_cli, capsys, kinds, workers):
    prepare, prompt, calls, secret = setup_cli
    args, _, _ = prepare(kinds)
    assert cli.main(args + ["--json", "--max-workers", str(workers)]) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert captured.err == ""
    assert secret not in captured.out
    assert "example-user" not in captured.out
    assert document["schema_version"] == 1
    assert document["summary"] == {"total": len(kinds), "succeeded": len(kinds), "failed": 0}
    assert [result["target"]["id"] for result in document["results"]] == [f"target{i}" for i in range(len(kinds))]
    assert [result["target"]["kind"] for result in document["results"]] == list(kinds)
    assert prompt.call_count == len(set(kinds))
    assert {call.args[0] for call in prompt.call_args_list} == {f"{kind} SSH password: " for kind in kinds}
    for collector, target, _ in calls:
        assert collector.credentials.password == secret
        assert collector.port == 2222
        assert collector.connection_timeout == 2
        assert collector.command_timeout == 3
        assert Path(collector.known_hosts).is_absolute()
    for result in document["results"]:
        assert set(result) == {"target", "status", "facts", "error"}
        assert result["status"] == "success" and result["error"] is None
        assert result["facts"] == ({"distribution": "Example Linux", "kernel_release": "6.1-example"}
                                    if result["target"]["kind"] == "linux"
                                    else {"platform": "arista_eos", "interfaces": ["Ethernet1"]})


@pytest.mark.parametrize("failures", [(0,), (0, 1)])
@pytest.mark.parametrize("json_mode", [False, True])
def test_failure_output(setup_cli, capsys, failures, json_mode):
    prepare, _, _, secret = setup_cli
    args, _, _ = prepare(("linux", "network"), failures)
    assert cli.main(args + (["--json"] if json_mode else [])) == 1
    out = capsys.readouterr()
    assert not out.err and secret not in out.out
    if json_mode:
        document = json.loads(out.out)
        assert document["summary"]["failed"] == len(failures)
        result = document["results"][0]
        assert result["facts"] is None
        assert result["status"] == "failure"
        assert result["error"] == {"code": "COLLECTION_FAILED", "message": "Collector raised an exception."}
    else:
        assert "FAILURE" in out.out and f"{len(failures)} failed" in out.out


def test_human_success(setup_cli, capsys):
    args, _, _ = setup_cli[0]()
    assert cli.main(args) == 0
    out = capsys.readouterr().out
    assert 'SUCCESS "target0" (linux, "host.example")' in out
    assert "Example Linux" in out and "1 targets: 1 succeeded, 0 failed." in out


@pytest.mark.parametrize("passphrase", [False, True])
def test_key_auth(setup_cli, capsys, passphrase):
    prepare, prompt, calls, secret = setup_cli
    args, path, config = prepare(key=True)
    config["linux"]["prompt_passphrase"] = passphrase
    path.write_text(json.dumps(config))
    assert cli.main(args) == 0
    credentials = calls[0][0].credentials
    assert credentials.password is None
    assert Path(credentials.key_filename).is_absolute()
    assert credentials.passphrase == (secret if passphrase else None)
    assert prompt.call_count == int(passphrase)
    assert secret not in str(capsys.readouterr())


@pytest.mark.parametrize("failure", [EOFError, OSError, KeyboardInterrupt, getpass.GetPassWarning])
def test_prompt_failure(setup_cli, capsys, failure):
    prepare, prompt, calls, _ = setup_cli
    args, _, _ = prepare()
    prompt.side_effect = failure
    assert cli.main(args) == (130 if failure is KeyboardInterrupt else 2)
    out = capsys.readouterr()
    assert not out.out and "Traceback" not in out.err
    assert not calls


def test_no_echo_fallback(setup_cli, monkeypatch, capsys):
    args, _, _ = setup_cli[0]()
    def unsafe_prompt(prompt):
        warnings.warn("fallback", getpass.GetPassWarning)
        pytest.fail("must not proceed to echoed input")
    monkeypatch.setattr(configuration.getpass, "getpass", unsafe_prompt)
    assert cli.main(args) == 2
    assert "Secure secret entry unavailable" in capsys.readouterr().err


@pytest.mark.parametrize("argv,code", [(["--help"], 0), ([], 2), (["file", "--max-workers", "0"], 2),
    (["file", "--max-workers", "-1"], 2), (["file", "--max-workers", "1.2"], 2),
    (["file", "--password", "synthetic"], 2)])
def test_argument_parsing(argv, code, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == code
    captured = capsys.readouterr()
    assert "usage:" in captured.out + captured.err
    assert "synthetic" not in captured.out + captured.err


def test_unused_kind_does_not_prompt(setup_cli):
    args, path, config = setup_cli[0]()
    config["network"] = {"username": "example", "known_hosts": "hosts", "platforms": {}}
    path.write_text(json.dumps(config))
    assert cli.main(args) == 0
    setup_cli[1].assert_called_once_with("linux SSH password: ")


def test_empty_secret_rejected(setup_cli, capsys):
    args, _, _ = setup_cli[0]()
    setup_cli[1].return_value = ""
    assert cli.main(args) == 2
    assert "nonempty secret" in capsys.readouterr().err


@pytest.mark.parametrize("content", [None, "{", '[{"password":"synthetic"}]', "{}"])
def test_bad_inventory(tmp_path, content, capsys):
    path = tmp_path / "input.json"
    if content is not None:
        path.write_text(content)
    assert cli.main([str(path)]) == 2
    captured = capsys.readouterr()
    assert not captured.out and "synthetic" not in captured.err


@pytest.mark.parametrize("field,value", [("password", "synthetic"), ("passphrase", "synthetic"),
    ("username", ""), ("known_hosts", "missing"), ("key_filename", "missing"),
    ("port", 0), ("port", True), ("port", 65536), ("connection_timeout", float("nan")),
    ("command_timeout", float("inf")), ("command_timeout", -1), ("prompt_passphrase", True),
    ("prompt_passphrase", "yes"), ("platforms", {})])
def test_invalid_configuration(setup_cli, capsys, field, value):
    prepare, prompt, calls, _ = setup_cli
    args, path, config = prepare()
    config["linux"][field] = value
    path.write_text(json.dumps(config))
    assert cli.main(args) == 2
    assert not prompt.called and not calls
    captured = capsys.readouterr()
    assert not captured.out and "synthetic" not in captured.err


@pytest.mark.parametrize("content", ["{", "[]", '{"linux":{},"linux":{}}', '{"other":{}}', '{}'])
def test_invalid_config_document(setup_cli, capsys, content):
    args, path, _ = setup_cli[0]()
    path.write_text(content)
    assert cli.main(args) == 2
    assert not setup_cli[1].called


@pytest.mark.parametrize("platforms", [{}, {"target0": "unsupported"}, {"target0": []}, None])
def test_network_platform_configuration(setup_cli, platforms):
    args, path, config = setup_cli[0](("network",))
    config["network"]["platforms"] = platforms
    path.write_text(json.dumps(config))
    assert cli.main(args) == 2
    assert not setup_cli[1].called


def test_missing_configuration_and_empty_inventory(setup_cli, capsys):
    args, path, _ = setup_cli[0]()
    assert cli.main(args[:1]) == 2
    path.unlink()
    assert cli.main(args) == 2
    Path(args[0]).write_text("[]")
    assert cli.main(args[:1] + ["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["results"] == []


def test_discovery_interrupt(setup_cli, monkeypatch, capsys):
    args, _, _ = setup_cli[0]()
    monkeypatch.setattr(cli, "discover", Mock(side_effect=KeyboardInterrupt))
    assert cli.main(args) == 130
    captured = capsys.readouterr()
    assert not captured.out and captured.err == "infra-discovery: interrupted.\n"


def test_serialization_escaping_and_determinism():
    value = 'quoted"\\\n\t\x1b café \ud800'
    target = Target(value, value, TargetKind.LINUX)
    outcomes = [DiscoveryOutcome(target, facts=LinuxFacts(value, value)),
                DiscoveryOutcome(target, error=DiscoveryError.COLLECTION_FAILED)]
    encoded = format_json(outcomes)
    assert encoded == format_json(outcomes)
    document = json.loads(encoded)
    assert document["results"][0]["facts"]["distribution"] == value
    assert len(document["results"]) == 2
    assert "\x1b" not in format_human(outcomes)
    encoded.encode("ascii")


def test_console_entry_configuration():
    path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    metadata = tomllib.loads(path.read_text())
    assert metadata["project"]["scripts"]["infra-discovery"] == "infra_discovery.cli:main"
    assert any(dep.startswith("paramiko") for dep in metadata["project"]["dependencies"])


@pytest.mark.parametrize("output_args", [[], ["--json"]])
def test_closed_stdout_pipe_at_process_exit(tmp_path, output_args):
    inventory = tmp_path / "empty.json"
    inventory.write_text("[]", encoding="utf-8")
    read_fd, write_fd = os.pipe()
    os.close(read_fd)  # No reader exists before the child can write or flush.
    environment = os.environ.copy()
    environment.pop("PYTHONUNBUFFERED", None)
    try:
        result = subprocess.run(
            [sys.executable, "-c",
             "from infra_discovery.cli import main; raise SystemExit(main())",
             str(inventory), *output_args],
            cwd=tmp_path,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=write_fd,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    finally:
        os.close(write_fd)
    assert result.returncode == 2, result.stderr
    assert result.stderr == (
        "infra-discovery: I/O failed; check file access and output destination.\n"
    )
