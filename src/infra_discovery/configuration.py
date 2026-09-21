"""Strict, non-secret CLI configuration and runtime credential prompting."""

import getpass
import json
import math
from pathlib import Path
import warnings

from infra_discovery.collectors import Collector
from infra_discovery.linux_ssh import LinuxSSHCollector
from infra_discovery.models import Target, TargetKind
from infra_discovery.network_ssh import NetworkSSHCollector
from infra_discovery.ssh import SSHCredentials


class ConfigurationError(ValueError):
    """A safe, actionable configuration diagnostic."""


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("Configuration contains duplicate keys.")
        result[key] = value
    return result


def _file(value: object, base: Path, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{field} must be a nonempty file path.")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    try:
        with path.open("rb"):
            pass
    except (OSError, ValueError):
        raise ConfigurationError(f"{field} must name a readable file.") from None
    return str(path)


def load_configuration(path: Path | None, targets: list[Target]) -> dict:
    """Validate all supplied sections before requesting any credentials."""
    needed = {target.kind.value for target in targets}
    if path is None:
        if needed:
            raise ConfigurationError("Supply --config with connection settings.")
        return {}
    try:
        config = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object)
    except (OSError, ValueError):
        raise ConfigurationError("Cannot read configuration: use valid UTF-8 JSON with unique keys.") from None
    if not isinstance(config, dict) or set(config) - {"linux", "network"}:
        raise ConfigurationError("Configuration must contain only linux/network sections.")
    if needed - set(config):
        raise ConfigurationError("Configuration needs a section for each inventory target kind.")
    for kind, section in config.items():
        allowed = {"username", "known_hosts", "key_filename", "prompt_passphrase",
                   "port", "connection_timeout", "command_timeout"}
        if kind == "network":
            allowed.add("platforms")
        if not isinstance(section, dict) or set(section) - allowed:
            raise ConfigurationError("Unknown configuration field; passwords and passphrases must be prompted.")
        username = section.get("username")
        if not isinstance(username, str) or not username.strip():
            raise ConfigurationError(f"{kind}.username is required.")
        section["known_hosts"] = _file(section.get("known_hosts"), path.parent, f"{kind}.known_hosts")
        if "key_filename" in section:
            section["key_filename"] = _file(section["key_filename"], path.parent, f"{kind}.key_filename")
        prompt = section.get("prompt_passphrase", False)
        if type(prompt) is not bool or (prompt and "key_filename" not in section):
            raise ConfigurationError("prompt_passphrase requires a key_filename and a boolean value.")
        port = section.get("port", 22)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ConfigurationError("port must be an integer between 1 and 65535.")
        for field in ("connection_timeout", "command_timeout"):
            value = section.get(field, 10.0)
            try:
                valid = type(value) in (int, float) and math.isfinite(value) and value > 0
            except OverflowError:
                valid = False
            if not valid:
                raise ConfigurationError(f"{field} must be a finite positive number.")
        if kind == "network":
            platforms = section.get("platforms")
            if not isinstance(platforms, dict) or any(
                not isinstance(value, str) or value not in ("arista_eos", "juniper_junos")
                for value in platforms.values()
            ):
                raise ConfigurationError("network.platforms must map target IDs to arista_eos or juniper_junos.")
            if any(target.id not in platforms for target in targets if target.kind is TargetKind.NETWORK):
                raise ConfigurationError("network.platforms needs an entry for every network target ID.")
    return {kind: config[kind] for kind in sorted(needed)}


def _secret(prompt: str) -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass(prompt)
    except (getpass.GetPassWarning, EOFError, OSError):
        raise ConfigurationError("Secure secret entry unavailable; use an interactive terminal or key authentication.") from None
    if not value:
        raise ConfigurationError("A nonempty secret is required.")
    return value


def build_collectors(config: dict) -> dict[TargetKind, Collector]:
    """Prompt only for selected collectors; never persist runtime credentials."""
    collectors = {}
    for kind, section in config.items():
        options = dict(section)
        username = options.pop("username")
        key = options.pop("key_filename", None)
        prompt = options.pop("prompt_passphrase", False)
        credentials = SSHCredentials(
            username=username,
            password=_secret(f"{kind} SSH password: ") if key is None else None,
            key_filename=key,
            passphrase=_secret(f"{kind} SSH key passphrase: ") if prompt else None,
        )
        factory = LinuxSSHCollector if kind == "linux" else NetworkSSHCollector
        collectors[TargetKind(kind)] = factory(credentials=credentials, **options)
    return collectors
