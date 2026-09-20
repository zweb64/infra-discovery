"""Read-only network interface discovery using noninteractive SSH exec."""

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
import re
from types import MappingProxyType
from xml.etree import ElementTree

from infra_discovery.models import NetworkFacts, Target, TargetKind
from infra_discovery.ssh import SSHCommandRunner, SSHCredentials


_COMMANDS = MappingProxyType({
    "arista_eos": "show interfaces | json",
    "juniper_junos": "show interfaces terse | display xml | no-more",
})
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9./:_-]{0,127}\Z")


class NetworkSSHError(Exception):
    """Sanitized target-specific failure without remote diagnostics."""


@dataclass(frozen=True)
class NetworkSSHCollector(SSHCommandRunner):
    """One credential set; an immutable snapshot selects each target's driver.

    Platform is a configured OS family, not an independently detected version.
    Only the fixed commands above are executed; no shell or privilege escalation.
    """

    platforms: Mapping[str, str] = field(kw_only=True, repr=False)

    kind = TargetKind.NETWORK

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.platforms, Mapping):
            raise ValueError("A target-to-platform mapping is required.")
        object.__setattr__(self, "platforms", MappingProxyType(dict(self.platforms)))

    def collect(self, target: Target) -> NetworkFacts:
        if target.kind is not self.kind:
            raise NetworkSSHError("Network SSH collection requires a network target.")
        try:
            platform = self.platforms[target.id]
            command = _COMMANDS[platform]
            data = self._run_command(target, command)
            return _parse_response(platform, data)
        except Exception:
            pass
        # Outside the handler: neither __cause__ nor __context__ retains secrets.
        raise NetworkSSHError("Network SSH collection failed.")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate response field.")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError("Invalid JSON constant.")


def _parse_response(platform: str, data: bytes) -> NetworkFacts:
    text = data.decode("utf-8", errors="strict")
    if platform == "arista_eos":
        document = json.loads(
            text, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
        if not isinstance(document, dict) or "error" in document:
            raise ValueError("Invalid interface response.")
        interfaces = document.get("interfaces")
        if not isinstance(interfaces, dict) or any(
            not isinstance(value, dict) for value in interfaces.values()
        ):
            raise ValueError("Invalid interface response.")
        names = list(interfaces)
    elif platform == "juniper_junos":
        # Do not accept DTD/entity declarations, even within the byte limit.
        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            raise ValueError("Invalid XML response.")
        root = ElementTree.fromstring(text)
        # Junos uses version-dependent namespaces. Compare local tag names.
        for element in root.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]
        if root.tag != "rpc-reply" or any(
            element.tag in {"rpc-error", "error"} for element in root.iter()
        ):
            raise ValueError("Invalid interface response.")
        groups = root.findall("interface-information")
        if len(groups) != 1:
            raise ValueError("Invalid interface response.")
        names = []
        for interface in groups[0].iter():
            if interface.tag in {"physical-interface", "logical-interface"}:
                fields = interface.findall("name")
                if len(fields) != 1 or fields[0].text is None:
                    raise ValueError("Missing interface name.")
                names.append(fields[0].text.strip())
    else:
        raise ValueError("Unsupported platform.")
    if not names or any(not _NAME.fullmatch(name) for name in names):
        raise ValueError("Invalid interface names.")
    if len(set(names)) != len(names):
        raise ValueError("Duplicate interface names.")
    return NetworkFacts(platform=platform, interfaces=tuple(sorted(names)))
