"""Transport-independent collector contract and deterministic offline fixtures."""

from typing import Protocol

from infra_discovery.models import LinuxFacts, NetworkFacts, Target, TargetKind


class Collector(Protocol):
    @property
    def kind(self) -> TargetKind:
        """The single target kind supported by this collector."""
        ...

    def collect(self, target: Target) -> NetworkFacts | LinuxFacts:
        """Return facts or raise an exception; do not mutate the target."""
        ...


class FakeNetworkCollector:
    kind = TargetKind.NETWORK

    def collect(self, target: Target) -> NetworkFacts:
        if target.kind is not self.kind:
            raise ValueError("Network collector requires a network target.")
        return NetworkFacts(platform="offline-network-os", interfaces=("eth0", "eth1"))


class FakeLinuxCollector:
    kind = TargetKind.LINUX

    def collect(self, target: Target) -> LinuxFacts:
        if target.kind is not self.kind:
            raise ValueError("Linux collector requires a Linux target.")
        return LinuxFacts(distribution="offline-linux", kernel_release="6.1.0-fake")
