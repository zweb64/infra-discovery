"""Domain models for infrastructure discovery targets."""

from dataclasses import dataclass
from enum import Enum


class TargetKind(Enum):
    NETWORK = "network"
    LINUX = "linux"


@dataclass
class Target:
    id: str
    host: str
    kind: TargetKind


@dataclass(frozen=True)
class NetworkFacts:
    platform: str
    interfaces: tuple[str, ...]


@dataclass(frozen=True)
class LinuxFacts:
    distribution: str
    kernel_release: str


class DiscoveryError(Enum):
    INVALID_TARGET_KIND = "Invalid target kind."
    MISSING_COLLECTOR = "No collector registered for target kind."
    INVALID_RESULT = "Collector returned facts for an incorrect target kind."
    COLLECTION_FAILED = "Collector raised an exception."


@dataclass(frozen=True)
class DiscoveryOutcome:
    target: Target
    facts: NetworkFacts | LinuxFacts | None = None
    error: DiscoveryError | None = None

    def __post_init__(self) -> None:
        if (self.facts is None) == (self.error is None):
            raise ValueError("An outcome requires exactly one of facts or error.")
        if self.error is not None and not isinstance(self.error, DiscoveryError):
            raise ValueError("Outcome error must be a DiscoveryError.")
        if self.facts is not None:
            expected = {
                TargetKind.NETWORK: NetworkFacts,
                TargetKind.LINUX: LinuxFacts,
            }
            if not isinstance(self.target.kind, TargetKind) or not isinstance(
                self.facts, expected[self.target.kind]
            ):
                raise ValueError("Outcome facts must match the target kind.")

    @property
    def succeeded(self) -> bool:
        return self.error is None
