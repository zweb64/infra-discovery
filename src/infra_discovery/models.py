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
