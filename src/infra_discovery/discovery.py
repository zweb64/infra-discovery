"""Sequential routing and per-target failure isolation."""

from collections.abc import Iterable, Mapping

from infra_discovery.collectors import Collector
from infra_discovery.models import (
    DiscoveryError,
    DiscoveryOutcome,
    LinuxFacts,
    NetworkFacts,
    Target,
    TargetKind,
)


def discover(
    targets: Iterable[Target], collectors: Mapping[TargetKind, Collector]
) -> list[DiscoveryOutcome]:
    """Process targets in order, preserving duplicates and original targets.

    Invalid registry entries raise ValueError before consuming targets. Missing
    routes, invalid target kinds, wrong result types, and collector exceptions
    produce failed outcomes. Exception text is deliberately not retained.
    BaseException (including cancellation via KeyboardInterrupt) propagates.
    Input iteration errors propagate; inputs must be Target objects.
    """
    registry = dict(collectors)
    for kind, collector in registry.items():
        if (
            not isinstance(kind, TargetKind)
            or getattr(collector, "kind", None) is not kind
            or not callable(getattr(collector, "collect", None))
        ):
            raise ValueError("Collector registration must match a supported target kind.")

    outcomes = []
    for target in targets:
        if not isinstance(target.kind, TargetKind):
            outcomes.append(
                DiscoveryOutcome(target, error=DiscoveryError.INVALID_TARGET_KIND)
            )
            continue
        collector = registry.get(target.kind)
        if collector is None:
            outcomes.append(
                DiscoveryOutcome(target, error=DiscoveryError.MISSING_COLLECTOR)
            )
            continue
        try:
            facts = collector.collect(target)
        except Exception:
            outcomes.append(
                DiscoveryOutcome(target, error=DiscoveryError.COLLECTION_FAILED)
            )
            continue
        expected = NetworkFacts if target.kind is TargetKind.NETWORK else LinuxFacts
        if not isinstance(facts, expected):
            outcomes.append(
                DiscoveryOutcome(target, error=DiscoveryError.INVALID_RESULT)
            )
        else:
            outcomes.append(DiscoveryOutcome(target, facts=facts))
    return outcomes
