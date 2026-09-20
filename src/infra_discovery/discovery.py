"""Bounded discovery orchestration and per-target failure isolation."""

from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from functools import partial

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
    targets: Iterable[Target],
    collectors: Mapping[TargetKind, Collector],
    *,
    max_workers: int = 1,
) -> list[DiscoveryOutcome]:
    """Return outcomes in input order, preserving duplicates and original targets.

    max_workers must be a positive integer (not bool); invalid values raise
    ValueError before consuming targets. The default runs sequentially; larger
    values share collector instances across at most max_workers threads.
    Collectors must support concurrent calls when concurrency is enabled.
    Results retain input order even when collection finishes out of order.

    Invalid registry entries raise ValueError before consuming targets. Missing
    routes, invalid target kinds, wrong result types, and collector exceptions
    produce failed outcomes. Exception text is deliberately not retained.
    BaseException (including cancellation via KeyboardInterrupt) propagates.
    Input iteration errors propagate; inputs must be Target objects.
    """
    if (
        isinstance(max_workers, bool)
        or not isinstance(max_workers, int)
        or max_workers < 1
    ):
        raise ValueError("max_workers must be a positive integer (not bool).")

    registry = dict(collectors)
    for kind, collector in registry.items():
        if (
            not isinstance(kind, TargetKind)
            or getattr(collector, "kind", None) is not kind
            or not callable(getattr(collector, "collect", None))
        ):
            raise ValueError("Collector registration must match a supported target kind.")

    collect_one = partial(_discover_target, registry=registry)
    if max_workers == 1:
        return [collect_one(target) for target in targets]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(collect_one, targets))


def _discover_target(
    target: Target, registry: Mapping[TargetKind, Collector]
) -> DiscoveryOutcome:
    """Route one target and translate collection failures into outcomes."""
    if not isinstance(target.kind, TargetKind):
        return DiscoveryOutcome(target, error=DiscoveryError.INVALID_TARGET_KIND)
    collector = registry.get(target.kind)
    if collector is None:
        return DiscoveryOutcome(target, error=DiscoveryError.MISSING_COLLECTOR)
    try:
        facts = collector.collect(target)
    except Exception:
        return DiscoveryOutcome(target, error=DiscoveryError.COLLECTION_FAILED)
    expected = NetworkFacts if target.kind is TargetKind.NETWORK else LinuxFacts
    if not isinstance(facts, expected):
        return DiscoveryOutcome(target, error=DiscoveryError.INVALID_RESULT)
    return DiscoveryOutcome(target, facts=facts)
