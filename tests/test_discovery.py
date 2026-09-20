import pytest

from infra_discovery.collectors import FakeLinuxCollector, FakeNetworkCollector
from infra_discovery.discovery import discover
from infra_discovery.inventory import load_inventory
from infra_discovery.models import (
    DiscoveryError,
    DiscoveryOutcome,
    LinuxFacts,
    NetworkFacts,
    Target,
    TargetKind,
)


def target(kind=TargetKind.LINUX, identifier="example"):
    return Target(identifier, "host.example.com", kind)


def registry():
    return {
        TargetKind.NETWORK: FakeNetworkCollector(),
        TargetKind.LINUX: FakeLinuxCollector(),
    }


@pytest.mark.parametrize(
    ("collector", "kind", "expected"),
    [
        (FakeNetworkCollector(), TargetKind.NETWORK,
         NetworkFacts("offline-network-os", ("eth0", "eth1"))),
        (FakeLinuxCollector(), TargetKind.LINUX,
         LinuxFacts("offline-linux", "6.1.0-fake")),
    ],
)
def test_fake_collection_is_deterministic(collector, kind, expected):
    item = target(kind)
    assert collector.collect(item) == expected
    assert collector.collect(item) == expected
    assert item == target(kind)


@pytest.mark.parametrize(
    ("collector", "kind"),
    [(FakeNetworkCollector(), TargetKind.LINUX),
     (FakeLinuxCollector(), TargetKind.NETWORK),
     (FakeLinuxCollector(), "linux")],
)
def test_fake_rejects_wrong_target_kind(collector, kind):
    with pytest.raises(ValueError):
        collector.collect(target(kind))


def test_inventory_to_outcomes(tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        '[{"id":"switch","host":"switch.example.com","kind":"network"},'
        '{"id":"server","host":"server.example.com","kind":"linux"}]',
        encoding="utf-8",
    )
    targets = load_inventory(inventory)
    outcomes = discover(iter(targets), registry())
    assert len(outcomes) == 2
    assert all(outcome.succeeded and outcome.error is None for outcome in outcomes)
    assert outcomes[0].target is targets[0]
    assert outcomes[1].target is targets[1]
    assert isinstance(outcomes[0].facts, NetworkFacts)
    assert isinstance(outcomes[1].facts, LinuxFacts)


def test_empty_and_duplicate_targets():
    assert discover([], registry()) == []
    item = target()
    outcomes = discover([item, item], registry())
    assert len(outcomes) == 2
    assert all(outcome.target is item and outcome.succeeded for outcome in outcomes)


@pytest.mark.parametrize("exception", [RuntimeError, ValueError, OSError])
def test_failure_isolated_and_exception_text_not_exposed(exception):
    calls = []

    class SelectiveCollector:
        kind = TargetKind.LINUX

        def collect(self, item):
            calls.append(item.id)
            if item.id == "broken":
                raise exception("private diagnostic details")
            return LinuxFacts("example-linux", "example-kernel")

    collectors = registry()
    collectors[TargetKind.LINUX] = SelectiveCollector()
    targets = [target(identifier="before"), target(identifier="broken"),
               target(TargetKind.NETWORK), target(identifier="after")]
    outcomes = discover(targets, collectors)
    assert [outcome.succeeded for outcome in outcomes] == [True, False, True, True]
    assert calls == ["before", "broken", "after"]
    assert outcomes[1].target is targets[1]
    assert outcomes[1].facts is None
    assert outcomes[1].error is DiscoveryError.COLLECTION_FAILED
    assert "private diagnostic details" not in repr(outcomes)


def test_missing_route_does_not_fall_back_or_stop_processing():
    outcomes = discover(
        [target(TargetKind.NETWORK), target()],
        {TargetKind.LINUX: FakeLinuxCollector()},
    )
    assert outcomes[0].error is DiscoveryError.MISSING_COLLECTOR
    assert outcomes[1].succeeded
    assert discover([target()], {})[0].error is DiscoveryError.MISSING_COLLECTOR


@pytest.mark.parametrize("kind", ["linux", "unsupported", None, []])
def test_invalid_target_kind_is_isolated(kind):
    outcomes = discover([target(kind), target()], registry())
    assert outcomes[0].error is DiscoveryError.INVALID_TARGET_KIND
    assert outcomes[1].succeeded


@pytest.mark.parametrize(
    "collectors",
    [{"linux": FakeLinuxCollector()},
     {TargetKind.NETWORK: FakeLinuxCollector()},
     {TargetKind.LINUX: object()},
     {TargetKind.LINUX: None}],
)
def test_invalid_registry_rejected_before_consuming_targets(collectors):
    def targets():
        pytest.fail("Invalid registry must be rejected before iteration")
        yield target()

    with pytest.raises(ValueError, match="registration"):
        discover(targets(), collectors)


def test_noncallable_collect_rejected():
    class InvalidCollector:
        kind = TargetKind.LINUX
        collect = None

    with pytest.raises(ValueError, match="registration"):
        discover([], {TargetKind.LINUX: InvalidCollector()})


@pytest.mark.parametrize("result", [None, {}, "facts", NetworkFacts("os", ())])
def test_invalid_collector_result_is_isolated(result):
    class InvalidCollector:
        kind = TargetKind.LINUX

        def collect(self, item):
            return result

    collectors = registry()
    collectors[TargetKind.LINUX] = InvalidCollector()
    outcomes = discover([target(), target(TargetKind.NETWORK)], collectors)
    assert outcomes[0].error is DiscoveryError.INVALID_RESULT
    assert outcomes[0].facts is None
    assert outcomes[1].succeeded


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
def test_process_control_exceptions_propagate(exception):
    class InterruptedCollector:
        kind = TargetKind.LINUX

        def collect(self, item):
            raise exception()

    with pytest.raises(exception):
        discover([target()], {TargetKind.LINUX: InterruptedCollector()})


def test_input_iteration_errors_propagate():
    def targets():
        yield target()
        raise RuntimeError("input iteration failed")

    with pytest.raises(RuntimeError, match="input iteration"):
        discover(targets(), registry())


@pytest.mark.parametrize(
    ("facts", "error"),
    [(None, None), (LinuxFacts("os", "kernel"), DiscoveryError.COLLECTION_FAILED),
     (NetworkFacts("os", ()), None), ({}, None), (None, "error")],
)
def test_outcome_rejects_inconsistent_state(facts, error):
    with pytest.raises(ValueError):
        DiscoveryOutcome(target(), facts=facts, error=error)
