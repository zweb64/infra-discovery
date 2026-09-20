from threading import Barrier, Event, Lock

import pytest

from infra_discovery.collectors import FakeLinuxCollector, FakeNetworkCollector
from infra_discovery.discovery import discover
from infra_discovery.models import DiscoveryError, LinuxFacts, Target, TargetKind


def target(identifier, kind=TargetKind.LINUX):
    return Target(identifier, "host.example.com", kind)


@pytest.mark.parametrize("workers", [2, 3])
def test_workers_overlap_and_are_bounded(workers):
    barrier = Barrier(workers)
    lock = Lock()
    active = 0
    peak = 0
    calls = []

    class CoordinatedCollector:
        kind = TargetKind.LINUX

        def collect(self, item):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
                calls.append(item.id)
            try:
                # Each wave requires all workers to be collecting simultaneously.
                # Timeout only prevents a broken implementation hanging the suite.
                barrier.wait(timeout=10)
                return LinuxFacts("offline", "kernel")
            finally:
                with lock:
                    active -= 1

    targets = [target(str(index)) for index in range(workers * 3)]
    outcomes = discover(
        iter(targets), {TargetKind.LINUX: CoordinatedCollector()},
        max_workers=workers,
    )
    assert all(outcome.succeeded for outcome in outcomes)
    assert len(outcomes) == len(targets)
    assert all(outcome.target is item for outcome, item in zip(outcomes, targets))
    assert sorted(calls) == sorted(item.id for item in targets)
    assert peak == workers
    assert active == 0


def test_out_of_order_failure_preserves_identity_and_complete_results():
    failed = Event()
    completed = []
    lock = Lock()

    class SelectiveCollector:
        kind = TargetKind.LINUX

        def collect(self, item):
            if item.id == "first":
                assert failed.wait(timeout=10)
            if item.id == "broken":
                with lock:
                    completed.append(item.id)
                failed.set()
                raise OSError("private diagnostic")
            if item.id == "invalid":
                return None
            with lock:
                completed.append(item.id)
            return LinuxFacts("offline", "kernel")

    repeated = target("repeated")
    targets = [target("first"), target("broken"), repeated,
               target("invalid"), target("network", TargetKind.NETWORK),
               target("bad-kind", "linux"), repeated]
    outcomes = discover(
        targets, {TargetKind.LINUX: SelectiveCollector()}, max_workers=2,
    )
    assert len(outcomes) == len(targets)
    assert all(outcome.target is item for outcome, item in zip(outcomes, targets))
    assert [outcome.error for outcome in outcomes] == [
        None, DiscoveryError.COLLECTION_FAILED, None,
        DiscoveryError.INVALID_RESULT, DiscoveryError.MISSING_COLLECTOR,
        DiscoveryError.INVALID_TARGET_KIND, None,
    ]
    assert completed.index("broken") < completed.index("first")
    assert completed.count("repeated") == 2
    assert "private diagnostic" not in repr(outcomes)


@pytest.mark.parametrize("workers", [0, -1, True, False, 1.0, 2.5, "2", None])
def test_invalid_worker_count_rejected_before_iteration(workers):
    def targets():
        pytest.fail("Invalid worker count must be rejected before iteration")
        yield target("unused")

    with pytest.raises(ValueError, match="max_workers"):
        discover(targets(), {}, max_workers=workers)
    with pytest.raises(ValueError, match="max_workers"):
        discover([], {}, max_workers=workers)


@pytest.mark.parametrize("workers", [1, 2, 8])
def test_empty_and_mixed_offline_discovery(workers):
    collectors = {TargetKind.LINUX: FakeLinuxCollector(),
                  TargetKind.NETWORK: FakeNetworkCollector()}
    assert discover([], collectors, max_workers=workers) == []
    targets = [target("linux"), target("network", TargetKind.NETWORK)]
    outcomes = discover(targets, collectors, max_workers=workers)
    assert len(outcomes) == 2
    assert all(outcome.succeeded for outcome in outcomes)
    assert all(outcome.target is item for outcome, item in zip(outcomes, targets))


def test_one_worker_preserves_sequential_calls():
    calls = []

    class RecordingCollector(FakeLinuxCollector):
        def collect(self, item):
            calls.append(item.id)
            return super().collect(item)

    outcomes = discover(
        [target(str(index)) for index in range(5)],
        {TargetKind.LINUX: RecordingCollector()}, max_workers=1,
    )
    assert calls == [str(index) for index in range(5)]
    assert all(outcome.succeeded for outcome in outcomes)
