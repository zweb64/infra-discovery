import pytest

from infra_discovery.models import Target, TargetKind


@pytest.mark.parametrize(
    ("kind", "expected_value"),
    [
        (TargetKind.NETWORK, "network"),
        (TargetKind.LINUX, "linux"),
    ],
)
def test_target_construction(kind: TargetKind, expected_value: str) -> None:
    target = Target(id="example-target", host="target.example.com", kind=kind)

    assert target.id == "example-target"
    assert target.host == "target.example.com"
    assert target.kind is kind
    assert target.kind.value == expected_value


def test_target_kind_members() -> None:
    assert TargetKind.__members__ == {
        "NETWORK": TargetKind.NETWORK,
        "LINUX": TargetKind.LINUX,
    }
