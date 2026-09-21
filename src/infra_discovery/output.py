"""Explicit versioned output contract, independent of Python object layouts."""

import json
from collections.abc import Sequence

from infra_discovery.models import DiscoveryOutcome, LinuxFacts, NetworkFacts


def result_document(outcomes: Sequence[DiscoveryOutcome]) -> dict:
    """Return one primitive-only result per outcome, preserving order."""
    results = []
    for outcome in outcomes:
        facts = None
        if isinstance(outcome.facts, LinuxFacts):
            facts = {"distribution": outcome.facts.distribution,
                     "kernel_release": outcome.facts.kernel_release}
        elif isinstance(outcome.facts, NetworkFacts):
            facts = {"platform": outcome.facts.platform,
                     "interfaces": list(outcome.facts.interfaces)}
        results.append({
            "target": {"id": outcome.target.id, "host": outcome.target.host,
                       "kind": outcome.target.kind.value},
            "status": "success" if outcome.succeeded else "failure",
            "facts": facts,
            "error": None if outcome.error is None else {
                "code": outcome.error.name, "message": outcome.error.value},
        })
    succeeded = sum(outcome.succeeded for outcome in outcomes)
    return {"schema_version": 1, "results": results,
            "summary": {"total": len(outcomes), "succeeded": succeeded,
                        "failed": len(outcomes) - succeeded}}


def format_json(outcomes: Sequence[DiscoveryOutcome]) -> str:
    """Emit deterministic JSON with terminal/encoding-safe string escaping."""
    return json.dumps(result_document(outcomes), ensure_ascii=True, allow_nan=False,
                      sort_keys=True, indent=2)


def format_human(outcomes: Sequence[DiscoveryOutcome]) -> str:
    """Use quoted strings so remote control characters cannot affect terminals."""
    document = result_document(outcomes)
    lines = []
    for result in document["results"]:
        target = result["target"]
        detail = (json.dumps(result["facts"], ensure_ascii=True, sort_keys=True)
                  if result["error"] is None else result["error"]["message"])
        lines.append(f'{result["status"].upper()} {json.dumps(target["id"])} '
                     f'({target["kind"]}, {json.dumps(target["host"])}) {detail}')
    summary = document["summary"]
    lines.append(f'{summary["total"]} targets: {summary["succeeded"]} succeeded, '
                 f'{summary["failed"]} failed.')
    return "\n".join(lines)
