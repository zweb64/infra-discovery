"""Public command-line entry point for infrastructure discovery."""

import argparse
from pathlib import Path
import sys

from infra_discovery.configuration import ConfigurationError, build_collectors, load_configuration
from infra_discovery.discovery import discover
from infra_discovery.inventory import InventoryError, load_inventory
from infra_discovery.output import format_human, format_json


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # Never echo mistakenly supplied secret flags and their values.
        if message.startswith("unrecognized arguments:"):
            message = "unrecognized arguments; use --help for supported options (secrets are prompted)"
        super().error(message)


def _workers(value: str) -> int:
    try:
        workers = int(value)
        if workers > 0:
            return workers
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("worker count must be a positive integer")


def main(argv: list[str] | None = None) -> int:
    """Run discovery; return 0/1/2/130 for success/failures/input/interruption."""
    parser = _Parser(prog="infra-discovery", description="Discover Linux and network targets over SSH.")
    parser.add_argument("inventory", type=Path, help="UTF-8 JSON inventory path")
    parser.add_argument("--config", type=Path, help="non-secret JSON connection configuration")
    parser.add_argument("--max-workers", type=_workers, default=1, help="positive worker count (default: 1)")
    parser.add_argument("--json", action="store_true", help="emit versioned JSON to stdout")
    try:
        args = parser.parse_args(argv)
        try:
            targets = load_inventory(args.inventory)
        except (OSError, ValueError) as exc:
            message = str(exc) if isinstance(exc, InventoryError) else "Cannot read inventory; check its path and permissions."
            raise ConfigurationError(message) from None
        config = load_configuration(args.config, targets)
        collectors = build_collectors(config)
        outcomes = discover(targets, collectors, max_workers=args.max_workers)
        try:
            print(format_json(outcomes) if args.json else format_human(outcomes))
            sys.stdout.flush()
        except OSError:
            # Close even if flushing fails again, preventing a shutdown retry.
            try:
                sys.stdout.close()
            except OSError:
                pass
            raise
        return 1 if any(not outcome.succeeded for outcome in outcomes) else 0
    except ConfigurationError as exc:
        print(f"infra-discovery: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("infra-discovery: interrupted.", file=sys.stderr)
        return 130
    except OSError:
        print("infra-discovery: I/O failed; check file access and output destination.", file=sys.stderr)
        return 2
