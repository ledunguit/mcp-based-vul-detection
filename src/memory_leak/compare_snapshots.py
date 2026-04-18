from __future__ import annotations

import argparse
import json
from pathlib import Path

from .reporting import compare_result_snapshots


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare two memory leak result snapshots")
    parser.add_argument("baseline_snapshot")
    parser.add_argument("current_snapshot")
    parser.add_argument("--output", "-o", help="Write comparison JSON to this file")
    args = parser.parse_args()

    baseline = json.loads(Path(args.baseline_snapshot).read_text())
    current = json.loads(Path(args.current_snapshot).read_text())
    comparison = compare_result_snapshots(baseline, current)
    output = json.dumps(comparison, indent=2)
    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
