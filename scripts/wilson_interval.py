from __future__ import annotations

import argparse
import json

from on_device_agent_runtime_attestation.stats import wilson_interval


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--successes", type=int, required=True)
    parser.add_argument("--total", type=int, required=True)
    args = parser.parse_args()
    low, high = wilson_interval(args.successes, args.total)
    print(json.dumps({"lower": low, "upper": high}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
