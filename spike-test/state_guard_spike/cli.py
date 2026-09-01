from __future__ import annotations

import argparse
import json

from .contract import load_contract
from .evaluation.compliance_audit import generate_compliance_report
from .evaluation.evaluator import run_frozen_evaluation


def main() -> None:
    parser = argparse.ArgumentParser(description="StateGuard controlled spike")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-contract")
    subparsers.add_parser("pre-evaluation-audit")
    subparsers.add_parser("evaluate")
    args = parser.parse_args()
    if args.command == "validate-contract":
        contract = load_contract()
        print(json.dumps({"status": "PASS", "experiment": contract["experiment"]}))
    elif args.command == "pre-evaluation-audit":
        print(json.dumps(generate_compliance_report()))
    elif args.command == "evaluate":
        print(json.dumps(run_frozen_evaluation()["overall"]))


if __name__ == "__main__":
    main()

