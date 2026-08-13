"""CLI entry point and composition root.

This is the only place WaiverStore and LLMSummarizer get constructed —
everything else receives them as constructor/method arguments.
"""

import argparse
import sys

from llm_summary import LLMSummarizer
from policy import PolicyEngine
from scanner import TrivyScanner
from waiver_store import WaiverStore
from models import Waiver


def cmd_scan(args: argparse.Namespace, waiver_store: WaiverStore) -> int:
    scanner = TrivyScanner()
    if args.sample:
        scan_result = scanner.load_sample(args.sample)
    elif args.image:
        scan_result = scanner.load_sample(args.image)
    else:
        print("error: provide a Trivy JSON path or --sample PATH", file=sys.stderr)
        return 2

    active_waivers = waiver_store.get_active_waivers(scan_result.image)
    decision = PolicyEngine().evaluate(scan_result, active_waivers)

    if not args.no_summary:
        decision.summary = LLMSummarizer().summarize(decision)

    waiver_store.log_decision(decision)
    _print_decision(decision)

    if decision.overall_verdict.value == "BLOCK":
        return 1
    return 0


def cmd_add_waiver(args: argparse.Namespace, waiver_store: WaiverStore) -> int:
    waiver = Waiver.create(
        image=args.image,
        cve_id=args.cve_id,
        reason=args.reason,
        approved_by=args.approved_by,
        days=args.days,
    )
    waiver_id = waiver_store.add_waiver(waiver)
    print(f"Added waiver #{waiver_id} for {args.cve_id} on {args.image}, "
          f"expires {waiver.expires_at.date()}")
    return 0


def cmd_list_waivers(args: argparse.Namespace, waiver_store: WaiverStore) -> int:
    waivers = waiver_store.get_all_waivers(args.image)
    if not waivers:
        print(f"No waivers found for {args.image}")
        return 0

    for waiver in waivers:
        if waiver.is_active():
            active = "active"
        else:
            active = "expired"
        print(
            f"#{waiver.id} {waiver.cve_id} [{active}] "
            f"approved_by={waiver.approved_by} expires={waiver.expires_at.date()} "
            f"reason=\"{waiver.reason}\""
        )
    return 0


def cmd_history(args: argparse.Namespace, waiver_store: WaiverStore) -> int:
    history = waiver_store.get_decision_history(args.image)
    if not history:
        print(f"No decision history found for {args.image}")
        return 0

    for entry in history:
        print(
            f"{entry['decided_at']} {entry['image']}:{entry['image_tag']} "
            f"-> {entry['verdict']}  {entry['summary']}"
        )
    return 0


def _print_decision(decision) -> None:
    print(f"\nImage: {decision.image}:{decision.image_tag}")
    print(f"Verdict: {decision.overall_verdict.value}\n")

    for finding in decision.findings:
        vuln = finding.vulnerability
        print(
            f"  [{finding.verdict.value}] {vuln.cve_id} ({vuln.severity.value}) "
            f"{vuln.package_name} {vuln.installed_version}"
        )
        print(f"    reason: {finding.reason}")

    if decision.summary:
        print(f"\nSummary:\n{decision.summary}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="docker-gatekeeper-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan an image against policy")
    scan_parser.add_argument(
        "image", nargs="?", help="Path to a real Trivy JSON scan file"
    )
    scan_parser.add_argument("--sample", help="Path to sample scan data (demo mode)")
    scan_parser.add_argument(
        "--no-summary", action="store_true", help="Skip the LLM summary"
    )

    add_waiver_parser = subparsers.add_parser("add-waiver", help="Add a waiver")
    add_waiver_parser.add_argument("image")
    add_waiver_parser.add_argument("cve_id")
    add_waiver_parser.add_argument("--reason", required=True)
    add_waiver_parser.add_argument("--approved-by", required=True)
    add_waiver_parser.add_argument("--days", type=int, default=30)

    list_waivers_parser = subparsers.add_parser(
        "list-waivers", help="List waivers for an image"
    )
    list_waivers_parser.add_argument("image")

    history_parser = subparsers.add_parser(
        "history", help="Show decision history for an image"
    )
    history_parser.add_argument("image")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    waiver_store = WaiverStore()

    # Explicit dispatch: easier to trace than a function stored on args.
    if args.command == "scan":
        return cmd_scan(args, waiver_store)
    elif args.command == "add-waiver":
        return cmd_add_waiver(args, waiver_store)
    elif args.command == "list-waivers":
        return cmd_list_waivers(args, waiver_store)
    elif args.command == "history":
        return cmd_history(args, waiver_store)


if __name__ == "__main__":
    sys.exit(main())
