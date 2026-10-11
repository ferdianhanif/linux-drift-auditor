#!/usr/bin/env python3
"""
Linux Configuration Drift & Security Baseline Gatekeeper
Main CLI Entry Point

Usage:
  python auditor.py [--baseline config/baseline.yaml] [--root /] [--remediate-out remediate.sh]
"""

import os
import sys
import argparse

# Ensure src module can be resolved
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.engine import DriftAuditorEngine
from src.reporter import HTMLReportGenerator


def main():
    parser = argparse.ArgumentParser(
        description="Linux Configuration Drift & Security Baseline Gatekeeper",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--baseline", "-b",
        default=os.path.join(os.path.dirname(__file__), "config", "baseline.yaml"),
        help="Path to baseline policy YAML file"
    )
    parser.add_argument(
        "--root", "-r",
        default="/",
        help="Root directory for system inspection (use custom path for mock/testing)"
    )
    parser.add_argument(
        "--remediate-out",
        default="remediate.sh",
        help="Path to generate automated bash remediation script"
    )
    parser.add_argument(
        "--html",
        default=os.path.join(os.path.dirname(__file__), "reports", "audit_report_latest.html"),
        help="Path to generate standalone HTML audit report"
    )
    parser.add_argument(
        "--telegram",
        action="store_true",
        help="Dispatch executive incident alert to Telegram bot"
    )

    args = parser.parse_args()

    try:
        engine = DriftAuditorEngine(baseline_path=args.baseline, root_dir=args.root)
        summary = engine.run_audit()

        # 1. Print visual CLI terminal output
        engine.print_cli_report(summary)

        # 2. Generate remediation script if there are failures
        if summary.failed_count > 0:
            engine.generate_remediation_script(summary, args.remediate_out)
            print(f"[+] Remediation script generated: {args.remediate_out}")

        # 3. Generate standalone HTML report
        out_html = None
        if args.html:
            report_gen = HTMLReportGenerator(summary)
            out_html = report_gen.generate(args.html)
            print(f"[+] Interactive HTML report generated: {out_html}")

        # 4. Dispatch Telegram incident notification if enabled
        if args.telegram:
            from src.telegram_dispatch import TelegramDispatcher
            dispatcher = TelegramDispatcher()
            dispatcher.send_alert(summary, html_report_path=out_html)

        # Exit with standard POSIX code
        sys.exit(summary.exit_code)

    except Exception as e:
        print(f"\n[!] Audit engine execution failed: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
