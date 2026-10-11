"""
Master Audit Engine for Linux Configuration Drift & Security Baseline Gatekeeper.
Coordinates all inspector modules, evaluates baseline policies, calculates compliance score,
and emits colorized CLI summaries and remediation scripts.
"""

import os
import sys
import time
import socket
import platform
import yaml
from typing import Optional
from src.models import Finding, Severity, Status, AuditSummary
from src.inspectors.ssh_inspector import SSHInspector
from src.inspectors.auth_inspector import AuthInspector
from src.inspectors.firewall_inspector import FirewallInspector
from src.inspectors.filesystem_inspector import FilesystemInspector


# ANSI Color Codes for Terminal Output
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


class DriftAuditorEngine:
    def __init__(self, baseline_path: str, root_dir: str = "/"):
        self.baseline_path = baseline_path
        self.root_dir = root_dir
        self.config = self._load_baseline()

    def _load_baseline(self) -> dict:
        if not os.path.exists(self.baseline_path):
            raise FileNotFoundError(f"Baseline policy file not found at: {self.baseline_path}")

        with open(self.baseline_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def run_audit(self) -> AuditSummary:
        start_time = time.time()
        hostname = socket.gethostname()
        os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

        summary = AuditSummary(
            hostname=hostname,
            os_info=os_info
        )

        # 1. Run SSH Inspector
        ssh_insp = SSHInspector(self.config.get("ssh", {}), root_dir=self.root_dir)
        summary.findings.extend(ssh_insp.inspect())

        # 2. Run Auth Inspector
        auth_insp = AuthInspector(self.config.get("auth", {}), root_dir=self.root_dir)
        summary.findings.extend(auth_insp.inspect())

        # 3. Run Firewall Inspector
        fw_insp = FirewallInspector(self.config.get("firewall", {}), root_dir=self.root_dir)
        summary.findings.extend(fw_insp.inspect())

        # 4. Run Filesystem Inspector
        fs_insp = FilesystemInspector(self.config.get("filesystem", {}), root_dir=self.root_dir)
        summary.findings.extend(fs_insp.inspect())

        summary.execution_duration_sec = round(time.time() - start_time, 3)
        return summary

    def print_cli_report(self, summary: AuditSummary) -> None:
        """
        Emits an executive, color-coded terminal report with status badges.
        """
        if hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 75}{Colors.RESET}")
        print(f"{Colors.BOLD} [!] LINUX CONFIGURATION DRIFT & SECURITY BASELINE GATEKEEPER{Colors.RESET}")
        print(f"{Colors.DIM} Host: {summary.hostname} | OS: {summary.os_info} | Time: {summary.timestamp.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 75}{Colors.RESET}\n")

        # Category group findings
        current_cat = None
        for f in summary.findings:
            if f.category != current_cat:
                current_cat = f.category
                print(f"\n{Colors.BOLD}{Colors.BLUE}[+] {current_cat.upper()}{Colors.RESET}")
                print(f"{Colors.DIM}{'-' * 50}{Colors.RESET}")

            # Badge color
            if f.status == Status.PASS:
                status_badge = f"{Colors.GREEN}[ PASS ]{Colors.RESET}"
            elif f.status == Status.FAIL:
                sev_color = Colors.RED if f.severity in [Severity.CRITICAL, Severity.HIGH] else Colors.YELLOW
                status_badge = f"{sev_color}[ {f.severity.value} ]{Colors.RESET}"
            elif f.status == Status.SKIPPED:
                status_badge = f"{Colors.DIM}[ SKIP ]{Colors.RESET}"
            else:
                status_badge = f"{Colors.YELLOW}[ WARN ]{Colors.RESET}"

            print(f"  {status_badge} {Colors.BOLD}{f.rule_id}{Colors.RESET}: {f.title}")
            if f.is_failure:
                print(f"         {Colors.DIM}Expected:{Colors.RESET} {f.expected}")
                print(f"         {Colors.RED}Actual:  {Colors.RESET} {f.actual}")
                if f.remediation_cmd:
                    print(f"         {Colors.CYAN}Fix:     {Colors.DIM}{f.remediation_cmd}{Colors.RESET}")

        # Final Executive Score Banner
        print(f"\n{Colors.CYAN}{'=' * 75}{Colors.RESET}")
        score = summary.compliance_score
        score_color = Colors.GREEN if score >= 85 else (Colors.YELLOW if score >= 60 else Colors.RED)

        print(f" {Colors.BOLD}EXECUTIVE SUMMARY & COMPLIANCE SCORE:{Colors.RESET}")
        print(f" - Compliance Score: {score_color}{Colors.BOLD}{score} / 100.0{Colors.RESET} ({score_color}{summary.risk_level}{Colors.RESET})")
        print(f" - Rules Evaluated:  {summary.total_rules} ({summary.passed_count} Passed, {summary.failed_count} Failed)")
        print(f" - Severity Breakdown: {Colors.RED}{summary.critical_count} Critical{Colors.RESET}, {Colors.RED}{summary.high_count} High{Colors.RESET}, {Colors.YELLOW}{summary.medium_count} Medium{Colors.RESET}, {Colors.BLUE}{summary.low_count} Low{Colors.RESET}")
        print(f" - Execution Time:   {summary.execution_duration_sec}s")
        print(f" - Exit Code:        {summary.exit_code} (0=Clean, 1=Minor, 2=Critical)")
        print(f"{Colors.CYAN}{'=' * 75}{Colors.RESET}\n")

    def generate_remediation_script(self, summary: AuditSummary, output_path: str) -> None:
        """
        Generates an executable bash remediation script containing exact idempotent fix commands.
        """
        fixes = [f for f in summary.findings if f.is_failure and f.remediation_cmd]
        if not fixes:
            return

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env bash\n")
            f.write("# ====================================================================\n")
            f.write(f"# AUTOMATED REMEDIATION SCRIPT - {summary.hostname}\n")
            f.write(f"# Generated: {summary.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Compliance Score: {summary.compliance_score} / 100 ({summary.risk_level})\n")
            f.write("# REVIEW BEFORE RUNNING IN PRODUCTION\n")
            f.write("# ====================================================================\n\n")
            f.write("set -euo pipefail\n\n")

            for fix in fixes:
                f.write(f"# [{fix.rule_id}] {fix.title} ({fix.severity.value})\n")
                f.write(f"# Issue: {fix.actual}\n")
                f.write(f"echo \"[+] Remediating {fix.rule_id}: {fix.title}...\"\n")
                f.write(f"{fix.remediation_cmd}\n\n")

            f.write("echo \"[OK] Remediation completed. Re-running drift audit...\"\n")
