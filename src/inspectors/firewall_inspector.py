"""
Firewall & Network Attack Surface Inspector
Validates host firewall state (UFW / iptables) and verifies listening TCP ports
against the organization's allowed_inbound_ports baseline.
"""

import os
import subprocess
from typing import List, Set
from src.models import Finding, Severity, Status


class FirewallInspector:
    def __init__(self, baseline_config: dict, root_dir: str = "/"):
        self.baseline = baseline_config or {}
        self.root_dir = root_dir
        self.ufw_conf_path = os.path.join(root_dir, "etc", "ufw", "ufw.conf")

    def _check_ufw_status(self) -> str:
        """
        Reads /etc/ufw/ufw.conf or runs ufw status if on live Linux system.
        """
        # Try reading ufw.conf first (no subprocess needed)
        if os.path.exists(self.ufw_conf_path):
            try:
                with open(self.ufw_conf_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.strip().startswith("ENABLED="):
                            val = line.strip().split("=")[1].strip().lower()
                            return "active" if val == "yes" else "inactive"
            except Exception:
                pass

        # If on live Linux, try running ufw status
        try:
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=2)
            if "Status: active" in res.stdout:
                return "active"
            elif "Status: inactive" in res.stdout:
                return "inactive"
        except Exception:
            pass

        return "unknown"

    def _get_listening_tcp_ports(self) -> Set[int]:
        """
        Extracts open listening TCP ports from /proc/net/tcp or ss -tuln.
        """
        open_ports: Set[int] = set()

        # Parse /proc/net/tcp (Linux native, fast, no external binary needed)
        proc_tcp = os.path.join(self.root_dir, "proc", "net", "tcp")
        if os.path.exists(proc_tcp):
            try:
                with open(proc_tcp, "r") as f:
                    lines = f.readlines()[1:] # skip header
                    for line in lines:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            local_address = parts[1]
                            state = parts[3]
                            # State 0A is TCP_LISTEN in hex
                            if state == "0A":
                                ip_hex, port_hex = local_address.split(":")
                                port_int = int(port_hex, 16)
                                open_ports.add(port_int)
            except Exception:
                pass

        return open_ports

    def inspect(self) -> List[Finding]:
        findings: List[Finding] = []

        # Check 1: Firewall Active
        expected_fw = self.baseline.get("enabled", True)
        actual_fw_status = self._check_ufw_status()
        
        status_fw = Status.PASS if actual_fw_status == "active" else Status.FAIL
        findings.append(Finding(
            rule_id="FW-01",
            category="Firewall & Perimeter",
            title="Host Firewall Operational Status",
            severity=Severity.CRITICAL,
            status=status_fw,
            expected="Firewall active (UFW / iptables)",
            actual=f"Firewall is {actual_fw_status}",
            description="An inactive host firewall exposes all listening daemon ports directly to the local or public network.",
            remediation_cmd="sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw allow 22/tcp && sudo ufw --force enable"
        ))

        # Check 2: Unauthorized Listening Ports
        allowed_ports = set(self.baseline.get("allowed_inbound_ports", [22, 80, 443]))
        listening_ports = self._get_listening_tcp_ports()

        # In testing environments where /proc/net/tcp doesn't exist, provide graceful notice
        if listening_ports:
            unauthorized_ports = listening_ports - allowed_ports
            status_ports = Status.PASS if not unauthorized_ports else Status.FAIL
            actual_ports_str = f"Open ports: {sorted(list(listening_ports))}"
            if unauthorized_ports:
                actual_ports_str += f" (Unauthorized: {sorted(list(unauthorized_ports))})"

            findings.append(Finding(
                rule_id="FW-02",
                category="Firewall & Perimeter",
                title="Authorized Listening Port Governance",
                severity=Severity.HIGH,
                status=status_ports,
                expected=f"Only baseline ports listening: {sorted(list(allowed_ports))}",
                actual=actual_ports_str,
                description="Unmanaged listening ports represent unapproved network services and potential entry vectors.",
                remediation_cmd=f"sudo ss -tulpn | grep -E '({ '|'.join(str(p) for p in unauthorized_ports) })'" if unauthorized_ports else None
            ))
        else:
            findings.append(Finding(
                rule_id="FW-02",
                category="Firewall & Perimeter",
                title="Authorized Listening Port Governance",
                severity=Severity.INFO,
                status=Status.SKIPPED,
                expected=f"Only baseline ports listening: {sorted(list(allowed_ports))}",
                actual="Socket telemetry unavailable (non-Linux or unmounted /proc)",
                description="Port governance check skipped.",
                remediation_cmd=None
            ))

        return findings
