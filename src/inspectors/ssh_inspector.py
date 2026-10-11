"""
SSH Configuration Inspector
Parses /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf
Detects deviations against CIS Level 1 SSH baseline specifications.
"""

import os
import glob
import re
from typing import Dict, List, Optional
from src.models import Finding, Severity, Status


class SSHInspector:
    def __init__(self, baseline_config: dict, root_dir: str = "/"):
        """
        :param baseline_config: 'ssh' section from baseline.yaml
        :param root_dir: Root directory for testing/mocking (defaults to '/')
        """
        self.baseline = baseline_config or {}
        self.root_dir = root_dir
        self.sshd_config_path = os.path.join(root_dir, "etc", "ssh", "sshd_config")
        self.sshd_config_d = os.path.join(root_dir, "etc", "ssh", "sshd_config.d")

    def _parse_sshd_files(self) -> Dict[str, str]:
        """
        Parses sshd_config and included files, respecting order of precedence.
        OpenSSH uses first-match-wins for directives.
        """
        directives: Dict[str, str] = {}
        files_to_read = []

        # If Include directive is present in main config or drop-in directory exists
        if os.path.exists(self.sshd_config_path):
            files_to_read.append(self.sshd_config_path)

        if os.path.isdir(self.sshd_config_d):
            drop_ins = sorted(glob.glob(os.path.join(self.sshd_config_d, "*.conf")))
            # In modern OpenSSH on Ubuntu/Debian, drop-ins are often evaluated first via Include
            files_to_read = drop_ins + files_to_read

        for file_path in files_to_read:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        # Ignore comments and empty lines
                        if not line or line.startswith("#"):
                            continue

                        # Match key-value or key=value
                        parts = re.split(r"[\s=]+", line, maxsplit=1)
                        if len(parts) == 2:
                            key = parts[0].strip().lower()
                            val = parts[1].strip()
                            # First occurrence takes precedence in sshd
                            if key not in directives:
                                directives[key] = val
            except Exception as e:
                # Log or handle read permissions gracefully
                pass

        return directives

    def inspect(self) -> List[Finding]:
        findings: List[Finding] = []
        parsed = self._parse_sshd_files()

        # Check 1: PermitRootLogin (CIS: no)
        expected_root = str(self.baseline.get("permit_root_login", "no")).lower()
        actual_root = parsed.get("permitrootlogin", "prohibit-password").lower() # default on modern ubuntu is prohibit-password
        
        status_root = Status.PASS if actual_root == expected_root else Status.FAIL
        findings.append(Finding(
            rule_id="SSH-01",
            category="SSH Hardening",
            title="PermitRootLogin Policy",
            severity=Severity.CRITICAL,
            status=status_root,
            expected=f"PermitRootLogin {expected_root}",
            actual=f"PermitRootLogin {actual_root}",
            description="Root login directly via SSH exposes the system to elevated brute-force compromise.",
            remediation_cmd="sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd"
        ))

        # Check 2: PasswordAuthentication (CIS: no / key-based)
        expected_pass_auth = str(self.baseline.get("password_authentication", "no")).lower()
        actual_pass_auth = parsed.get("passwordauthentication", "yes").lower() # default OpenSSH is yes

        status_pass_auth = Status.PASS if actual_pass_auth == expected_pass_auth else Status.FAIL
        findings.append(Finding(
            rule_id="SSH-02",
            category="SSH Hardening",
            title="PasswordAuthentication Policy",
            severity=Severity.HIGH,
            status=status_pass_auth,
            expected=f"PasswordAuthentication {expected_pass_auth}",
            actual=f"PasswordAuthentication {actual_pass_auth}",
            description="Password-based authentication permits credential guessing. Key-based authentication is mandatory.",
            remediation_cmd="sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd"
        ))

        # Check 3: MaxAuthTries (CIS: <= 4)
        expected_tries = int(self.baseline.get("max_auth_tries", 4))
        actual_tries_str = parsed.get("maxauthtries", "6") # default is 6
        try:
            actual_tries = int(actual_tries_str)
        except ValueError:
            actual_tries = 6

        status_tries = Status.PASS if actual_tries <= expected_tries else Status.FAIL
        findings.append(Finding(
            rule_id="SSH-03",
            category="SSH Hardening",
            title="MaxAuthTries Threshold",
            severity=Severity.MEDIUM,
            status=status_tries,
            expected=f"MaxAuthTries <= {expected_tries}",
            actual=f"MaxAuthTries {actual_tries}",
            description="Limits number of failed authentication attempts per connection to mitigate rapid brute-forcing.",
            remediation_cmd=f"echo 'MaxAuthTries {expected_tries}' | sudo tee -a /etc/ssh/sshd_config.d/hardening.conf && sudo systemctl reload sshd"
        ))

        # Check 4: X11Forwarding (CIS: no)
        expected_x11 = str(self.baseline.get("x11_forwarding", "no")).lower()
        actual_x11 = parsed.get("x11forwarding", "yes").lower() # many distros enable this

        status_x11 = Status.PASS if actual_x11 == expected_x11 else Status.FAIL
        findings.append(Finding(
            rule_id="SSH-04",
            category="SSH Hardening",
            title="X11Forwarding Disabled",
            severity=Severity.LOW,
            status=status_x11,
            expected=f"X11Forwarding {expected_x11}",
            actual=f"X11Forwarding {actual_x11}",
            description="Disabling X11 forwarding reduces server attack surface on headless production systems.",
            remediation_cmd="sudo sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config && sudo systemctl reload sshd"
        ))

        # Check 5: ClientAliveInterval (CIS: 300 or > 0)
        expected_interval = int(self.baseline.get("client_alive_interval", 300))
        actual_interval_str = parsed.get("clientaliveinterval", "0")
        try:
            actual_interval = int(actual_interval_str)
        except ValueError:
            actual_interval = 0

        status_interval = Status.PASS if actual_interval > 0 and actual_interval <= expected_interval else Status.FAIL
        findings.append(Finding(
            rule_id="SSH-05",
            category="SSH Hardening",
            title="ClientAliveInterval (Idle Session Timeout)",
            severity=Severity.MEDIUM,
            status=status_interval,
            expected=f"ClientAliveInterval 1-{expected_interval}",
            actual=f"ClientAliveInterval {actual_interval}",
            description="Terminates abandoned or stale SSH sessions automatically after inactive periods.",
            remediation_cmd=f"echo 'ClientAliveInterval {expected_interval}' | sudo tee -a /etc/ssh/sshd_config.d/hardening.conf && sudo systemctl reload sshd"
        ))

        return findings
