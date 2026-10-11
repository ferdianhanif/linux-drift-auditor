"""
Authentication & Password Policy Inspector
Parses /etc/login.defs, /etc/passwd, and /etc/shadow
Validates password expiration, rogue UID 0 accounts, and empty passwords.
"""

import os
import re
from typing import Dict, List
from src.models import Finding, Severity, Status


class AuthInspector:
    def __init__(self, baseline_config: dict, root_dir: str = "/"):
        self.baseline = baseline_config or {}
        self.root_dir = root_dir
        self.login_defs_path = os.path.join(root_dir, "etc", "login.defs")
        self.passwd_path = os.path.join(root_dir, "etc", "passwd")
        self.shadow_path = os.path.join(root_dir, "etc", "shadow")

    def _parse_login_defs(self) -> Dict[str, str]:
        defs: Dict[str, str] = {}
        if not os.path.exists(self.login_defs_path):
            return defs

        try:
            with open(self.login_defs_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        defs[parts[0].upper()] = parts[1]
        except Exception:
            pass
        return defs

    def inspect(self) -> List[Finding]:
        findings: List[Finding] = []
        defs = self._parse_login_defs()

        # Check 1: PASS_MAX_DAYS (CIS: <= 90)
        expected_max = int(self.baseline.get("pass_max_days", 90))
        actual_max_str = defs.get("PASS_MAX_DAYS", "99999")
        try:
            actual_max = int(actual_max_str)
        except ValueError:
            actual_max = 99999

        status_max = Status.PASS if actual_max <= expected_max else Status.FAIL
        findings.append(Finding(
            rule_id="AUTH-01",
            category="Password Policy",
            title="Maximum Password Age (PASS_MAX_DAYS)",
            severity=Severity.MEDIUM,
            status=status_max,
            expected=f"PASS_MAX_DAYS <= {expected_max}",
            actual=f"PASS_MAX_DAYS {actual_max}",
            description="Enforces regular password rotation to limit exposure window of compromised credentials.",
            remediation_cmd=f"sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   {expected_max}/' /etc/login.defs"
        ))

        # Check 2: PASS_MIN_DAYS (CIS: >= 7)
        expected_min = int(self.baseline.get("pass_min_days", 7))
        actual_min_str = defs.get("PASS_MIN_DAYS", "0")
        try:
            actual_min = int(actual_min_str)
        except ValueError:
            actual_min = 0

        status_min = Status.PASS if actual_min >= expected_min else Status.FAIL
        findings.append(Finding(
            rule_id="AUTH-02",
            category="Password Policy",
            title="Minimum Password Age (PASS_MIN_DAYS)",
            severity=Severity.MEDIUM,
            status=status_min,
            expected=f"PASS_MIN_DAYS >= {expected_min}",
            actual=f"PASS_MIN_DAYS {actual_min}",
            description="Prevents users from immediately cycling through password history to reuse old passwords.",
            remediation_cmd=f"sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   {expected_min}/' /etc/login.defs"
        ))

        # Check 3: Rogue UID 0 accounts in /etc/passwd
        rogue_root_accounts = []
        if os.path.exists(self.passwd_path):
            try:
                with open(self.passwd_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        fields = line.split(":")
                        if len(fields) >= 3:
                            username = fields[0]
                            uid = fields[2]
                            if uid == "0" and username != "root":
                                rogue_root_accounts.append(username)
            except Exception:
                pass

        status_uid0 = Status.PASS if not rogue_root_accounts else Status.FAIL
        actual_uid0 = "Only 'root' has UID 0" if not rogue_root_accounts else f"Rogue UID 0 accounts: {', '.join(rogue_root_accounts)}"
        findings.append(Finding(
            rule_id="AUTH-03",
            category="User Accounts",
            title="Unique Superuser UID 0 Verification",
            severity=Severity.CRITICAL,
            status=status_uid0,
            expected="UID 0 uniquely assigned to 'root'",
            actual=actual_uid0,
            description="Any non-root user with UID 0 possesses full unconstrained kernel privileges (backdoor pattern).",
            remediation_cmd="sudo userdel -f <username>" if rogue_root_accounts else None
        ))

        # Check 4: Empty password fields in /etc/shadow
        empty_password_accounts = []
        shadow_accessible = False
        if os.path.exists(self.shadow_path):
            try:
                with open(self.shadow_path, "r", encoding="utf-8", errors="ignore") as f:
                    shadow_accessible = True
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        fields = line.split(":")
                        if len(fields) >= 2:
                            username = fields[0]
                            passwd_hash = fields[1]
                            if passwd_hash == "" or passwd_hash.strip() == "":
                                empty_password_accounts.append(username)
            except PermissionError:
                shadow_accessible = False
            except Exception:
                pass

        if shadow_accessible:
            status_shadow = Status.PASS if not empty_password_accounts else Status.FAIL
            actual_shadow = "No empty password accounts" if not empty_password_accounts else f"Empty password on: {', '.join(empty_password_accounts)}"
            findings.append(Finding(
                rule_id="AUTH-04",
                category="User Accounts",
                title="Null/Empty Password Verification",
                severity=Severity.CRITICAL,
                status=status_shadow,
                expected="No user accounts with null password hash in /etc/shadow",
                actual=actual_shadow,
                description="Accounts with blank passwords permit unauthenticated interactive logins.",
                remediation_cmd="sudo passwd -l <username>" if empty_password_accounts else None
            ))
        else:
            findings.append(Finding(
                rule_id="AUTH-04",
                category="User Accounts",
                title="Null/Empty Password Verification",
                severity=Severity.INFO,
                status=Status.SKIPPED,
                expected="Access to /etc/shadow requires elevated privileges",
                actual="/etc/shadow unreadable (Run auditor with sudo for root check)",
                description="Audit skipped due to unprivileged process context.",
                remediation_cmd=None
            ))

        return findings
