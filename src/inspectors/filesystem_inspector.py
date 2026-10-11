"""
Filesystem & Permissions Inspector
Audits world-writable files in critical directories (/etc)
and scans for dangerous SUID/SGID binaries in temporary paths (/tmp, /dev/shm).
"""

import os
import stat
from typing import List
from src.models import Finding, Severity, Status


class FilesystemInspector:
    def __init__(self, baseline_config: dict, root_dir: str = "/"):
        self.baseline = baseline_config or {}
        self.root_dir = root_dir

    def _find_world_writable_files(self, target_dir_rel: str) -> List[str]:
        target_path = os.path.join(self.root_dir, target_dir_rel.lstrip("/\\"))
        world_writable = []
        if not os.path.isdir(target_path):
            return world_writable

        for root, dirs, files in os.walk(target_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    # Don't follow symlinks
                    st = os.lstat(fpath)
                    if stat.S_ISREG(st.st_mode):
                        # Check world writable bit (other write)
                        if st.st_mode & stat.S_IWOTH:
                            world_writable.append(fpath)
                except Exception:
                    pass
        return world_writable

    def _find_risky_suid_binaries(self) -> List[str]:
        """
        Scans temporary directories (/tmp, /var/tmp, /dev/shm) for SUID binaries.
        Legitimate systems never store SUID executables in temp directories.
        """
        risky_dirs = ["tmp", "var/tmp", "dev/shm"]
        found_suid = []

        for r_dir in risky_dirs:
            full_dir = os.path.join(self.root_dir, r_dir)
            if not os.path.isdir(full_dir):
                continue

            for root, dirs, files in os.walk(full_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        st = os.lstat(fpath)
                        if stat.S_ISREG(st.st_mode):
                            # SUID bit is 0o4000
                            if st.st_mode & stat.S_ISUID:
                                found_suid.append(fpath)
                    except Exception:
                        pass
        return found_suid

    def inspect(self) -> List[Finding]:
        findings: List[Finding] = []

        # Check 1: World-writable files in /etc
        dirs_to_check = self.baseline.get("check_world_writable_dirs", ["/etc"])
        all_ww_files = []
        for d in dirs_to_check:
            all_ww_files.extend(self._find_world_writable_files(d))

        status_ww = Status.PASS if not all_ww_files else Status.FAIL
        actual_ww_str = "No world-writable files detected in /etc" if not all_ww_files else f"{len(all_ww_files)} world-writable files found (e.g. {all_ww_files[0]})"
        findings.append(Finding(
            rule_id="FS-01",
            category="Filesystem Integrity",
            title="World-Writable System Configuration Files",
            severity=Severity.HIGH,
            status=status_ww,
            expected="0 world-writable files in critical system configuration paths",
            actual=actual_ww_str,
            description="World-writable files in /etc allow unprivileged local users or compromised processes to modify system configuration.",
            remediation_cmd="sudo chmod o-w <file>" if all_ww_files else None
        ))

        # Check 2: Unauthorized SUID binaries in temporary locations
        risky_suids = self._find_risky_suid_binaries()
        status_suid = Status.PASS if not risky_suids else Status.FAIL
        actual_suid_str = "No SUID binaries detected in /tmp or /dev/shm" if not risky_suids else f"Rogue SUID binaries detected: {', '.join(risky_suids)}"

        findings.append(Finding(
            rule_id="FS-02",
            category="Filesystem Integrity",
            title="Temporary Directory SUID Execution Anomaly",
            severity=Severity.CRITICAL,
            status=status_suid,
            expected="Zero SUID binaries located in /tmp, /var/tmp, or /dev/shm",
            actual=actual_suid_str,
            description="SUID binaries in temporary directories indicate local privilege escalation exploitation attempts.",
            remediation_cmd=f"sudo chmod u-s {risky_suids[0]}" if risky_suids else None
        ))

        return findings
