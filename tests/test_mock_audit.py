"""
Unit & Simulation Test for Linux Drift Auditor
Creates a simulated unhardened Linux environment in a temporary root,
executes the audit engine, and asserts findings, score, and exit code.
"""

import os
import sys
import shutil
import tempfile

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.engine import DriftAuditorEngine
from src.models import Status, Severity


def create_simulated_linux_root(base_dir: str):
    # 1. Mock SSH config with critical drift
    ssh_dir = os.path.join(base_dir, "etc", "ssh")
    os.makedirs(ssh_dir, exist_ok=True)
    with open(os.path.join(ssh_dir, "sshd_config"), "w") as f:
        f.write("""
# Simulated Unhardened OpenSSH Config
Port 22
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 8
X11Forwarding yes
ClientAliveInterval 0
""")

    # 2. Mock login.defs with lax password expiration
    os.makedirs(os.path.join(base_dir, "etc"), exist_ok=True)
    with open(os.path.join(base_dir, "etc", "login.defs"), "w") as f:
        f.write("""
PASS_MAX_DAYS 99999
PASS_MIN_DAYS 0
PASS_WARN_AGE 7
""")

    # 3. Mock passwd with rogue UID 0 user
    with open(os.path.join(base_dir, "etc", "passwd"), "w") as f:
        f.write("""
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
hacker_backdoor:x:0:0:Hacked Account:/tmp:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
""")

    # 4. Mock UFW firewall inactive
    ufw_dir = os.path.join(base_dir, "etc", "ufw")
    os.makedirs(ufw_dir, exist_ok=True)
    with open(os.path.join(ufw_dir, "ufw.conf"), "w") as f:
        f.write("ENABLED=no\n")

    # 5. Mock world-writable file in /etc
    ww_file = os.path.join(base_dir, "etc", "insecure_app.conf")
    with open(ww_file, "w") as f:
        f.write("DB_PASSWORD=secret\n")
    # Set world writable permission (on platforms that support it)
    try:
        os.chmod(ww_file, 0o666)
    except Exception:
        pass


def run_test():
    temp_root = tempfile.mkdtemp(prefix="mock_linux_audit_")
    baseline_path = os.path.join(os.path.dirname(__file__), "..", "config", "baseline.yaml")

    try:
        print(f"[+] Creating simulated unhardened Linux root at: {temp_root}")
        create_simulated_linux_root(temp_root)

        engine = DriftAuditorEngine(baseline_path=baseline_path, root_dir=temp_root)
        summary = engine.run_audit()

        print("\n--- CLI REPORT OUTPUT ---")
        engine.print_cli_report(summary)

        # Assertions
        print("\n--- VERIFYING AUDIT ASSERTIONS ---")
        assert summary.failed_count > 0, "Audit should detect failures on unhardened root"
        print(f"✓ Total failures detected: {summary.failed_count}")

        # Check critical findings
        rule_ids = {f.rule_id: f for f in summary.findings}
        assert rule_ids["SSH-01"].status == Status.FAIL, "SSH-01 (PermitRootLogin) must FAIL"
        print("✓ Verified rule SSH-01 failed as expected")

        assert rule_ids["SSH-02"].status == Status.FAIL, "SSH-02 (PasswordAuthentication) must FAIL"
        print("✓ Verified rule SSH-02 failed as expected")

        assert rule_ids["AUTH-03"].status == Status.FAIL, "AUTH-03 (Rogue UID 0) must FAIL"
        print("✓ Verified rule AUTH-03 rogue superuser detected")

        assert rule_ids["FW-01"].status == Status.FAIL, "FW-01 (Firewall inactive) must FAIL"
        print("✓ Verified rule FW-01 inactive firewall detected")

        assert summary.exit_code == 2, f"Expected exit code 2 (Critical breach), got {summary.exit_code}"
        print("✓ Verified POSIX exit code is 2 (Critical Security Breach)")

        # Verify remediation script generation
        remediate_path = os.path.join(temp_root, "remediate.sh")
        engine.generate_remediation_script(summary, remediate_path)
        assert os.path.exists(remediate_path), "remediate.sh must be generated"
        with open(remediate_path, "r") as rf:
            remediate_content = rf.read()
            assert "PermitRootLogin no" in remediate_content
            assert "ufw --force enable" in remediate_content
        print("✓ Verified automated bash remediation script generated successfully")

        print("\n🎉 ALL TESTS PASSED SUCCESSFULLY!")

    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    run_test()
