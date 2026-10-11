"""
Telegram Incident Dispatcher for Linux Drift Auditor.
Sends real-time executive incident triage alerts and attaches standalone HTML reports
via official Telegram Bot API (urllib native, zero third-party dependencies).
"""

import os
import json
import urllib.request
import urllib.error
from typing import Optional
from src.models import AuditSummary, Severity, Status


class TelegramDispatcher:
    def __init__(self, bot_token: Optional[str] = None, chat_id: Optional[str] = None):
        self.bot_token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID")

    @property
    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def format_alert_message(self, summary: AuditSummary) -> str:
        score = summary.compliance_score
        status_tag = "[CRITICAL ALERT]" if summary.critical_count > 0 or score < 60 else ("[WARNING]" if score < 85 else "[OK]")
        
        lines = [
            f"*{status_tag} LINUX DRIFT AUDIT NOTIFICATION*",
            f"*Host:* `{summary.hostname}`",
            f"*OS:* `{summary.os_info}`",
            f"*Time:* `{summary.timestamp.strftime('%Y-%m-%d %H:%M:%S')}`",
            "",
            f"*Compliance Score:* *{score} / 100.0* ({summary.risk_level})",
            f"- Passed: {summary.passed_count} / {summary.total_rules}",
            f"- Failures: {summary.failed_count} (Critical: {summary.critical_count}, High: {summary.high_count}, Med: {summary.medium_count})",
            f"- Exit Code: `{summary.exit_code}`",
            ""
        ]

        # Top critical/high findings
        critical_high = [f for f in summary.findings if f.is_failure and f.severity in [Severity.CRITICAL, Severity.HIGH]]
        if critical_high:
            lines.append("*Top Security Drift Breaches:*")
            for f in critical_high[:5]:
                lines.append(f"- *[{f.rule_id}]* {f.title}: `{f.actual}`")
            lines.append("")

        lines.append("Full interactive audit report and remediation script generated on host.")
        return "\n".join(lines)

    def send_alert(self, summary: AuditSummary, html_report_path: Optional[str] = None) -> bool:
        if not self.is_configured:
            print("[INFO] Telegram dispatch skipped (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set).")
            return False

        message_text = self.format_alert_message(summary)
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

        payload = {
            "chat_id": self.chat_id,
            "text": message_text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    print("[OK] Executive incident alert dispatched to Telegram.")

            # If html report is available, send as document
            if html_report_path and os.path.exists(html_report_path):
                self._send_document(html_report_path, caption=f"Audit Report - {summary.hostname} ({summary.compliance_score}%)")

            return True

        except Exception as e:
            print(f"[ERROR] Telegram notification failed: {e}")
            return False

    def _send_document(self, file_path: str, caption: str = "") -> bool:
        # Multipart upload using native urllib
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        url = f"https://api.telegram.org/bot{self.bot_token}/sendDocument"

        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            file_data = f.read()

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="chat_id"\r\n\r\n'
            f"{self.chat_id}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="caption"\r\n\r\n'
            f"{caption}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'
            f"Content-Type: text/html\r\n\r\n"
        ).encode("utf-8") + file_data + f"\r\n--{boundary}--\r\n".encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    print("[OK] HTML report document attached and sent to Telegram.")
                    return True
        except Exception as e:
            print(f"[ERROR] Sending document to Telegram failed: {e}")
        return False
