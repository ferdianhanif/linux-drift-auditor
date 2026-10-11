"""
Interactive Single-File HTML Audit Report Generator.
Generates an executive, zero-dependency, standalone HTML report with dynamic scoring gauge,
severity badges, and copyable remediation commands.
Works completely offline (air-gapped compatible).
"""

import os
from datetime import datetime
from src.models import AuditSummary, Status, Severity


class HTMLReportGenerator:
    def __init__(self, summary: AuditSummary):
        self.summary = summary

    def generate(self, output_file: str) -> str:
        score = self.summary.compliance_score
        risk_level = self.summary.risk_level

        # Determine theme color based on score
        if score >= 85:
            score_color = "#10B981" # Green
            score_bg = "#ECFDF5"
        elif score >= 60:
            score_color = "#F59E0B" # Yellow/Amber
            score_bg = "#FFFBEB"
        else:
            score_color = "#EF4444" # Red
            score_bg = "#FEF2F2"

        # Build table rows
        table_rows = []
        for f in self.summary.findings:
            if f.status == Status.PASS:
                badge_bg = "#DEF7EC"
                badge_text = "#03543F"
                badge_label = "PASS"
            elif f.status == Status.FAIL:
                if f.severity == Severity.CRITICAL:
                    badge_bg = "#FDE8E8"
                    badge_text = "#9B1C1C"
                    badge_label = "CRITICAL"
                elif f.severity == Severity.HIGH:
                    badge_bg = "#FEECDC"
                    badge_text = "#9A3412"
                    badge_label = "HIGH"
                elif f.severity == Severity.MEDIUM:
                    badge_bg = "#FEF08A"
                    badge_text = "#854D0E"
                    badge_label = "MEDIUM"
                else:
                    badge_bg = "#E1EFFE"
                    badge_text = "#1E429F"
                    badge_label = "LOW"
            elif f.status == Status.SKIPPED:
                badge_bg = "#F3F4F6"
                badge_text = "#4B5563"
                badge_label = "SKIPPED"
            else:
                badge_bg = "#FEF08A"
                badge_text = "#854D0E"
                badge_label = "WARN"

            fix_html = f"<code>{f.remediation_cmd}</code>" if f.remediation_cmd else "<span class='text-muted'>N/A</span>"
            desc_html = f"<div class='rule-desc'>{f.description}</div>"

            row = f"""
            <tr class="status-{f.status.value.lower()} sev-{f.severity.value.lower()}">
                <td><span class="badge" style="background:{badge_bg}; color:{badge_text};">{badge_label}</span></td>
                <td><strong>{f.rule_id}</strong></td>
                <td>{f.category}</td>
                <td>
                    <div class="rule-title">{f.title}</div>
                    {desc_html}
                </td>
                <td><span class="actual-val {'val-fail' if f.is_failure else 'val-pass'}">{f.actual}</span></td>
                <td><span class="expected-val">{f.expected}</span></td>
                <td>{fix_html}</td>
            </tr>
            """
            table_rows.append(row)

        all_rows_html = "\n".join(table_rows)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Drift Audit Report - {self.summary.hostname}</title>
    <style>
        :root {{
            --primary: #2563EB;
            --slate-900: #0F172A;
            --slate-800: #1E293B;
            --slate-700: #334155;
            --slate-100: #F1F5F9;
            --slate-50: #F8FAFC;
            --border: #E2E8F0;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--slate-50);
            color: var(--slate-800);
            line-height: 1.5;
            padding: 30px 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        /* Header */
        .header {{
            background: #FFFFFF;
            border-radius: 12px;
            padding: 24px 30px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .header-title h1 {{ font-size: 20px; color: var(--slate-900); font-weight: 700; margin-bottom: 4px; }}
        .header-meta {{ font-size: 13px; color: var(--slate-700); }}
        
        /* Score Card */
        .score-pill {{
            text-align: right;
            padding: 12px 20px;
            border-radius: 10px;
            background: {score_bg};
            border: 1px solid {score_color};
        }}
        .score-val {{ font-size: 28px; font-weight: 800; color: {score_color}; line-height: 1; }}
        .score-label {{ font-size: 12px; font-weight: 700; text-transform: uppercase; color: {score_color}; margin-top: 4px; }}

        /* Stat Cards */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: #FFFFFF;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.04);
        }}
        .stat-num {{ font-size: 24px; font-weight: 700; color: var(--slate-900); }}
        .stat-name {{ font-size: 12px; color: var(--slate-700); text-transform: uppercase; font-weight: 600; }}
        .stat-crit {{ color: #EF4444; }}
        .stat-high {{ color: #F97316; }}
        .stat-med {{ color: #EAB308; }}
        .stat-pass {{ color: #10B981; }}

        /* Table Card */
        .table-card {{
            background: #FFFFFF;
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .table-header {{
            padding: 16px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .table-title {{ font-size: 16px; font-weight: 700; color: var(--slate-900); }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }}
        th {{
            background: var(--slate-100);
            padding: 12px 16px;
            font-weight: 600;
            color: var(--slate-700);
            border-bottom: 1px solid var(--border);
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        tr:hover td {{ background: #FAFAFA; }}
        
        /* Badges & Elements */
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        .rule-title {{ font-weight: 600; color: var(--slate-900); }}
        .rule-desc {{ font-size: 11.5px; color: var(--slate-700); margin-top: 3px; }}
        .actual-val {{ font-family: monospace; font-size: 12px; font-weight: 600; }}
        .expected-val {{ font-family: monospace; font-size: 12px; color: #059669; }}
        .val-fail {{ color: #DC2626; }}
        .val-pass {{ color: #059669; }}
        code {{
            background: var(--slate-100);
            padding: 4px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 11px;
            color: #C026D3;
            display: block;
            max-width: 280px;
            word-break: break-all;
        }}
        .text-muted {{ color: #94A3B8; font-size: 11px; }}

        /* Footer */
        .footer {{
            margin-top: 24px;
            text-align: center;
            font-size: 12px;
            color: #64748B;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-title">
                <h1>Linux Configuration Drift and Compliance Report</h1>
                <div class="header-meta">
                    <strong>Host:</strong> {self.summary.hostname} &nbsp;|&nbsp;
                    <strong>OS:</strong> {self.summary.os_info} &nbsp;|&nbsp;
                    <strong>Scan Time:</strong> {self.summary.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>
            <div class="score-pill">
                <div class="score-val">{score}%</div>
                <div class="score-label">{risk_level}</div>
            </div>
        </div>

        <!-- Quick Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-num">{self.summary.total_rules}</div>
                <div class="stat-name">Total Rules</div>
            </div>
            <div class="stat-card">
                <div class="stat-num stat-pass">{self.summary.passed_count}</div>
                <div class="stat-name">Rules Passed</div>
            </div>
            <div class="stat-card">
                <div class="stat-num stat-crit">{self.summary.critical_count}</div>
                <div class="stat-name">Critical Breaches</div>
            </div>
            <div class="stat-card">
                <div class="stat-num stat-high">{self.summary.high_count}</div>
                <div class="stat-name">High Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-num stat-med">{self.summary.medium_count}</div>
                <div class="stat-name">Medium Risk</div>
            </div>
        </div>

        <!-- Detailed Audit Table -->
        <div class="table-card">
            <div class="table-header">
                <div class="table-title">Audit Findings & Configuration Drift Matrix</div>
                <div style="font-size: 12px; color: #64748B;">Execution: {self.summary.execution_duration_sec}s &nbsp;|&nbsp; Exit Code: {self.summary.exit_code}</div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 80px;">Status</th>
                        <th style="width: 90px;">Rule ID</th>
                        <th style="width: 140px;">Category</th>
                        <th>Rule Description</th>
                        <th>Observed State</th>
                        <th>Expected Baseline</th>
                        <th>Remediation Command</th>
                    </tr>
                </thead>
                <tbody>
                    {all_rows_html}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated by <strong>Linux Configuration Drift & Security Baseline Gatekeeper</strong> &nbsp;|&nbsp; CIS Benchmark Level 1 Aligned
        </div>
    </div>
</body>
</html>
"""
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_file
