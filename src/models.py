"""
Data models and core definitions for Linux Configuration Drift & Security Baseline Gatekeeper.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from datetime import datetime


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def penalty_weight(self) -> int:
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 3,
            Severity.INFO: 0
        }
        return weights.get(self, 0)

    @property
    def color_badge(self) -> str:
        colors = {
            Severity.CRITICAL: "#EF4444", # Red
            Severity.HIGH: "#F97316",     # Orange
            Severity.MEDIUM: "#EAB308",   # Yellow
            Severity.LOW: "#3B82F6",      # Blue
            Severity.INFO: "#64748B"      # Slate
        }
        return colors.get(self, "#64748B")


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIPPED = "SKIPPED"


@dataclass
class Finding:
    rule_id: str
    category: str
    title: str
    severity: Severity
    status: Status
    expected: str
    actual: str
    description: str
    remediation_cmd: Optional[str] = None

    @property
    def is_failure(self) -> bool:
        return self.status in [Status.FAIL, Status.WARN]


@dataclass
class AuditSummary:
    hostname: str
    timestamp: datetime = field(default_factory=datetime.now)
    os_info: str = "Unknown Linux"
    findings: List[Finding] = field(default_factory=list)
    execution_duration_sec: float = 0.0

    @property
    def total_rules(self) -> int:
        return len(self.findings)

    @property
    def passed_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.PASS)

    @property
    def failed_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.FAIL)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.FAIL and f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.FAIL and f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.FAIL and f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.FAIL and f.severity == Severity.LOW)

    @property
    def compliance_score(self) -> float:
        """
        Calculates compliance score (0.0 to 100.0) based on weighted severity penalties.
        A single critical finding reduces the score significantly.
        """
        total_penalty = sum(
            f.severity.penalty_weight for f in self.findings if f.status == Status.FAIL
        )
        score = max(0.0, 100.0 - total_penalty)
        return round(score, 1)

    @property
    def exit_code(self) -> int:
        """
        Standard POSIX exit codes:
        0 = Clean (100% Pass or only INFO)
        1 = Minor Drift / Warning (Medium or Low severity failures)
        2 = Critical Security Breach (At least 1 Critical or High failure)
        """
        if self.critical_count > 0 or self.high_count > 0:
            return 2
        elif self.medium_count > 0 or self.low_count > 0:
            return 1
        return 0

    @property
    def risk_level(self) -> str:
        score = self.compliance_score
        if self.critical_count > 0 or score < 50:
            return "CRITICAL RISK"
        elif self.high_count > 0 or score < 75:
            return "HIGH RISK"
        elif self.medium_count > 0 or score < 90:
            return "MODERATE RISK"
        elif score < 100:
            return "LOW RISK"
        return "EXCELLENT (COMPLIANT)"
