"""Domain models for the gatekeeper. Pydantic v2 BaseModels only — no I/O, no business logic."""

from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from pydantic import BaseModel, model_validator


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        # Higher rank = more severe. Compare severities with e.g.
        # vuln.severity.rank > Severity.HIGH.rank instead of using > directly
        # on the enum members.
        order = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3,
        }
        return order[self]


class Vulnerability(BaseModel):
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    severity: Severity
    title: str


class ScanResult(BaseModel):
    image: str
    image_tag: str
    scanned_at: datetime
    vulnerabilities: list[Vulnerability]

    @property
    def is_prod_tag(self) -> bool:
        # Non-prod tags get a relaxed policy in policy.py. We check whole
        # segments of the tag, not a substring, so "latest" doesn't
        # accidentally match "test" (latest = la + test).
        non_prod_markers = ["dev", "staging", "test", "local"]

        tag_lower = self.image_tag.lower()
        for separator in ("-", "_", ".", "/"):
            tag_lower = tag_lower.replace(separator, " ")
        segments = tag_lower.split()

        for segment in segments:
            if segment in non_prod_markers:
                return False
        return True


class Waiver(BaseModel):
    id: Optional[int] = None
    image: str
    cve_id: str
    reason: str
    approved_by: str
    created_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def check_expiry_after_creation(self) -> "Waiver":
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        return self

    def is_active(self, as_of: Optional[datetime] = None) -> bool:
        if as_of is None:
            as_of = datetime.now()
        return self.created_at <= as_of < self.expires_at

    @classmethod
    def create(
        cls,
        image: str,
        cve_id: str,
        reason: str,
        approved_by: str,
        days: int = 30,
    ) -> "Waiver":
        created_at = datetime.now()
        return cls(
            image=image,
            cve_id=cve_id,
            reason=reason,
            approved_by=approved_by,
            created_at=created_at,
            expires_at=created_at + timedelta(days=days),
        )


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ALLOW_WITH_WAIVER = "ALLOW_WITH_WAIVER"


class FindingDecision(BaseModel):
    vulnerability: Vulnerability
    verdict: Verdict
    reason: str
    waiver_id: Optional[int] = None


class PolicyDecision(BaseModel):
    image: str
    image_tag: str
    overall_verdict: Verdict
    findings: list[FindingDecision]
    decided_at: datetime
    summary: str = ""  # Filled in later by llm_summary.py

    @property
    def blocking_findings(self) -> list[FindingDecision]:
        result = []
        for finding in self.findings:
            if finding.verdict == Verdict.BLOCK:
                result.append(finding)
        return result

    @property
    def waived_findings(self) -> list[FindingDecision]:
        result = []
        for finding in self.findings:
            if finding.verdict == Verdict.ALLOW_WITH_WAIVER:
                result.append(finding)
        return result
