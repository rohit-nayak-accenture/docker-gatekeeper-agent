"""Business rules for deciding whether a scan result should block a release.

PolicyEngine has no external dependencies (no DB, no LLM, no file I/O) — it's
pure logic, which is exactly why it doesn't need anything injected into it.
"""

from datetime import datetime

from models import (
    FindingDecision,
    PolicyDecision,
    ScanResult,
    Severity,
    Verdict,
    Vulnerability,
    Waiver,
)


class PolicyEngine:
    def evaluate(
        self, scan_result: ScanResult, active_waivers: list[Waiver]
    ) -> PolicyDecision:
        # Index active waivers by CVE ID for quick lookup per finding.
        waivers_by_cve: dict[str, Waiver] = {}
        for waiver in active_waivers:
            waivers_by_cve[waiver.cve_id] = waiver

        findings: list[FindingDecision] = []
        for vulnerability in scan_result.vulnerabilities:
            findings.append(
                self._evaluate_finding(
                    vulnerability, scan_result.is_prod_tag, waivers_by_cve
                )
            )

        # Overall verdict is BLOCK if any single finding blocked, else ALLOW.
        overall_verdict = Verdict.ALLOW
        for finding in findings:
            if finding.verdict == Verdict.BLOCK:
                overall_verdict = Verdict.BLOCK
                break

        return PolicyDecision(
            image=scan_result.image,
            image_tag=scan_result.image_tag,
            overall_verdict=overall_verdict,
            findings=findings,
            decided_at=datetime.now(),
        )

    def _evaluate_finding(
        self,
        vulnerability: Vulnerability,
        is_prod_tag: bool,
        waivers_by_cve: dict[str, Waiver],
    ) -> FindingDecision:
        waiver = waivers_by_cve.get(vulnerability.cve_id)
        has_fix = vulnerability.fixed_version is not None

        if vulnerability.severity == Severity.CRITICAL:
            if waiver is not None:
                return FindingDecision(
                    vulnerability=vulnerability,
                    verdict=Verdict.ALLOW_WITH_WAIVER,
                    reason=f"CRITICAL severity but waived by {waiver.approved_by}: {waiver.reason}",
                    waiver_id=waiver.id,
                )
            return FindingDecision(
                vulnerability=vulnerability,
                verdict=Verdict.BLOCK,
                reason="CRITICAL severity with no active waiver",
            )

        if vulnerability.severity == Severity.HIGH:
            if waiver is not None:
                return FindingDecision(
                    vulnerability=vulnerability,
                    verdict=Verdict.ALLOW_WITH_WAIVER,
                    reason=f"HIGH severity but waived by {waiver.approved_by}: {waiver.reason}",
                    waiver_id=waiver.id,
                )
            if not has_fix:
                return FindingDecision(
                    vulnerability=vulnerability,
                    verdict=Verdict.ALLOW,
                    reason="HIGH severity but no fix is available yet, nothing actionable",
                )
            # Fix is available, no waiver: prod tags get blocked, non-prod is relaxed.
            if is_prod_tag:
                return FindingDecision(
                    vulnerability=vulnerability,
                    verdict=Verdict.BLOCK,
                    reason="HIGH severity with a fix available, no waiver, on a prod tag",
                )
            return FindingDecision(
                vulnerability=vulnerability,
                verdict=Verdict.ALLOW,
                reason="HIGH severity with a fix available, but relaxed policy applies on non-prod tags",
            )

        # MEDIUM or LOW: always allowed.
        return FindingDecision(
            vulnerability=vulnerability,
            verdict=Verdict.ALLOW,
            reason=f"{vulnerability.severity.value} severity is below the blocking threshold",
        )
