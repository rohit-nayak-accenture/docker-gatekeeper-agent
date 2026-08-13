"""Talks to the LLM to explain a policy decision in plain English.

This is the only file that imports the anthropic SDK — swapping providers
or mocking the client for tests never touches any other file.
"""

import os

import anthropic

from models import PolicyDecision


class LLMSummarizer:
    def __init__(self, client: anthropic.Anthropic | None = None):
        # Client is injected so callers can pass a test double instead of a
        # real API client.
        if client is None:
            client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
        self.client = client

    def summarize(self, decision: PolicyDecision) -> str:
        blocking = decision.blocking_findings
        waived = decision.waived_findings

        if not blocking and not waived:
            return "No blocking issues - this image passed policy cleanly."

        prompt = self._build_prompt(blocking, waived)
        response = self.client.messages.create(
            model="claude-sonnet-5",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def _build_prompt(self, blocking, waived) -> str:
        lines = [
            "You are summarizing a Docker image security gate decision for a developer.",
            "Explain in plain English what is blocking release, and give one concrete",
            "remediation suggestion per blocking CVE (e.g. 'upgrade openssl to 3.0.9').",
            "Keep it short and skip anything not listed below.",
            "",
        ]

        if blocking:
            lines.append("BLOCKING FINDINGS:")
            for finding in blocking:
                vuln = finding.vulnerability
                if vuln.fixed_version:
                    fix_note = f"fix available: {vuln.fixed_version}"
                else:
                    fix_note = "no fix available yet"
                lines.append(
                    f"- {vuln.cve_id} ({vuln.severity.value}) in {vuln.package_name} "
                    f"{vuln.installed_version}, {fix_note}. Reason: {finding.reason}"
                )
            lines.append("")

        if waived:
            lines.append("WAIVED FINDINGS (already approved, just for context):")
            for finding in waived:
                vuln = finding.vulnerability
                lines.append(
                    f"- {vuln.cve_id} ({vuln.severity.value}) in {vuln.package_name}. "
                    f"Reason: {finding.reason}"
                )

        return "\n".join(lines)
