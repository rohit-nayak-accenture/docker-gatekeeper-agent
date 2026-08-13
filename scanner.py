"""Adapter that translates Trivy's raw JSON schema into our own domain models.

Trivy's field names (VulnerabilityID, PkgName, ...) never leak past this file.
"""

import json

from models import ScanResult, Severity, Vulnerability


class TrivyScanner:
    def parse(self, data: dict) -> ScanResult:
        image, image_tag = self._split_artifact_name(data["ArtifactName"])

        vulnerabilities: list[Vulnerability] = []
        for result in data.get("Results", []):
            for raw_vuln in result.get("Vulnerabilities", []):
                vulnerabilities.append(
                    Vulnerability(
                        cve_id=raw_vuln["VulnerabilityID"],
                        package_name=raw_vuln["PkgName"],
                        installed_version=raw_vuln["InstalledVersion"],
                        fixed_version=raw_vuln.get("FixedVersion") or None,
                        severity=Severity(raw_vuln["Severity"]),
                        title=raw_vuln.get("Title", ""),
                    )
                )

        return ScanResult(
            image=image,
            image_tag=image_tag,
            scanned_at=data["ScannedAt"],
            vulnerabilities=vulnerabilities,
        )

    @staticmethod
    def _split_artifact_name(artifact_name: str) -> tuple[str, str]:
        # ArtifactName is "image:tag" — split on the last colon so registry
        # hosts with ports (e.g. "localhost:5000/myapp:latest") stay intact.
        image, _, tag = artifact_name.rpartition(":")
        return image, tag

    @staticmethod
    def load_sample(path: str) -> ScanResult:
        with open(path, "r") as f:
            data = json.load(f)
        return TrivyScanner().parse(data)
