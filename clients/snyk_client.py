"""
Snyk API Client

Implements the 3-step async SBOM scanning workflow:
1. POST SBOM to get job_id
2. Poll job status until "finished"
3. GET results to retrieve vulnerability data

API Documentation: https://docs.snyk.io/snyk-api/reference/sbom-test
"""

import os
import json
import logging
import aiohttp
from typing import Optional, List

from .sca_client_base import SCAClientBase, SCAResponse, SCAVulnerability

logger = logging.getLogger(__name__)


class SnykClient(SCAClientBase):
    """
    Snyk API client for SBOM vulnerability scanning.

    Environment Variables:
        SNYK_TOKEN: Snyk API token
        SNYK_ORG_ID: Snyk organization ID (UUID)

    API Flow:
        1. Submit SBOM → POST /orgs/{org}/sbom_tests → job_id
        2. Poll status → GET /orgs/{org}/sbom_tests/{job_id}
        3. Get results → GET /orgs/{org}/sbom_tests/{job_id}/results
    """

    API_BASE = "https://api.snyk.io/rest"
    API_VERSION = "2024-09-03~beta"

    def __init__(self, timeout: int = 300, poll_interval: int = 5):
        super().__init__(timeout, poll_interval)
        self.token = os.environ.get("SNYK_TOKEN")
        self.org_id = os.environ.get("SNYK_ORG_ID")

    @property
    def source_name(self) -> str:
        return "snyk"

    @property
    def is_configured(self) -> bool:
        return bool(self.token and self.org_id)

    def _headers(self) -> dict:
        """Get API headers with authentication."""
        return {
            "Authorization": f"token {self.token}",
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json"
        }

    def _sbom_to_cyclonedx(self, sbom: dict) -> dict:
        """
        Convert internal SBOM format to CycloneDX for Snyk API.

        Snyk accepts CycloneDX 1.4+ format.
        """
        components = []
        for pkg in sbom.get("packages", []):
            component = {
                "type": "library",
                "name": pkg.get("name", "unknown"),
                "version": pkg.get("version", "0.0.0"),
            }
            if pkg.get("purl"):
                component["purl"] = pkg["purl"]
            components.append(component)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": sbom.get("scan_timestamp"),
                "component": {
                    "type": "application",
                    "name": sbom.get("environment_id", "unknown-app"),
                    "version": "1.0.0"
                }
            },
            "components": components
        }

    async def submit_sbom(self, sbom: dict) -> str:
        """Submit SBOM to Snyk for scanning."""
        url = f"{self.API_BASE}/orgs/{self.org_id}/sbom_tests?version={self.API_VERSION}"

        cyclonedx = self._sbom_to_cyclonedx(sbom)
        payload = {
            "data": {
                "type": "sbom_test",
                "attributes": {
                    "sbom": cyclonedx
                }
            }
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=self._headers(), json=payload) as resp:
                if resp.status == 401:
                    raise PermissionError("Snyk authentication failed - check SNYK_TOKEN")
                if resp.status == 404:
                    raise ValueError(f"Snyk org not found - check SNYK_ORG_ID: {self.org_id}")
                resp.raise_for_status()

                data = await resp.json()
                job_id = data.get("data", {}).get("id")
                if not job_id:
                    raise ValueError("No job_id returned from Snyk")
                return job_id

    async def poll_status(self, job_id: str) -> str:
        """Poll Snyk for job status."""
        url = f"{self.API_BASE}/orgs/{self.org_id}/sbom_tests/{job_id}?version={self.API_VERSION}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers()) as resp:
                resp.raise_for_status()
                data = await resp.json()

                status = data.get("data", {}).get("attributes", {}).get("status", "unknown")
                # Snyk uses: queued, processing, finished, error
                status_map = {
                    "queued": "pending",
                    "processing": "in_progress",
                    "finished": "completed",
                    "error": "failed"
                }
                return status_map.get(status, "pending")

    async def get_results(self, job_id: str) -> dict:
        """Get vulnerability results from Snyk."""
        url = f"{self.API_BASE}/orgs/{self.org_id}/sbom_tests/{job_id}/results?version={self.API_VERSION}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers()) as resp:
                resp.raise_for_status()
                return await resp.json()

    def normalize_response(self, raw: dict, latency_ms: int) -> SCAResponse:
        """
        Normalize Snyk API response to common schema.

        Snyk response structure:
        {
          "data": {
            "type": "sbom_test_results",
            "attributes": {
              "summary": { total_packages, packages_with_issues, total_issues, critical, high, medium, low },
              "packages": [
                {
                  "name": "...",
                  "version": "...",
                  "purl": "...",
                  "vulnerabilities": [
                    { "id": "SNYK-...", "title": "...", "severity": "...", "cvss_score": ..., "cve": [...] }
                  ]
                }
              ]
            }
          }
        }
        """
        vulnerabilities: List[SCAVulnerability] = []

        data = raw.get("data", {})
        attributes = data.get("attributes", {})
        summary = attributes.get("summary", {})
        packages = attributes.get("packages", [])

        for pkg in packages:
            pkg_name = pkg.get("name", "unknown")
            pkg_version = pkg.get("version", "unknown")
            pkg_purl = pkg.get("purl")

            for vuln in pkg.get("vulnerabilities", []):
                cve_list = vuln.get("cve", [])
                cve_id = cve_list[0] if cve_list else vuln.get("id", "UNKNOWN")

                vulnerabilities.append(SCAVulnerability(
                    cve_id=cve_id,
                    source_id=vuln.get("id", ""),
                    package=pkg_name,
                    version=pkg_version,
                    purl=pkg_purl,
                    severity=vuln.get("severity", "unknown").lower(),
                    cvss_score=vuln.get("cvss_score"),
                    epss_score=None,  # Snyk doesn't provide EPSS
                    remediation=vuln.get("remediation", {}).get("description"),
                    cwe_ids=vuln.get("cwe", [])
                ))

        severity_counts = self._count_severity(vulnerabilities)

        return SCAResponse(
            source=self.source_name,
            scan_id=data.get("id", "unknown"),
            status="completed",
            latency_ms=latency_ms,
            total_packages=summary.get("total_packages", 0),
            packages_with_issues=summary.get("packages_with_issues", 0),
            critical=severity_counts['critical'],
            high=severity_counts['high'],
            medium=severity_counts['medium'],
            low=severity_counts['low'],
            vulnerabilities=vulnerabilities
        )
