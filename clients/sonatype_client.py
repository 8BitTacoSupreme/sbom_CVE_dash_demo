"""
Sonatype Nexus IQ API Client

Integrates with Sonatype Nexus IQ Server for policy-driven SCA scanning.
Supports SBOM submission and vulnerability retrieval with Sonatype Intelligence.

API Documentation: https://help.sonatype.com/iqserver/automating/rest-apis
"""

import os
import json
import logging
import aiohttp
from typing import Optional, List
from urllib.parse import urljoin

from .sca_client_base import SCAClientBase, SCAResponse, SCAVulnerability

logger = logging.getLogger(__name__)


class SonatypeClient(SCAClientBase):
    """
    Sonatype Nexus IQ API client for SBOM vulnerability scanning.

    Environment Variables:
        IQ_URL: Nexus IQ Server URL (e.g., https://iq.example.com)
        IQ_TOKEN: Bearer token for authentication
        IQ_APP_ID: Application ID for scanning (optional, defaults to 'flox-sca')

    Features:
        - Sonatype Intelligence: Proprietary vulnerability data (faster than NVD)
        - VEX Support: Vulnerability exploitability exchange data
        - Policy Engine: Custom policies beyond vulnerabilities
        - Waiver Support: Document why certain vulnerabilities are acceptable
        - CVSS v3.1 scoring
    """

    def __init__(self, timeout: int = 300, poll_interval: int = 5):
        super().__init__(timeout, poll_interval)
        self.base_url = os.environ.get("IQ_URL", "").rstrip("/")
        self.token = os.environ.get("IQ_TOKEN")
        self.app_id = os.environ.get("IQ_APP_ID", "flox-sca")
        self._internal_app_id: Optional[str] = None
        self._report_id: Optional[str] = None

    @property
    def source_name(self) -> str:
        return "sonatype"

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.token)

    def _headers(self) -> dict:
        """Get API headers with authentication."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def _sbom_to_cyclonedx_xml(self, sbom: dict) -> str:
        """
        Convert internal SBOM format to CycloneDX XML for Sonatype API.

        Sonatype accepts CycloneDX 1.4+ in XML format.
        """
        components_xml = []
        for pkg in sbom.get("packages", []):
            purl = pkg.get("purl", "")
            name = pkg.get("name", "unknown")
            version = pkg.get("version", "0.0.0")

            component = f'''    <component type="library" bom-ref="{purl or f'pkg:generic/{name}@{version}'}">
      <name>{name}</name>
      <version>{version}</version>
      {f'<purl>{purl}</purl>' if purl else ''}
    </component>'''
            components_xml.append(component)

        return f'''<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <metadata>
    <timestamp>{sbom.get("scan_timestamp", "")}</timestamp>
    <component type="application">
      <name>{sbom.get("environment_id", "unknown-app")}</name>
      <version>1.0.0</version>
    </component>
  </metadata>
  <components>
{chr(10).join(components_xml)}
  </components>
</bom>'''

    async def _get_or_create_app(self, session: aiohttp.ClientSession) -> str:
        """Get or create application in Nexus IQ."""
        # First, try to get existing app
        apps_url = urljoin(self.base_url, "/api/v2/applications")

        async with session.get(apps_url, headers=self._headers()) as resp:
            if resp.status == 200:
                data = await resp.json()
                for app in data.get("applications", []):
                    if app.get("publicId") == self.app_id:
                        return app.get("id")

        # App doesn't exist, create it
        create_payload = {
            "publicId": self.app_id,
            "name": self.app_id,
            "organizationId": "ROOT_ORGANIZATION_ID"  # Default org
        }

        async with session.post(apps_url, headers=self._headers(), json=create_payload) as resp:
            if resp.status in [200, 201]:
                data = await resp.json()
                return data.get("id", self.app_id)
            elif resp.status == 400:
                # App might exist with different case, use the public ID
                return self.app_id
            else:
                logger.warning(f"Could not create app: {resp.status}")
                return self.app_id

    async def submit_sbom(self, sbom: dict) -> str:
        """
        Submit SBOM to Sonatype Nexus IQ for scanning.

        Uses the scan API to upload CycloneDX SBOM.
        """
        async with aiohttp.ClientSession() as session:
            # Get internal app ID
            self._internal_app_id = await self._get_or_create_app(session)

            # Submit SBOM for scanning
            scan_url = urljoin(
                self.base_url,
                f"/api/v2/scan/applications/{self._internal_app_id}"
            )

            # Prepare CycloneDX XML
            sbom_xml = self._sbom_to_cyclonedx_xml(sbom)

            headers = self._headers()
            headers["Content-Type"] = "application/xml"

            async with session.post(scan_url, headers=headers, data=sbom_xml) as resp:
                if resp.status == 401:
                    raise PermissionError("Sonatype authentication failed - check IQ_TOKEN")
                if resp.status == 404:
                    raise ValueError(f"Sonatype app not found: {self.app_id}")

                resp.raise_for_status()
                data = await resp.json()

                # Sonatype returns a scan ID
                self._report_id = data.get("scanId") or data.get("reportId")
                return self._report_id or self._internal_app_id

    async def poll_status(self, job_id: str) -> str:
        """
        Poll Sonatype for scan status.

        Check the report status endpoint.
        """
        if not self._report_id:
            return "completed"

        url = urljoin(
            self.base_url,
            f"/api/v2/scan/applications/{self._internal_app_id}/status/{self._report_id}"
        )

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers()) as resp:
                if resp.status != 200:
                    # Assume completed if can't check
                    return "completed"

                data = await resp.json()
                status = data.get("status", "DONE")

                status_map = {
                    "QUEUED": "pending",
                    "PROCESSING": "in_progress",
                    "DONE": "completed",
                    "FAILED": "failed"
                }
                return status_map.get(status, "completed")

    async def get_results(self, job_id: str) -> dict:
        """Get vulnerability results from Sonatype."""
        # Get the policy evaluation report
        report_url = urljoin(
            self.base_url,
            f"/api/v2/applications/{self._internal_app_id}/reports/{self._report_id or 'latest'}"
        )

        async with aiohttp.ClientSession() as session:
            async with session.get(report_url, headers=self._headers()) as resp:
                if resp.status == 404:
                    # Try the components endpoint instead
                    return await self._get_components_fallback(session, job_id)

                resp.raise_for_status()
                report_data = await resp.json()

                # Get component details with vulnerabilities
                components_url = urljoin(
                    self.base_url,
                    f"/api/v2/applications/{self._internal_app_id}/reports/{self._report_id or 'latest'}/components"
                )

                async with session.get(components_url, headers=self._headers()) as comp_resp:
                    comp_resp.raise_for_status()
                    components_data = await comp_resp.json()

                    report_data["components"] = components_data.get("components", [])
                    return report_data

    async def _get_components_fallback(
        self,
        session: aiohttp.ClientSession,
        job_id: str
    ) -> dict:
        """Fallback to get components directly if report endpoint fails."""
        url = urljoin(
            self.base_url,
            f"/api/v2/components/details"
        )

        # Query for all components
        async with session.get(url, headers=self._headers()) as resp:
            if resp.status == 200:
                return await resp.json()
            return {"components": []}

    def normalize_response(self, raw: dict, latency_ms: int) -> SCAResponse:
        """
        Normalize Sonatype API response to common schema.

        Sonatype response structure:
        {
          "reportTime": "2025-01-13T10:30:00.000Z",
          "components": [
            {
              "componentIdentifier": {
                "format": "maven",
                "coordinates": { "groupId": "...", "artifactId": "...", "version": "..." }
              },
              "securityData": {
                "securityIssues": [
                  {
                    "reference": "sonatype-2021-5422",
                    "severity": 10.0,
                    "status": "OPEN",
                    "threatCategory": "critical",
                    "cwe": "CWE-502",
                    "cvssScore": 10.0
                  }
                ]
              }
            }
          ]
        }
        """
        vulnerabilities: List[SCAVulnerability] = []
        components = raw.get("components", [])
        packages_with_issues = 0

        for comp in components:
            # Extract component identifier
            comp_id = comp.get("componentIdentifier", {})
            coords = comp_id.get("coordinates", {})

            # Build component name from coordinates
            if comp_id.get("format") == "maven":
                comp_name = coords.get("artifactId", "unknown")
                comp_version = coords.get("version", "unknown")
                group_id = coords.get("groupId", "")
                purl = f"pkg:maven/{group_id}/{comp_name}@{comp_version}" if group_id else None
            else:
                comp_name = coords.get("name", comp.get("displayName", "unknown"))
                comp_version = coords.get("version", "unknown")
                purl = comp.get("packageUrl")

            # Get security issues
            security_data = comp.get("securityData", {})
            security_issues = security_data.get("securityIssues", [])

            if security_issues:
                packages_with_issues += 1

            for issue in security_issues:
                # Map threat category to standard severity
                threat = issue.get("threatCategory", "").lower()
                severity_map = {
                    "critical": "critical",
                    "severe": "high",
                    "moderate": "medium",
                    "low": "low"
                }
                severity = severity_map.get(threat, "medium")

                cwe = issue.get("cwe")
                cwe_ids = [cwe] if cwe else []

                # Reference could be CVE or Sonatype-specific
                reference = issue.get("reference", "UNKNOWN")
                cve_id = reference if reference.startswith("CVE-") else reference

                vulnerabilities.append(SCAVulnerability(
                    cve_id=cve_id,
                    source_id=reference,
                    package=comp_name,
                    version=comp_version,
                    purl=purl,
                    severity=severity,
                    cvss_score=issue.get("cvssScore"),
                    epss_score=None,  # Sonatype doesn't provide EPSS directly
                    remediation=None,  # Would need to query remediation endpoint
                    cwe_ids=cwe_ids
                ))

        severity_counts = self._count_severity(vulnerabilities)

        return SCAResponse(
            source=self.source_name,
            scan_id=self._report_id or "unknown",
            status="completed",
            latency_ms=latency_ms,
            total_packages=len(components),
            packages_with_issues=packages_with_issues,
            critical=severity_counts['critical'],
            high=severity_counts['high'],
            medium=severity_counts['medium'],
            low=severity_counts['low'],
            vulnerabilities=vulnerabilities
        )
