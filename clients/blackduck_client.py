"""
Black Duck API Client

Integrates with Black Duck Hub for enterprise SCA scanning.
Supports SBOM submission and vulnerability retrieval with BDSA advisories.

API Documentation: https://sig-product-docs.synopsys.com/bundle/bd-hub/page/Welcome.html
"""

import os
import json
import logging
import aiohttp
from typing import Optional, List
from urllib.parse import urljoin

from .sca_client_base import SCAClientBase, SCAResponse, SCAVulnerability

logger = logging.getLogger(__name__)


class BlackDuckClient(SCAClientBase):
    """
    Black Duck Hub API client for SBOM vulnerability scanning.

    Environment Variables:
        BD_URL: Black Duck Hub URL (e.g., https://blackduck.example.com)
        BD_TOKEN: Bearer token for authentication

    Features:
        - BDSA (Black Duck Security Advisories) - often 23 days before NVD
        - EPSS scoring support
        - Multiple CVSS versions (v2, v3, v4)
        - VEX support
    """

    def __init__(self, timeout: int = 300, poll_interval: int = 5):
        super().__init__(timeout, poll_interval)
        self.base_url = os.environ.get("BD_URL", "").rstrip("/")
        self.token = os.environ.get("BD_TOKEN")
        self._project_id: Optional[str] = None
        self._version_id: Optional[str] = None

    @property
    def source_name(self) -> str:
        return "blackduck"

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.token)

    def _headers(self) -> dict:
        """Get API headers with authentication."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.blackducksoftware.user-4+json"
        }

    def _sbom_to_bdio(self, sbom: dict) -> dict:
        """
        Convert internal SBOM format to BDIO (Black Duck I/O) format.

        Black Duck uses BDIO for component analysis.
        """
        components = []
        for pkg in sbom.get("packages", []):
            component = {
                "@id": pkg.get("purl", f"http://component/{pkg.get('name')}"),
                "@type": "Component",
                "name": pkg.get("name", "unknown"),
                "revision": pkg.get("version", "0.0.0"),
            }
            if pkg.get("purl"):
                component["externalId"] = {
                    "forge": "maven" if "maven" in pkg["purl"] else "generic",
                    "externalId": pkg["purl"]
                }
            components.append(component)

        return {
            "@context": "https://blackducksoftware.github.io/bdio/schema.json",
            "@type": "BillOfMaterials",
            "@id": f"urn:uuid:{sbom.get('environment_hash', 'unknown')[:36]}",
            "specVersion": "2.0.0",
            "spdx:name": sbom.get("environment_id", "unknown-project"),
            "components": components
        }

    async def submit_sbom(self, sbom: dict) -> str:
        """
        Submit SBOM to Black Duck for scanning.

        This creates a project/version and uploads the BOM.
        Returns the version ID for tracking.
        """
        project_name = sbom.get("environment_id", "flox-scan")
        version_name = sbom.get("environment_hash", "latest")[:16]

        async with aiohttp.ClientSession() as session:
            # 1. Create or get project
            project_url = urljoin(self.base_url, "/api/projects")
            project_payload = {
                "name": project_name,
                "description": f"Flox SCA scan for {project_name}"
            }

            async with session.post(project_url, headers=self._headers(), json=project_payload) as resp:
                if resp.status == 401:
                    raise PermissionError("Black Duck authentication failed - check BD_TOKEN")
                # 201 = created, 412 = already exists
                if resp.status == 201:
                    location = resp.headers.get("Location", "")
                    self._project_id = location.split("/")[-1]
                elif resp.status == 412:
                    # Project exists, find it
                    async with session.get(
                        f"{project_url}?q=name:{project_name}",
                        headers=self._headers()
                    ) as search_resp:
                        search_resp.raise_for_status()
                        data = await search_resp.json()
                        items = data.get("items", [])
                        if items:
                            self._project_id = items[0].get("_meta", {}).get("href", "").split("/")[-1]
                        else:
                            raise ValueError(f"Could not find project: {project_name}")
                else:
                    resp.raise_for_status()

            # 2. Create version
            version_url = urljoin(self.base_url, f"/api/projects/{self._project_id}/versions")
            version_payload = {
                "versionName": version_name,
                "phase": "DEVELOPMENT"
            }

            async with session.post(version_url, headers=self._headers(), json=version_payload) as resp:
                if resp.status == 201:
                    location = resp.headers.get("Location", "")
                    self._version_id = location.split("/")[-1]
                elif resp.status == 412:
                    # Version exists
                    async with session.get(
                        f"{version_url}?q=versionName:{version_name}",
                        headers=self._headers()
                    ) as search_resp:
                        search_resp.raise_for_status()
                        data = await search_resp.json()
                        items = data.get("items", [])
                        if items:
                            self._version_id = items[0].get("_meta", {}).get("href", "").split("/")[-1]
                        else:
                            self._version_id = version_name
                else:
                    resp.raise_for_status()

            # 3. Upload BDIO
            bdio = self._sbom_to_bdio(sbom)
            upload_url = urljoin(self.base_url, "/api/developer-scans")
            upload_headers = self._headers()
            upload_headers["Content-Type"] = "application/vnd.blackducksoftware.developer-scan-1-ld-2+json"

            async with session.post(upload_url, headers=upload_headers, json=bdio) as resp:
                # 201 or 202 = accepted
                if resp.status not in [200, 201, 202]:
                    resp.raise_for_status()

            return f"{self._project_id}:{self._version_id}"

    async def poll_status(self, job_id: str) -> str:
        """
        Poll Black Duck for scan status.

        Black Duck scans are typically synchronous after BDIO upload,
        but we check the BOM status to ensure components are processed.
        """
        if ":" in job_id:
            project_id, version_id = job_id.split(":", 1)
        else:
            return "completed"  # Assume done if no structured ID

        url = urljoin(
            self.base_url,
            f"/api/projects/{project_id}/versions/{version_id}/components"
        )

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers()) as resp:
                if resp.status == 200:
                    return "completed"
                elif resp.status == 202:
                    return "in_progress"
                else:
                    return "pending"

    async def get_results(self, job_id: str) -> dict:
        """Get vulnerability results from Black Duck."""
        if ":" in job_id:
            project_id, version_id = job_id.split(":", 1)
        else:
            raise ValueError(f"Invalid job_id format: {job_id}")

        url = urljoin(
            self.base_url,
            f"/api/projects/{project_id}/versions/{version_id}/vulnerable-bom-components"
        )

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers()) as resp:
                resp.raise_for_status()
                data = await resp.json()

                # Also get component count
                components_url = urljoin(
                    self.base_url,
                    f"/api/projects/{project_id}/versions/{version_id}/components"
                )
                async with session.get(components_url, headers=self._headers()) as comp_resp:
                    comp_resp.raise_for_status()
                    comp_data = await comp_resp.json()
                    data["_total_components"] = comp_data.get("totalCount", 0)

                return data

    def normalize_response(self, raw: dict, latency_ms: int) -> SCAResponse:
        """
        Normalize Black Duck API response to common schema.

        Black Duck response structure:
        {
          "items": [
            {
              "componentName": "...",
              "componentVersionName": "...",
              "vulnerabilityWithRemediation": {
                "vulnerabilityName": "CVE-...",
                "description": "...",
                "severity": "CRITICAL|HIGH|MEDIUM|LOW",
                "baseScore": 10.0,
                "epssScore": 0.97,
                "remediationStatus": "...",
                "cweId": "CWE-..."
              }
            }
          ],
          "totalCount": 5
        }
        """
        vulnerabilities: List[SCAVulnerability] = []
        items = raw.get("items", [])
        packages_with_issues = set()

        for item in items:
            vuln_data = item.get("vulnerabilityWithRemediation", {})
            comp_name = item.get("componentName", "unknown")
            comp_version = item.get("componentVersionName", "unknown")
            packages_with_issues.add(f"{comp_name}@{comp_version}")

            cwe_id = vuln_data.get("cweId")
            cwe_ids = [cwe_id] if cwe_id else []

            vulnerabilities.append(SCAVulnerability(
                cve_id=vuln_data.get("vulnerabilityName", "UNKNOWN"),
                source_id=vuln_data.get("vulnerabilityName", ""),
                package=comp_name,
                version=comp_version,
                purl=item.get("componentVersionOriginId"),
                severity=vuln_data.get("severity", "unknown").lower(),
                cvss_score=vuln_data.get("baseScore"),
                epss_score=vuln_data.get("epssScore"),  # Black Duck supports EPSS
                remediation=vuln_data.get("remediationComment"),
                cwe_ids=cwe_ids
            ))

        severity_counts = self._count_severity(vulnerabilities)

        return SCAResponse(
            source=self.source_name,
            scan_id=raw.get("_meta", {}).get("href", "unknown"),
            status="completed",
            latency_ms=latency_ms,
            total_packages=raw.get("_total_components", 0),
            packages_with_issues=len(packages_with_issues),
            critical=severity_counts['critical'],
            high=severity_counts['high'],
            medium=severity_counts['medium'],
            low=severity_counts['low'],
            vulnerabilities=vulnerabilities
        )
