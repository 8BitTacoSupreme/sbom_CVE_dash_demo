"""
FOSSA API Client

Implements the 2-step SBOM upload workflow for license compliance scanning:
1. Get signed URL for upload
2. PUT SBOM to signed URL
3. Query issues API for license violations

FOSSA focuses on license compliance but also provides vulnerability data.
This is particularly useful when waiting for BlackDuck trial licenses.

API Documentation: https://docs.fossa.com/reference/api
"""

import os
import json
import logging
import aiohttp
from typing import Optional, List

from .sca_client_base import SCAClientBase, SCAResponse, SCAVulnerability

logger = logging.getLogger(__name__)


class FOSSAClient(SCAClientBase):
    """
    FOSSA API client for license compliance and vulnerability scanning.

    Environment Variables:
        FOSSA_TOKEN: FOSSA API token (from Settings > API Tokens)

    API Flow:
        1. Get signed URL → GET /api/components/signed_url
        2. Upload SBOM → PUT to signed URL
        3. Get issues → GET /api/v2/issues
    """

    API_BASE = "https://app.fossa.com"

    def __init__(self, timeout: int = 300, poll_interval: int = 5):
        super().__init__(timeout, poll_interval)
        self.token = os.environ.get("FOSSA_TOKEN")
        # FOSSA project name (derived from environment_id)
        self._current_project = None

    @property
    def source_name(self) -> str:
        return "fossa"

    @property
    def is_configured(self) -> bool:
        return bool(self.token)

    def _headers(self) -> dict:
        """Get API headers with authentication."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def _sbom_to_fossa_format(self, sbom: dict) -> dict:
        """
        Convert internal SBOM format to FOSSA-compatible CycloneDX.

        FOSSA accepts CycloneDX 1.4+ format for SBOM uploads.
        """
        components = []
        dependencies = []
        app_name = sbom.get("environment_id", "unknown-app")

        for idx, pkg in enumerate(sbom.get("packages", [])):
            # Generate unique bom-ref for relationships
            bom_ref = f"pkg:{idx}"

            component = {
                "type": "library",
                "bom-ref": bom_ref,
                "name": pkg.get("name", "unknown"),
                "version": pkg.get("version", "0.0.0"),
                "supplier": {"name": "nixpkgs"},  # Default supplier for Nix packages
            }
            if pkg.get("purl"):
                component["purl"] = pkg["purl"]
            # Add license if available
            if pkg.get("license"):
                component["licenses"] = [{"license": {"id": pkg["license"]}}]
            components.append(component)

            # Add as dependency of root application
            dependencies.append({"ref": bom_ref, "dependsOn": []})

        # Ensure timestamp is a string
        timestamp = sbom.get("scan_timestamp")
        if timestamp and not isinstance(timestamp, str):
            timestamp = str(timestamp)
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "authors": [{"name": "Flox SCA Demo"}],
                "component": {
                    "type": "application",
                    "bom-ref": "root-app",
                    "name": app_name,
                    "version": "1.0.0"
                }
            },
            "components": components,
            "dependencies": [
                {"ref": "root-app", "dependsOn": [c["bom-ref"] for c in components]}
            ] + dependencies
        }

    async def submit_sbom(self, sbom: dict) -> str:
        """
        Submit SBOM to FOSSA using 2-step signed URL upload.

        Returns a project locator (equivalent to job_id for FOSSA).
        """
        project_name = sbom.get("environment_id", "flox-sca-scan")
        self._current_project = project_name

        # Step 1: Get signed URL for SBOM upload
        signed_url_endpoint = f"{self.API_BASE}/api/components/signed_url"
        revision = sbom.get("environment_hash", "latest")[:16]
        params = {
            "packageSpec": project_name,
            "revision": revision,
            "fileType": "sbom"  # Required for SBOM import feature
        }

        async with aiohttp.ClientSession() as session:
            # Request signed URL
            async with session.get(
                signed_url_endpoint,
                headers=self._headers(),
                params=params
            ) as resp:
                if resp.status == 401:
                    raise PermissionError("FOSSA authentication failed - check FOSSA_TOKEN")
                if resp.status == 403:
                    error_body = await resp.text()
                    if "premium" in error_body.lower() or "feature flag" in error_body.lower():
                        raise PermissionError("FOSSA SBOM upload requires premium subscription (Free tier not supported)")
                    raise PermissionError(f"FOSSA access denied: {error_body}")
                resp.raise_for_status()

                url_data = await resp.json()
                signed_url = url_data.get("signedUrl")
                if not signed_url:
                    raise ValueError("No signed URL returned from FOSSA")

            # Step 2: Upload SBOM to signed URL
            cyclonedx = self._sbom_to_fossa_format(sbom)
            async with session.put(
                signed_url,
                json=cyclonedx,
                headers={"Content-Type": "application/json"}
            ) as upload_resp:
                if upload_resp.status >= 400:
                    error_text = await upload_resp.text()
                    raise ValueError(f"FOSSA upload failed: {error_text}")

            # Step 3: Trigger build/analysis
            build_endpoint = f"{self.API_BASE}/api/components/build"
            build_params = {"fileType": "sbom"}
            build_body = {
                "selectedTeams": [],
                "archives": [{
                    "packageSpec": project_name,
                    "revision": revision,
                    "fileType": "sbom"
                }]
            }
            async with session.post(
                build_endpoint,
                headers=self._headers(),
                params=build_params,
                json=build_body
            ) as build_resp:
                if build_resp.status >= 400:
                    error_text = await build_resp.text()
                    logger.warning(f"FOSSA build trigger returned {build_resp.status}: {error_text}")
                    # Continue anyway - some plans don't require explicit build trigger

        # Return project locator as job_id
        return f"{project_name}${revision}"

    async def poll_status(self, job_id: str) -> str:
        """
        Poll FOSSA for analysis status.

        FOSSA processes uploads asynchronously. We check the project
        revision status until analysis is complete.
        """
        # Parse project locator
        if "$" in job_id:
            project_name, revision = job_id.split("$", 1)
        else:
            project_name = job_id
            revision = "latest"

        # Check project build status
        url = f"{self.API_BASE}/api/revisions/{project_name}%24{revision}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers()) as resp:
                if resp.status == 404:
                    # Project/revision not found yet - still processing
                    return "pending"
                if resp.status >= 400:
                    return "failed"

                data = await resp.json()
                status = data.get("status", "")

                # FOSSA statuses: WAITING, SCANNING, ANALYZED, FAILED
                status_map = {
                    "WAITING": "pending",
                    "SCANNING": "in_progress",
                    "ANALYZED": "completed",
                    "FAILED": "failed"
                }
                return status_map.get(status.upper(), "in_progress")

    async def get_results(self, job_id: str) -> dict:
        """
        Get license and vulnerability issues from FOSSA.

        FOSSA separates issues by category:
        - licensing: License compliance violations
        - vulnerability: Security vulnerabilities
        - quality: Code quality issues
        """
        # Parse project locator
        if "$" in job_id:
            project_name, revision = job_id.split("$", 1)
        else:
            project_name = job_id
            revision = "latest"

        results = {
            "project": project_name,
            "revision": revision,
            "licensing_issues": [],
            "vulnerability_issues": [],
            "dependencies": []
        }

        async with aiohttp.ClientSession() as session:
            # Get licensing issues
            license_url = f"{self.API_BASE}/api/v2/issues"
            license_params = {
                "projectId": project_name,
                "revisionId": f"{project_name}${revision}",
                "category": "licensing"
            }

            async with session.get(
                license_url,
                headers=self._headers(),
                params=license_params
            ) as resp:
                if resp.status == 200:
                    license_data = await resp.json()
                    results["licensing_issues"] = license_data.get("issues", [])

            # Get vulnerability issues
            vuln_params = {
                "projectId": project_name,
                "revisionId": f"{project_name}${revision}",
                "category": "vulnerability"
            }

            async with session.get(
                license_url,
                headers=self._headers(),
                params=vuln_params
            ) as resp:
                if resp.status == 200:
                    vuln_data = await resp.json()
                    results["vulnerability_issues"] = vuln_data.get("issues", [])

            # Get dependency list
            deps_url = f"{self.API_BASE}/api/revisions/{project_name}%24{revision}/dependencies"
            async with session.get(deps_url, headers=self._headers()) as resp:
                if resp.status == 200:
                    deps_data = await resp.json()
                    results["dependencies"] = deps_data if isinstance(deps_data, list) else []

        return results

    def normalize_response(self, raw: dict, latency_ms: int) -> SCAResponse:
        """
        Normalize FOSSA API response to common schema.

        FOSSA provides both license violations and vulnerability data.
        We treat license violations as issues and map them to our schema.
        """
        vulnerabilities: List[SCAVulnerability] = []

        project = raw.get("project", "unknown")
        revision = raw.get("revision", "unknown")
        licensing_issues = raw.get("licensing_issues", [])
        vuln_issues = raw.get("vulnerability_issues", [])
        dependencies = raw.get("dependencies", [])

        # Process vulnerability issues (security CVEs)
        for issue in vuln_issues:
            vuln = issue.get("vulnerability", {})
            affected = issue.get("affectedPackage", {})

            cve_id = vuln.get("cve") or vuln.get("id", "FOSSA-VULN")

            vulnerabilities.append(SCAVulnerability(
                cve_id=cve_id,
                source_id=f"FOSSA-{vuln.get('id', 'UNKNOWN')}",
                package=affected.get("name", issue.get("packageName", "unknown")),
                version=affected.get("version", issue.get("packageVersion", "unknown")),
                purl=affected.get("purl"),
                severity=self._map_severity(vuln.get("severity", "medium")),
                cvss_score=vuln.get("cvssScore"),
                epss_score=None,  # FOSSA doesn't provide EPSS
                remediation=vuln.get("remediation"),
                cwe_ids=vuln.get("cwes", [])
            ))

        # Process license compliance issues as special "license vulnerability" entries
        # These are compliance risks, not security vulnerabilities per se
        for issue in licensing_issues:
            license_info = issue.get("license", {})
            affected = issue.get("affectedPackage", {})

            # Create a pseudo-CVE ID for license issues
            license_id = license_info.get("id", "UNKNOWN")
            issue_type = issue.get("type", "license_violation")

            vulnerabilities.append(SCAVulnerability(
                cve_id=f"LICENSE-{license_id}",
                source_id=f"FOSSA-LICENSE-{issue.get('id', 'UNKNOWN')}",
                package=affected.get("name", issue.get("packageName", "unknown")),
                version=affected.get("version", issue.get("packageVersion", "unknown")),
                purl=affected.get("purl"),
                severity=self._license_severity(issue_type),
                cvss_score=None,
                epss_score=None,
                remediation=f"License: {license_id}. {issue.get('resolution', 'Review license compliance requirements.')}",
                cwe_ids=[]
            ))

        # Count severities
        severity_counts = self._count_severity(vulnerabilities)

        # Count unique packages with issues
        packages_with_issues = len(set(
            (v.package, v.version) for v in vulnerabilities
        ))

        return SCAResponse(
            source=self.source_name,
            scan_id=f"{project}${revision}",
            status="completed",
            latency_ms=latency_ms,
            total_packages=len(dependencies),
            packages_with_issues=packages_with_issues,
            critical=severity_counts['critical'],
            high=severity_counts['high'],
            medium=severity_counts['medium'],
            low=severity_counts['low'],
            vulnerabilities=vulnerabilities
        )

    def _map_severity(self, fossa_severity: str) -> str:
        """Map FOSSA severity levels to standard levels."""
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "low",
            "none": "low"
        }
        return severity_map.get(fossa_severity.lower(), "medium")

    def _license_severity(self, issue_type: str) -> str:
        """
        Map license issue types to severity levels.

        License compliance issues are generally high severity
        as they can have legal implications.
        """
        # High-risk license issues
        high_risk = ["copyleft", "gpl_violation", "incompatible", "unlicensed"]
        # Medium-risk license issues
        medium_risk = ["weak_copyleft", "notice_required", "attribution"]

        issue_lower = issue_type.lower()

        for risk in high_risk:
            if risk in issue_lower:
                return "high"

        for risk in medium_risk:
            if risk in issue_lower:
                return "medium"

        return "medium"  # Default for license issues
