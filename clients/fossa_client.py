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
from datetime import datetime, timezone
from typing import Optional, List
from urllib.parse import quote

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
        # FOSSA org ID for locator prefix (discovered on first API call)
        self._org_id = None

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

    async def _discover_org_id(self, session: aiohttp.ClientSession) -> str:
        """
        Discover FOSSA org ID from projects API.

        FOSSA locators include an org prefix like 'sbom+59671/project-name'.
        We need this to correctly poll status and get results.
        """
        if self._org_id:
            return self._org_id

        url = f"{self.API_BASE}/api/projects"
        async with session.get(url, headers=self._headers()) as resp:
            if resp.status == 200:
                projects = await resp.json()
                if projects and len(projects) > 0:
                    # Extract org ID from first project's locator
                    # Format: sbom+{org_id}/project-name
                    locator = projects[0].get("locator", "")
                    if "/" in locator and "+" in locator:
                        # sbom+59671/project -> 59671
                        prefix = locator.split("/")[0]  # sbom+59671
                        self._org_id = prefix.split("+")[1]  # 59671
                        logger.info(f"[fossa] Discovered org ID: {self._org_id}")
                        return self._org_id

        # Fallback: check self to get org from existing project
        logger.warning("[fossa] Could not discover org ID from projects")
        return None

    def _build_locator(self, project_name: str, revision: str) -> str:
        """Build the full FOSSA locator with org prefix."""
        if self._org_id:
            return f"sbom+{self._org_id}/{project_name}${revision}"
        # Fallback without org prefix (may not work for status polling)
        return f"{project_name}${revision}"

    def _parse_locator(self, job_id: str) -> tuple:
        """
        Parse a FOSSA locator into (full_project_id, revision).

        Handles both formats:
        - Full: sbom+59671/project-name$revision
        - Simple: project-name$revision
        """
        if "$" in job_id:
            full_project_id, revision = job_id.rsplit("$", 1)
        else:
            full_project_id = job_id
            revision = "latest"
        return full_project_id, revision

    def _enrich_spdx_with_purls(self, spdx: dict, packages: list) -> dict:
        """
        Enrich raw SPDX with PURLs from our package list.

        FOSSA requires PURLs for proper package identification.
        The original SPDX has nix-store-paths but not PURLs.
        """
        import copy
        enriched = copy.deepcopy(spdx)

        # Build lookup from package name to PURL
        purl_lookup = {}
        for pkg in packages:
            name = pkg.get("name", "").lower()
            if name and pkg.get("purl"):
                purl_lookup[name] = pkg["purl"]

        # Enrich each SPDX package with PURL
        purls_added = 0
        for spdx_pkg in enriched.get("packages", []):
            pkg_name = spdx_pkg.get("name", "").lower()

            # Check if already has a PURL
            has_purl = False
            for ref in spdx_pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl":
                    has_purl = True
                    break

            # Add PURL if not present and we have one
            if not has_purl and pkg_name in purl_lookup:
                if "externalRefs" not in spdx_pkg:
                    spdx_pkg["externalRefs"] = []
                spdx_pkg["externalRefs"].append({
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl_lookup[pkg_name]
                })
                purls_added += 1

        logger.info(f"[fossa] Added {purls_added} PURLs to SPDX")
        return enriched

    def _get_sbom_payload(self, sbom: dict) -> dict:
        """
        Get SBOM payload for FOSSA upload.

        FOSSA accepts both SPDX and CycloneDX formats directly.
        If raw_spdx is available, enrich it with PURLs and use it.
        Otherwise fall back to the simplified package list.
        """
        # Prefer raw SPDX if available - enrich with PURLs for FOSSA
        if sbom.get("raw_spdx"):
            logger.info("[fossa] Using raw SPDX format with PURL enrichment")
            return self._enrich_spdx_with_purls(sbom["raw_spdx"], sbom.get("packages", []))

        # Fallback: convert simplified format to basic SPDX
        logger.info("[fossa] Converting to SPDX format")
        packages = []
        for idx, pkg in enumerate(sbom.get("packages", [])):
            spdx_pkg = {
                "SPDXID": f"SPDXRef-Package-{idx}",
                "name": pkg.get("name", "unknown"),
                "versionInfo": pkg.get("version", "0.0.0"),
                "downloadLocation": "NOASSERTION",
            }
            if pkg.get("purl"):
                spdx_pkg["externalRefs"] = [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": pkg["purl"]
                }]
            if pkg.get("license"):
                spdx_pkg["licenseConcluded"] = pkg["license"]
                spdx_pkg["licenseDeclared"] = pkg["license"]
            packages.append(spdx_pkg)

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": sbom.get("environment_id", "unknown-app"),
            "creationInfo": {
                "created": sbom.get("scan_timestamp", datetime.now(timezone.utc).isoformat()),
                "creators": ["Tool: flox-sca-demo"]
            },
            "packages": packages
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
            # Discover org ID first for proper locator construction
            await self._discover_org_id(session)

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

            # Step 2: Upload SBOM to signed URL (SPDX or CycloneDX)
            sbom_payload = self._get_sbom_payload(sbom)
            async with session.put(
                signed_url,
                json=sbom_payload,
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

        # Return full project locator as job_id
        return self._build_locator(project_name, revision)

    async def poll_status(self, job_id: str) -> str:
        """
        Poll FOSSA for analysis status.

        FOSSA processes uploads asynchronously. We check the project
        revision status until analysis is complete.
        """
        # Parse project locator (handles both full and simple formats)
        full_project_id, revision = self._parse_locator(job_id)

        # URL-encode the full locator for the API call
        # Full locator: sbom+59671/project-name$revision -> sbom%2B59671%2Fproject-name%24revision
        encoded_locator = quote(f"{full_project_id}${revision}", safe="")

        # Check project build status
        url = f"{self.API_BASE}/api/revisions/{encoded_locator}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers()) as resp:
                if resp.status == 404:
                    # Project/revision not found yet - still processing
                    return "pending"
                if resp.status >= 400:
                    return "failed"

                data = await resp.json()

                # Check if revision is resolved (analysis complete)
                if data.get("resolved") is True:
                    return "completed"

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
        # Parse project locator (handles both full and simple formats)
        full_project_id, revision = self._parse_locator(job_id)
        full_locator = f"{full_project_id}${revision}"

        results = {
            "project": full_project_id,
            "revision": revision,
            "licensing_issues": [],
            "vulnerability_issues": [],
            "dependencies": []
        }

        async with aiohttp.ClientSession() as session:
            # Get licensing issues
            license_url = f"{self.API_BASE}/api/v2/issues"
            license_params = {
                "projectId": full_project_id,
                "revisionId": full_locator,
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
                "projectId": full_project_id,
                "revisionId": full_locator,
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
            encoded_locator = quote(full_locator, safe="")
            deps_url = f"{self.API_BASE}/api/revisions/{encoded_locator}/dependencies"
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
            # FOSSA API returns license as string, not dict
            license_id = issue.get("license", "UNKNOWN")
            if isinstance(license_id, dict):
                license_id = license_id.get("id", "UNKNOWN")

            # Package info is in 'source' field
            source = issue.get("source", {})
            if isinstance(source, str):
                source = {}

            issue_type = issue.get("type", "license_violation")

            vulnerabilities.append(SCAVulnerability(
                cve_id=f"LICENSE-{license_id}",
                source_id=f"FOSSA-LICENSE-{issue.get('id', 'UNKNOWN')}",
                package=source.get("name", "unknown"),
                version=source.get("version", "unknown"),
                purl=source.get("purl"),
                severity=self._license_severity(issue_type),
                cvss_score=None,
                epss_score=None,
                remediation=f"License: {license_id}. {issue.get('details', 'Review license compliance requirements.')}",
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
