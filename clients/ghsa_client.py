"""
GitHub Security Advisories (GHSA) Client

GHSA provides curated vulnerability data for open source packages.
Data is in OSV format with GitHub-specific enrichments.

Sources:
- REST API: https://api.github.com/advisories
- Raw data: https://github.com/github/advisory-database
"""

import requests
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import os

logger = logging.getLogger(__name__)


@dataclass
class GHSAAdvisory:
    """GitHub Security Advisory."""
    ghsa_id: str                    # GHSA-xxxx-xxxx-xxxx
    cve_id: Optional[str]           # CVE-2021-44228 (if assigned)
    summary: str
    description: str
    severity: str                   # critical, high, medium, low
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cwe_ids: List[str]
    published_at: Optional[datetime]
    updated_at: Optional[datetime]
    withdrawn_at: Optional[datetime]
    vulnerabilities: List[Dict]     # Affected packages with version ranges
    references: List[str]

    @property
    def primary_id(self) -> str:
        """Return CVE ID if available, else GHSA ID."""
        return self.cve_id or self.ghsa_id


class GHSAClient:
    """
    Client for GitHub Security Advisories.

    Uses the public REST API (no auth required for public advisories).
    For higher rate limits, set GITHUB_TOKEN env var.
    """

    API_BASE = "https://api.github.com/advisories"

    def __init__(self, token: Optional[str] = None, cache_ttl_hours: int = 1):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.cache_ttl_hours = cache_ttl_hours
        self._cache: Dict[str, GHSAAdvisory] = {}
        self._cache_timestamp: Optional[datetime] = None

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def query_by_package(self, ecosystem: str, package: str) -> List[GHSAAdvisory]:
        """
        Query advisories affecting a specific package.

        Args:
            ecosystem: Package ecosystem (npm, pypi, go, maven, nuget, rubygems, etc.)
            package: Package name

        Returns:
            List of advisories affecting this package
        """
        params = {
            "affects": f"{ecosystem}/{package}",
            "per_page": 100
        }
        return self._fetch_advisories(params)

    def query_by_cve(self, cve_id: str) -> Optional[GHSAAdvisory]:
        """
        Query advisory by CVE ID.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            Advisory if found, None otherwise
        """
        params = {"cve_id": cve_id}
        advisories = self._fetch_advisories(params)
        return advisories[0] if advisories else None

    def query_by_ghsa(self, ghsa_id: str) -> Optional[GHSAAdvisory]:
        """
        Query advisory by GHSA ID.

        Args:
            ghsa_id: GHSA identifier (e.g., GHSA-xxxx-xxxx-xxxx)

        Returns:
            Advisory if found, None otherwise
        """
        params = {"ghsa_id": ghsa_id}
        advisories = self._fetch_advisories(params)
        return advisories[0] if advisories else None

    def query_recent(self, since: datetime = None, severity: str = None) -> List[GHSAAdvisory]:
        """
        Query recent advisories.

        Args:
            since: Only return advisories updated after this time
            severity: Filter by severity (critical, high, medium, low)

        Returns:
            List of matching advisories
        """
        params = {"per_page": 100, "sort": "updated", "direction": "desc"}
        if since:
            params["updated"] = f">={since.isoformat()}"
        if severity:
            params["severity"] = severity
        return self._fetch_advisories(params)

    def _fetch_advisories(self, params: Dict) -> List[GHSAAdvisory]:
        """Fetch advisories from API with pagination."""
        advisories = []
        url = self.API_BASE

        while url:
            try:
                response = requests.get(url, headers=self._headers(), params=params, timeout=30)
                response.raise_for_status()

                data = response.json()

                # Handle error responses (e.g., rate limiting)
                if isinstance(data, dict):
                    if "message" in data:
                        logger.error(f"GHSA API error: {data.get('message')}")
                        break
                    # Single advisory response
                    try:
                        advisory = self._parse_advisory(data)
                        advisories.append(advisory)
                    except Exception as e:
                        logger.warning(f"Failed to parse advisory: {e}")
                    break
                elif isinstance(data, list):
                    for item in data:
                        try:
                            advisory = self._parse_advisory(item)
                            advisories.append(advisory)
                        except Exception as e:
                            logger.warning(f"Failed to parse advisory: {e}")
                else:
                    logger.warning(f"Unexpected GHSA API response type: {type(data)}")
                    break

                # Handle pagination
                url = response.links.get("next", {}).get("url")
                params = {}  # Params are in the next URL

            except requests.RequestException as e:
                logger.error(f"GHSA API error: {e}")
                break

        return advisories

    def _parse_advisory(self, data: Dict) -> GHSAAdvisory:
        """Parse API response into GHSAAdvisory."""
        cvss = data.get("cvss") or {}

        return GHSAAdvisory(
            ghsa_id=data.get("ghsa_id", ""),
            cve_id=data.get("cve_id"),
            summary=data.get("summary", ""),
            description=data.get("description", ""),
            severity=data.get("severity", "unknown"),
            cvss_score=cvss.get("score"),
            cvss_vector=cvss.get("vector_string"),
            cwe_ids=[c.get("cwe_id") for c in data.get("cwes", []) if c.get("cwe_id")],
            published_at=self._parse_datetime(data.get("published_at")),
            updated_at=self._parse_datetime(data.get("updated_at")),
            withdrawn_at=self._parse_datetime(data.get("withdrawn_at")),
            vulnerabilities=data.get("vulnerabilities", []),
            references=[r.get("url") for r in data.get("references", []) if r.get("url")]
        )

    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        except ValueError:
            return None

    def to_cve_record(self, advisory: GHSAAdvisory) -> Dict:
        """
        Convert GHSA advisory to cve_feed record format.

        Returns dict compatible with existing cve_feed topic schema.
        """
        # Extract affected packages and version ranges
        affected_packages = []
        for vuln in advisory.vulnerabilities:
            pkg = vuln.get("package", {})
            ecosystem = pkg.get("ecosystem", "generic").lower()
            name = pkg.get("name", "")

            affected_packages.append({
                "purl": f"pkg:{ecosystem}/{name}",
                "vulnerable_versions": vuln.get("vulnerable_version_range"),
                "patched_versions": vuln.get("patched_versions"),
                "first_patched": vuln.get("first_patched_version"),
            })

        return {
            "cve_id": advisory.cve_id or advisory.ghsa_id,
            "ghsa_id": advisory.ghsa_id,
            "severity": advisory.severity,
            "cvss_score": advisory.cvss_score,
            "cwe_ids": advisory.cwe_ids,
            "description": advisory.summary,
            "affected_packages": affected_packages,
            "source": "ghsa",
            "published_at": advisory.published_at.isoformat() if advisory.published_at else None,
            "updated_at": advisory.updated_at.isoformat() if advisory.updated_at else None,
            "references": advisory.references,
            "status": "withdrawn" if advisory.withdrawn_at else "active",
        }


def demo():
    """Demonstrate GHSA client functionality."""
    client = GHSAClient()

    print("=== GHSA Client Demo ===\n")

    # Query recent critical advisories
    print("Fetching recent critical advisories...")
    advisories = client.query_recent(severity="critical")
    print(f"Found {len(advisories)} critical advisories\n")

    for advisory in advisories[:5]:
        print(f"  {advisory.cve_id or advisory.ghsa_id}: {advisory.summary[:60]}...")
        if advisory.cvss_score:
            print(f"    CVSS: {advisory.cvss_score}")
        if advisory.vulnerabilities:
            pkg = advisory.vulnerabilities[0].get("package", {})
            print(f"    Package: {pkg.get('ecosystem')}/{pkg.get('name')}")
        print()

    # Query by package
    print("\nQuerying advisories for lodash (npm)...")
    lodash_advisories = client.query_by_package("npm", "lodash")
    print(f"Found {len(lodash_advisories)} advisories for lodash")
    for advisory in lodash_advisories[:3]:
        print(f"  {advisory.cve_id or advisory.ghsa_id}: {advisory.summary[:50]}...")

    # Convert to cve_feed format
    if advisories:
        print("\n\nSample cve_feed record:")
        record = client.to_cve_record(advisories[0])
        import json
        print(json.dumps(record, indent=2, default=str))


if __name__ == "__main__":
    demo()
