"""
OSV (Open Source Vulnerabilities) API Client

Google's OSV database provides vulnerability data for open source packages.
Supports PURL-based queries for language ecosystems (npm, PyPI, Go, Rust, etc.)

API Documentation: https://osv.dev/docs/
"""

import requests
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class Severity:
    """CVE severity information."""
    type: str  # CVSS_V2, CVSS_V3, etc.
    score: str


@dataclass
class AffectedRange:
    """Version range affected by vulnerability."""
    type: str  # SEMVER, ECOSYSTEM, GIT
    events: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class Affected:
    """Package affected by vulnerability."""
    package: Dict[str, str]  # {name, ecosystem, purl}
    ranges: List[AffectedRange] = field(default_factory=list)
    versions: List[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    """OSV vulnerability record."""
    id: str
    summary: str = ""
    details: str = ""
    severity: Optional[List[Severity]] = None
    affected: List[Affected] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)
    published: Optional[datetime] = None
    modified: Optional[datetime] = None
    aliases: List[str] = field(default_factory=list)  # CVE IDs
    cwe_ids: List[str] = field(default_factory=list)  # CWE IDs
    database_specific: Dict[str, Any] = field(default_factory=dict)

    @property
    def cve_id(self) -> Optional[str]:
        """Extract CVE ID from aliases if present."""
        for alias in self.aliases:
            if alias.startswith('CVE-'):
                return alias
        return None

    @property
    def cvss_score(self) -> Optional[float]:
        """Extract CVSS score if available."""
        if self.severity:
            for s in self.severity:
                try:
                    return float(s.score)
                except (ValueError, TypeError):
                    continue
        return None

    @property
    def severity_level(self) -> str:
        """Convert CVSS score to severity level."""
        score = self.cvss_score
        if score is None:
            return "unknown"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"


class OSVClient:
    """
    Client for the OSV (Open Source Vulnerabilities) API.

    Supports PURL-based queries for vulnerability lookups.
    Best for language ecosystem packages (npm, PyPI, Go, Rust, etc.)
    """

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, timeout: int = 30):
        """
        Initialize OSV client.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'flox-sca/2.0'
        })

    def query_by_purl(self, purl: str) -> List[Vulnerability]:
        """
        Query vulnerabilities affecting a package by PURL.

        Args:
            purl: Package URL (e.g., "pkg:npm/lodash@4.17.20")

        Returns:
            List of vulnerabilities affecting this package
        """
        try:
            response = self.session.post(
                f"{self.BASE_URL}/query",
                json={"package": {"purl": purl}},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_vulnerabilities(data.get('vulns', []))
        except requests.RequestException as e:
            logger.error(f"OSV query failed for {purl}: {e}")
            return []

    def query_by_package(self, name: str, ecosystem: str,
                         version: Optional[str] = None) -> List[Vulnerability]:
        """
        Query vulnerabilities by package name and ecosystem.

        Args:
            name: Package name (e.g., "lodash")
            ecosystem: Package ecosystem (e.g., "npm", "PyPI", "Go")
            version: Optional specific version

        Returns:
            List of vulnerabilities affecting this package
        """
        payload = {
            "package": {
                "name": name,
                "ecosystem": ecosystem
            }
        }
        if version:
            payload["version"] = version

        try:
            response = self.session.post(
                f"{self.BASE_URL}/query",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_vulnerabilities(data.get('vulns', []))
        except requests.RequestException as e:
            logger.error(f"OSV query failed for {name}@{ecosystem}: {e}")
            return []

    def query_batch(self, queries: List[Dict[str, Any]]) -> Dict[str, List[Vulnerability]]:
        """
        Query multiple packages in a single request.

        Args:
            queries: List of query objects, each with 'package' and optional 'version'
                     Example: [{"package": {"purl": "pkg:npm/lodash@4.17.20"}}]

        Returns:
            Dict mapping query index to list of vulnerabilities
        """
        try:
            response = self.session.post(
                f"{self.BASE_URL}/querybatch",
                json={"queries": queries},
                timeout=self.timeout * 2  # Longer timeout for batch
            )
            response.raise_for_status()
            data = response.json()

            results = {}
            for i, result in enumerate(data.get('results', [])):
                vulns = self._parse_vulnerabilities(result.get('vulns', []))
                results[str(i)] = vulns
            return results
        except requests.RequestException as e:
            logger.error(f"OSV batch query failed: {e}")
            return {}

    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """
        Get full details for a specific vulnerability.

        Args:
            vuln_id: Vulnerability ID (e.g., "GHSA-xxxx-xxxx-xxxx" or "OSV-xxxx")

        Returns:
            Vulnerability details or None if not found
        """
        try:
            response = self.session.get(
                f"{self.BASE_URL}/vulns/{vuln_id}",
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            vulns = self._parse_vulnerabilities([data])
            return vulns[0] if vulns else None
        except requests.RequestException as e:
            logger.error(f"OSV get vulnerability failed for {vuln_id}: {e}")
            return None

    def _parse_vulnerabilities(self, vulns_data: List[Dict]) -> List[Vulnerability]:
        """Parse raw OSV response into Vulnerability objects."""
        vulnerabilities = []
        for v in vulns_data:
            try:
                severity = None
                if 'severity' in v:
                    severity = [
                        Severity(type=s.get('type', ''), score=s.get('score', ''))
                        for s in v['severity']
                    ]

                affected = []
                for a in v.get('affected', []):
                    ranges = [
                        AffectedRange(
                            type=r.get('type', ''),
                            events=r.get('events', [])
                        )
                        for r in a.get('ranges', [])
                    ]
                    affected.append(Affected(
                        package=a.get('package', {}),
                        ranges=ranges,
                        versions=a.get('versions', [])
                    ))

                # Extract CWE IDs from database_specific (GHSA format)
                database_specific = v.get('database_specific', {})
                cwe_ids = []
                if 'cwe_ids' in database_specific:
                    cwe_ids = database_specific.get('cwe_ids', [])
                elif 'cwes' in database_specific:
                    # Alternative format
                    cwes = database_specific.get('cwes', [])
                    cwe_ids = [c.get('cweId', c) if isinstance(c, dict) else c for c in cwes]

                vuln = Vulnerability(
                    id=v.get('id', ''),
                    summary=v.get('summary', ''),
                    details=v.get('details', ''),
                    severity=severity,
                    affected=affected,
                    references=v.get('references', []),
                    aliases=v.get('aliases', []),
                    cwe_ids=cwe_ids,
                    database_specific=database_specific
                )
                vulnerabilities.append(vuln)
            except Exception as e:
                logger.warning(f"Failed to parse vulnerability: {e}")
                continue

        return vulnerabilities

    def purl_to_query(self, purl: str) -> Dict[str, Any]:
        """Convert a PURL to an OSV query payload."""
        return {"package": {"purl": purl}}


def demo():
    """Demonstrate OSV client functionality."""
    client = OSVClient()

    print("=== OSV Client Demo ===\n")

    # Query a known vulnerable package
    print("Querying pkg:npm/lodash@4.17.20...")
    vulns = client.query_by_purl("pkg:npm/lodash@4.17.20")
    print(f"Found {len(vulns)} vulnerabilities:")
    for v in vulns[:3]:  # Show first 3
        print(f"  - {v.id}: {v.summary[:60]}...")
        if v.cve_id:
            print(f"    CVE: {v.cve_id}")
        print(f"    Severity: {v.severity_level} (score: {v.cvss_score})")
    print()

    # Query by ecosystem
    print("Querying PyPI/requests...")
    vulns = client.query_by_package("requests", "PyPI")
    print(f"Found {len(vulns)} vulnerabilities for requests package")
    print()

    # Batch query
    print("Batch query for multiple packages...")
    queries = [
        {"package": {"purl": "pkg:npm/express@4.17.1"}},
        {"package": {"purl": "pkg:pypi/django@3.2.0"}},
    ]
    results = client.query_batch(queries)
    for idx, vulns in results.items():
        print(f"  Query {idx}: {len(vulns)} vulnerabilities")


if __name__ == "__main__":
    demo()
