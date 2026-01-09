"""
NVD (National Vulnerability Database) API Client

NIST's NVD provides CVE data with CPE (Common Platform Enumeration) matching.
Best for native C/C++ libraries and system software.

API Documentation: https://nvd.nist.gov/developers/vulnerabilities
Rate Limits:
  - Without API key: 5 requests per 30 seconds
  - With API key: 50 requests per 30 seconds
"""

import requests
import time
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
import logging
import os

logger = logging.getLogger(__name__)


class RateLimiter:
    """Thread-safe rate limiter for API requests."""

    def __init__(self, requests_per_window: int, window_seconds: int):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.request_times: List[float] = []
        self.lock = threading.Lock()

    def acquire(self):
        """Block until a request slot is available."""
        with self.lock:
            now = time.time()
            # Remove requests outside the window
            self.request_times = [
                t for t in self.request_times
                if now - t < self.window_seconds
            ]

            if len(self.request_times) >= self.requests_per_window:
                # Calculate wait time
                oldest = min(self.request_times)
                wait_time = self.window_seconds - (now - oldest) + 0.1
                if wait_time > 0:
                    logger.debug(f"Rate limit reached, waiting {wait_time:.1f}s")
                    time.sleep(wait_time)

            self.request_times.append(time.time())


@dataclass
class CVSSData:
    """CVSS scoring data."""
    version: str
    vector_string: str
    base_score: float
    base_severity: str


@dataclass
class CPEMatch:
    """CPE match criteria for vulnerability."""
    vulnerable: bool
    cpe23Uri: str
    version_start_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    version_end_including: Optional[str] = None


@dataclass
class CVE:
    """NVD CVE record."""
    id: str
    description: str = ""
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    cvss_v3: Optional[CVSSData] = None
    cvss_v2: Optional[CVSSData] = None
    cpe_matches: List[CPEMatch] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)  # e.g., ["CWE-787", "CWE-125"]

    @property
    def cvss_score(self) -> Optional[float]:
        """Get CVSS score, preferring v3."""
        if self.cvss_v3:
            return self.cvss_v3.base_score
        if self.cvss_v2:
            return self.cvss_v2.base_score
        return None

    @property
    def severity(self) -> str:
        """Get severity level."""
        if self.cvss_v3:
            return self.cvss_v3.base_severity.lower()
        if self.cvss_v2:
            return self.cvss_v2.base_severity.lower()
        return "unknown"

    @property
    def severity_level(self) -> str:
        """Normalize severity to standard levels."""
        sev = self.severity
        if sev in ('critical',):
            return 'critical'
        if sev in ('high',):
            return 'high'
        if sev in ('medium',):
            return 'medium'
        if sev in ('low',):
            return 'low'
        return 'unknown'


class NVDClient:
    """
    Client for the NVD (National Vulnerability Database) API.

    Supports CPE-based queries for vulnerability lookups.
    Best for native libraries and system software (openssl, curl, zlib, etc.)
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Hardcoded API key (get yours at https://nvd.nist.gov/developers/request-an-api-key)
    DEFAULT_API_KEY = "52865b85-fec8-435b-aaf8-d140e7e18051"  # Replace with: "your-api-key-here"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize NVD client.

        Args:
            api_key: NVD API key (optional, increases rate limit 10x)
                     Get one at: https://nvd.nist.gov/developers/request-an-api-key
            timeout: Request timeout in seconds
        """
        self.api_key = api_key or os.environ.get('NVD_API_KEY') or self.DEFAULT_API_KEY
        self.timeout = timeout

        # Rate limiter: 50/30s with key, 5/30s without
        requests_per_window = 50 if self.api_key else 5
        self.rate_limiter = RateLimiter(
            requests_per_window=requests_per_window,
            window_seconds=30
        )

        self.session = requests.Session()
        headers = {'User-Agent': 'flox-sca/2.0'}
        if self.api_key:
            headers['apiKey'] = self.api_key
        self.session.headers.update(headers)

    def query_by_cpe(self, cpe: str, exact_match: bool = False) -> List[CVE]:
        """
        Query CVEs affecting a CPE.

        Args:
            cpe: CPE 2.3 string (e.g., "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*")
            exact_match: If True, only return exact CPE matches

        Returns:
            List of CVEs affecting this CPE
        """
        self.rate_limiter.acquire()

        params = {}
        if exact_match:
            params['cpeName'] = cpe
        else:
            params['cpeMatchString'] = cpe

        try:
            response = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_cves(data.get('vulnerabilities', []))
        except requests.RequestException as e:
            logger.error(f"NVD query failed for {cpe}: {e}")
            return []

    def query_by_keyword(self, keyword: str) -> List[CVE]:
        """
        Search CVEs by keyword.

        Args:
            keyword: Search term (e.g., "openssl buffer overflow")

        Returns:
            List of matching CVEs
        """
        self.rate_limiter.acquire()

        try:
            response = self.session.get(
                self.BASE_URL,
                params={'keywordSearch': keyword},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_cves(data.get('vulnerabilities', []))
        except requests.RequestException as e:
            logger.error(f"NVD keyword search failed for {keyword}: {e}")
            return []

    def query_by_cve_id(self, cve_id: str) -> Optional[CVE]:
        """
        Get a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            CVE details or None if not found
        """
        self.rate_limiter.acquire()

        try:
            response = self.session.get(
                self.BASE_URL,
                params={'cveId': cve_id},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            cves = self._parse_cves(data.get('vulnerabilities', []))
            return cves[0] if cves else None
        except requests.RequestException as e:
            logger.error(f"NVD query failed for {cve_id}: {e}")
            return None

    def query_recent(self, days: int = 7, severity: Optional[str] = None) -> List[CVE]:
        """
        Query recently published or modified CVEs.

        Args:
            days: Number of days to look back
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            List of recent CVEs
        """
        self.rate_limiter.acquire()

        from datetime import datetime, timedelta
        end = datetime.utcnow()
        start = end - timedelta(days=days)

        params = {
            'pubStartDate': start.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end.strftime('%Y-%m-%dT%H:%M:%S.000'),
        }
        if severity:
            params['cvssV3Severity'] = severity.upper()

        try:
            response = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_cves(data.get('vulnerabilities', []))
        except requests.RequestException as e:
            logger.error(f"NVD recent query failed: {e}")
            return []

    def _parse_cves(self, vulns_data: List[Dict]) -> List[CVE]:
        """Parse raw NVD response into CVE objects."""
        cves = []
        for item in vulns_data:
            try:
                cve_data = item.get('cve', {})

                # Parse descriptions (English)
                description = ""
                for desc in cve_data.get('descriptions', []):
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break

                # Parse CVSS v3
                cvss_v3 = None
                metrics = cve_data.get('metrics', {})
                for v3_data in metrics.get('cvssMetricV31', []) + metrics.get('cvssMetricV30', []):
                    cvss = v3_data.get('cvssData', {})
                    cvss_v3 = CVSSData(
                        version=cvss.get('version', '3.1'),
                        vector_string=cvss.get('vectorString', ''),
                        base_score=cvss.get('baseScore', 0.0),
                        base_severity=cvss.get('baseSeverity', 'UNKNOWN')
                    )
                    break

                # Parse CVSS v2
                cvss_v2 = None
                for v2_data in metrics.get('cvssMetricV2', []):
                    cvss = v2_data.get('cvssData', {})
                    cvss_v2 = CVSSData(
                        version=cvss.get('version', '2.0'),
                        vector_string=cvss.get('vectorString', ''),
                        base_score=cvss.get('baseScore', 0.0),
                        base_severity=v2_data.get('baseSeverity', 'UNKNOWN')
                    )
                    break

                # Parse CPE matches
                cpe_matches = []
                for config in cve_data.get('configurations', []):
                    for node in config.get('nodes', []):
                        for match in node.get('cpeMatch', []):
                            cpe_matches.append(CPEMatch(
                                vulnerable=match.get('vulnerable', False),
                                cpe23Uri=match.get('criteria', ''),
                                version_start_including=match.get('versionStartIncluding'),
                                version_end_excluding=match.get('versionEndExcluding'),
                                version_end_including=match.get('versionEndIncluding')
                            ))

                # Parse references
                references = [
                    {'url': ref.get('url', ''), 'source': ref.get('source', '')}
                    for ref in cve_data.get('references', [])
                ]

                # Parse CWE IDs (weakness enumeration)
                cwe_ids = []
                for weakness in cve_data.get('weaknesses', []):
                    for desc in weakness.get('description', []):
                        if desc.get('lang') == 'en':
                            cwe_value = desc.get('value', '')
                            if cwe_value.startswith('CWE-') or cwe_value.startswith('NVD-CWE'):
                                cwe_ids.append(cwe_value)
                # Deduplicate while preserving order
                cwe_ids = list(dict.fromkeys(cwe_ids))

                # Parse dates
                published = None
                if cve_data.get('published'):
                    try:
                        published = datetime.fromisoformat(
                            cve_data['published'].replace('Z', '+00:00')
                        )
                    except ValueError:
                        pass

                cve = CVE(
                    id=cve_data.get('id', ''),
                    description=description,
                    published=published,
                    cvss_v3=cvss_v3,
                    cvss_v2=cvss_v2,
                    cpe_matches=cpe_matches,
                    references=references,
                    cwe_ids=cwe_ids
                )
                cves.append(cve)
            except Exception as e:
                logger.warning(f"Failed to parse CVE: {e}")
                continue

        return cves

    def build_cpe(self, vendor: str, product: str, version: str = "*") -> str:
        """
        Build a CPE 2.3 string.

        Args:
            vendor: Vendor name (e.g., "openssl")
            product: Product name (e.g., "openssl")
            version: Version (e.g., "3.0.0" or "*" for any)

        Returns:
            CPE 2.3 formatted string
        """
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def demo():
    """Demonstrate NVD client functionality."""
    client = NVDClient()

    print("=== NVD Client Demo ===\n")

    # Query a known CVE
    print("Fetching CVE-2021-44228 (Log4Shell)...")
    cve = client.query_by_cve_id("CVE-2021-44228")
    if cve:
        print(f"  ID: {cve.id}")
        print(f"  Severity: {cve.severity_level} (score: {cve.cvss_score})")
        print(f"  Description: {cve.description[:100]}...")
        print(f"  CPE matches: {len(cve.cpe_matches)}")
    print()

    # Query by CPE
    print("Querying CVEs for OpenSSL 3.0...")
    cpe = client.build_cpe("openssl", "openssl", "3.0.0")
    print(f"  CPE: {cpe}")
    cves = client.query_by_cpe(cpe)
    print(f"  Found {len(cves)} CVEs")
    for c in cves[:3]:
        print(f"    - {c.id}: {c.severity_level}")
    print()

    # Query by keyword
    print("Keyword search: 'curl buffer overflow'...")
    cves = client.query_by_keyword("curl buffer overflow")
    print(f"  Found {len(cves)} CVEs")
    for c in cves[:3]:
        print(f"    - {c.id}: {c.description[:60]}...")


if __name__ == "__main__":
    demo()
