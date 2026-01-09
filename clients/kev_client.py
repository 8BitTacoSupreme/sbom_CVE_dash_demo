"""
CISA KEV (Known Exploited Vulnerabilities) Client

CISA maintains a catalog of vulnerabilities that are being actively exploited.
This is critical for prioritization - a CVE on the KEV list needs immediate attention.

Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import requests
from dataclasses import dataclass
from typing import Dict, Optional, List
from datetime import datetime, date
import logging
import os

logger = logging.getLogger(__name__)


@dataclass
class KEVEntry:
    """CISA KEV catalog entry."""
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    short_description: str
    required_action: str
    due_date: date
    known_ransomware_use: bool
    notes: str = ""

    def to_dict(self) -> Dict:
        return {
            'cve_id': self.cve_id,
            'vendor_project': self.vendor_project,
            'product': self.product,
            'vulnerability_name': self.vulnerability_name,
            'date_added': self.date_added.isoformat() if self.date_added else None,
            'short_description': self.short_description,
            'required_action': self.required_action,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'known_ransomware_use': self.known_ransomware_use,
            'notes': self.notes,
        }


class KEVClient:
    """
    Client for CISA Known Exploited Vulnerabilities catalog.

    The KEV catalog is a list of CVEs that are known to be actively exploited
    in the wild. This is the highest priority signal for vulnerability remediation.
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, cache_ttl_hours: int = 24):
        """
        Initialize KEV client.

        Args:
            cache_ttl_hours: How long to cache the KEV list (default 24h)
        """
        self.cache_ttl_hours = cache_ttl_hours
        self._cache: Dict[str, KEVEntry] = {}
        self._cache_timestamp: Optional[datetime] = None
        self._catalog_version: Optional[str] = None

    def fetch_kev_list(self, force_refresh: bool = False) -> Dict[str, KEVEntry]:
        """
        Fetch the KEV catalog from CISA.

        Args:
            force_refresh: If True, bypass cache and fetch fresh data

        Returns:
            Dict mapping CVE ID to KEVEntry
        """
        # Check cache
        if not force_refresh and self._is_cache_valid():
            return self._cache

        try:
            logger.info("Fetching CISA KEV catalog...")
            response = requests.get(self.KEV_URL, timeout=30)
            response.raise_for_status()
            data = response.json()

            self._catalog_version = data.get('catalogVersion')
            self._cache = {}

            for vuln in data.get('vulnerabilities', []):
                try:
                    entry = self._parse_entry(vuln)
                    self._cache[entry.cve_id] = entry
                except Exception as e:
                    logger.warning(f"Failed to parse KEV entry: {e}")
                    continue

            self._cache_timestamp = datetime.utcnow()
            logger.info(f"Loaded {len(self._cache)} KEV entries (catalog v{self._catalog_version})")

            return self._cache

        except requests.RequestException as e:
            logger.error(f"Failed to fetch KEV catalog: {e}")
            # Return cached data if available, even if stale
            return self._cache

    def is_actively_exploited(self, cve_id: str) -> bool:
        """
        Check if a CVE is on the KEV list (actively exploited).

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            True if CVE is actively exploited
        """
        self.fetch_kev_list()  # Ensure cache is populated
        return cve_id.upper() in self._cache

    def get_kev_details(self, cve_id: str) -> Optional[KEVEntry]:
        """
        Get KEV entry details for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            KEVEntry if on KEV list, None otherwise
        """
        self.fetch_kev_list()
        return self._cache.get(cve_id.upper())

    def get_ransomware_cves(self) -> List[KEVEntry]:
        """
        Get all CVEs known to be used in ransomware campaigns.

        Returns:
            List of KEV entries with ransomware association
        """
        self.fetch_kev_list()
        return [e for e in self._cache.values() if e.known_ransomware_use]

    def get_recent_additions(self, days: int = 7) -> List[KEVEntry]:
        """
        Get CVEs added to KEV in the last N days.

        Args:
            days: Number of days to look back

        Returns:
            List of recently added KEV entries
        """
        self.fetch_kev_list()
        cutoff = date.today().toordinal() - days
        return [
            e for e in self._cache.values()
            if e.date_added and e.date_added.toordinal() >= cutoff
        ]

    def enrich_cve(self, cve: Dict) -> Dict:
        """
        Enrich a CVE record with KEV data.

        Args:
            cve: CVE record dict with 'cve_id' field

        Returns:
            CVE dict with added KEV fields
        """
        cve_id = cve.get('cve_id', '')
        kev_entry = self.get_kev_details(cve_id)

        cve['cisa_kev'] = kev_entry is not None
        if kev_entry:
            cve['kev_date_added'] = kev_entry.date_added.isoformat() if kev_entry.date_added else None
            cve['kev_ransomware'] = kev_entry.known_ransomware_use
            cve['kev_due_date'] = kev_entry.due_date.isoformat() if kev_entry.due_date else None

        return cve

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid."""
        if not self._cache or not self._cache_timestamp:
            return False
        age_hours = (datetime.utcnow() - self._cache_timestamp).total_seconds() / 3600
        return age_hours < self.cache_ttl_hours

    def _parse_entry(self, data: Dict) -> KEVEntry:
        """Parse raw JSON into KEVEntry."""
        return KEVEntry(
            cve_id=data.get('cveID', '').upper(),
            vendor_project=data.get('vendorProject', ''),
            product=data.get('product', ''),
            vulnerability_name=data.get('vulnerabilityName', ''),
            date_added=self._parse_date(data.get('dateAdded')),
            short_description=data.get('shortDescription', ''),
            required_action=data.get('requiredAction', ''),
            due_date=self._parse_date(data.get('dueDate')),
            known_ransomware_use=data.get('knownRansomwareCampaignUse', 'Unknown') == 'Known',
            notes=data.get('notes', ''),
        )

    def _parse_date(self, date_str: Optional[str]) -> Optional[date]:
        """Parse date string to date object."""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return None

    @property
    def catalog_version(self) -> Optional[str]:
        """Get the catalog version."""
        return self._catalog_version

    @property
    def entry_count(self) -> int:
        """Get number of entries in cache."""
        return len(self._cache)


def demo():
    """Demonstrate KEV client functionality."""
    client = KEVClient()

    print("=== CISA KEV Client Demo ===\n")

    # Fetch catalog
    print("Fetching KEV catalog...")
    entries = client.fetch_kev_list()
    print(f"Loaded {len(entries)} known exploited vulnerabilities")
    print(f"Catalog version: {client.catalog_version}\n")

    # Check specific CVEs
    test_cves = [
        "CVE-2021-44228",  # Log4Shell - definitely on KEV
        "CVE-2024-3400",   # Palo Alto PAN-OS - recent
        "CVE-2099-99999",  # Fake - not on KEV
    ]

    print("Checking specific CVEs:")
    for cve_id in test_cves:
        is_kev = client.is_actively_exploited(cve_id)
        details = client.get_kev_details(cve_id)
        if is_kev:
            print(f"  🔴 {cve_id}: ACTIVELY EXPLOITED")
            if details:
                print(f"      Added: {details.date_added}")
                print(f"      Ransomware: {'Yes' if details.known_ransomware_use else 'No'}")
                print(f"      {details.short_description[:60]}...")
        else:
            print(f"  ⚪ {cve_id}: Not on KEV list")
    print()

    # Show ransomware CVEs
    ransomware = client.get_ransomware_cves()
    print(f"CVEs with known ransomware use: {len(ransomware)}")
    for entry in ransomware[:3]:
        print(f"  - {entry.cve_id}: {entry.vulnerability_name[:50]}...")
    print()

    # Show recent additions
    recent = client.get_recent_additions(days=30)
    print(f"CVEs added in last 30 days: {len(recent)}")
    for entry in recent[:3]:
        print(f"  - {entry.cve_id} ({entry.date_added}): {entry.product}")


if __name__ == "__main__":
    demo()
