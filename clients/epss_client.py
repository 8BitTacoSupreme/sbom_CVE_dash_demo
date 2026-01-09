"""
EPSS (Exploit Prediction Scoring System) Client

Queries the FIRST EPSS API for exploit probability scores.
EPSS predicts the likelihood a CVE will be exploited in the next 30 days.

API Documentation: https://www.first.org/epss/api
"""

import requests
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class EPSSData:
    """EPSS score data for a CVE."""
    cve_id: str
    score: float        # 0.0 to 1.0 (probability of exploitation)
    percentile: float   # 0.0 to 100.0 (relative ranking)
    date: str           # YYYY-MM-DD when score was calculated


class EPSSClient:
    """
    Client for the FIRST EPSS API.

    EPSS (Exploit Prediction Scoring System) provides probability scores
    indicating the likelihood a CVE will be exploited in the wild.

    - Score 0.0-1.0: Probability of exploitation in next 30 days
    - Percentile 0-100: How this CVE ranks compared to all others

    Example:
        EPSS=0.97 means 97% chance of exploitation in next 30 days
        Percentile=99.9 means more likely to be exploited than 99.9% of CVEs
    """

    BASE_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, cache_ttl_hours: int = 24, timeout: int = 30):
        """
        Initialize EPSS client.

        Args:
            cache_ttl_hours: How long to cache EPSS scores (default 24h)
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self._cache: Dict[str, EPSSData] = {}
        self._cache_time: Optional[datetime] = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'flox-sca/2.0',
            'Accept': 'application/json'
        })

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid."""
        if self._cache_time is None:
            return False
        return datetime.now() - self._cache_time < self.cache_ttl

    def _clear_cache_if_expired(self):
        """Clear cache if TTL has expired."""
        if not self._is_cache_valid():
            self._cache.clear()
            self._cache_time = None

    def get_epss(self, cve_id: str) -> Optional[EPSSData]:
        """
        Get EPSS score for a single CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            EPSSData with score and percentile, or None if not found
        """
        if not cve_id or not cve_id.startswith('CVE-'):
            return None

        self._clear_cache_if_expired()

        # Check cache
        if cve_id in self._cache:
            return self._cache[cve_id]

        # Query API
        try:
            response = self.session.get(
                self.BASE_URL,
                params={'cve': cve_id},
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            if data.get('data'):
                entry = data['data'][0]
                epss_data = EPSSData(
                    cve_id=entry.get('cve', cve_id),
                    score=float(entry.get('epss', 0)),
                    percentile=float(entry.get('percentile', 0)) * 100,  # Convert to 0-100
                    date=entry.get('date', '')
                )
                self._cache[cve_id] = epss_data
                if self._cache_time is None:
                    self._cache_time = datetime.now()
                return epss_data

            return None

        except requests.RequestException as e:
            logger.warning(f"EPSS query failed for {cve_id}: {e}")
            return None
        except (ValueError, KeyError) as e:
            logger.warning(f"EPSS parse error for {cve_id}: {e}")
            return None

    def get_batch(self, cve_ids: List[str]) -> Dict[str, EPSSData]:
        """
        Batch query EPSS scores for multiple CVEs.

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dict mapping CVE ID to EPSSData
        """
        if not cve_ids:
            return {}

        self._clear_cache_if_expired()

        # Filter to only CVE-format IDs not in cache
        uncached = [
            cve for cve in cve_ids
            if cve.startswith('CVE-') and cve not in self._cache
        ]

        # Return cached results if all are cached
        if not uncached:
            return {cve: self._cache[cve] for cve in cve_ids if cve in self._cache}

        # Query API with comma-separated CVE list
        try:
            response = self.session.get(
                self.BASE_URL,
                params={'cve': ','.join(uncached[:100])},  # Limit batch size
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            # Parse and cache results
            for entry in data.get('data', []):
                cve_id = entry.get('cve')
                if cve_id:
                    epss_data = EPSSData(
                        cve_id=cve_id,
                        score=float(entry.get('epss', 0)),
                        percentile=float(entry.get('percentile', 0)) * 100,
                        date=entry.get('date', '')
                    )
                    self._cache[cve_id] = epss_data

            if self._cache_time is None:
                self._cache_time = datetime.now()

        except requests.RequestException as e:
            logger.warning(f"EPSS batch query failed: {e}")

        # Return results (cached + newly fetched)
        return {cve: self._cache[cve] for cve in cve_ids if cve in self._cache}

    def get_high_risk_cves(self, threshold: float = 0.4) -> List[EPSSData]:
        """
        Get all CVEs above a certain EPSS threshold from cache.

        Args:
            threshold: Minimum EPSS score (default 0.4 = 40%)

        Returns:
            List of EPSSData for high-risk CVEs
        """
        return [
            data for data in self._cache.values()
            if data.score >= threshold
        ]


def demo():
    """Demonstrate EPSS client functionality."""
    client = EPSSClient()

    print("=== EPSS Client Demo ===\n")

    # Query known high-risk CVEs
    test_cves = [
        "CVE-2021-44228",  # Log4Shell - should be very high
        "CVE-2024-3400",   # PAN-OS - recent high-risk
        "CVE-2023-29491",  # ncurses
        "CVE-2021-3156",   # sudo heap overflow
    ]

    print("Single queries:")
    for cve in test_cves:
        data = client.get_epss(cve)
        if data:
            print(f"  {cve}: EPSS={data.score:.1%}, Percentile={data.percentile:.1f}")
        else:
            print(f"  {cve}: No EPSS data")

    print("\nBatch query:")
    batch_results = client.get_batch(test_cves)
    for cve, data in batch_results.items():
        risk_level = "HIGH" if data.score > 0.4 else "MEDIUM" if data.score > 0.1 else "LOW"
        print(f"  {cve}: {data.score:.1%} [{risk_level}]")


if __name__ == "__main__":
    demo()
