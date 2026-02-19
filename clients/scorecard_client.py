"""
OpenSSF Scorecard API Client

Queries the OpenSSF Scorecard REST API for upstream repository health scores.
Scorecard measures maintenance quality (0-10) across multiple dimensions:
  - Code-Review, Maintained, Vulnerabilities, Branch-Protection, etc.

A CVE in a poorly-maintained project (score 2/10) is higher risk than
one in a well-maintained project (9/10). This enriches risk tiers.

API Documentation: https://api.scorecard.dev/
"""

import requests
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ScorecardCheck:
    """Individual Scorecard check result."""
    name: str
    score: int  # 0-10, -1 means not applicable
    reason: str = ""
    details: List[str] = field(default_factory=list)


@dataclass
class ScorecardResult:
    """Scorecard result for a repository."""
    repo: str  # e.g., "github.com/apache/logging-log4j2"
    score: float  # Aggregate score 0-10
    date: Optional[str] = None
    checks: List[ScorecardCheck] = field(default_factory=list)
    commit: Optional[str] = None

    @property
    def maintenance_score(self) -> Optional[int]:
        """Get the 'Maintained' check score specifically."""
        for c in self.checks:
            if c.name == 'Maintained':
                return c.score
        return None

    @property
    def vulnerability_score(self) -> Optional[int]:
        """Get the 'Vulnerabilities' check score."""
        for c in self.checks:
            if c.name == 'Vulnerabilities':
                return c.score
        return None

    def to_dict(self) -> Dict:
        return {
            'repo': self.repo,
            'score': self.score,
            'date': self.date,
            'commit': self.commit,
            'maintenance_score': self.maintenance_score,
            'vulnerability_score': self.vulnerability_score,
            'checks': {c.name: c.score for c in self.checks},
        }


class ScorecardClient:
    """
    Client for the OpenSSF Scorecard REST API.

    Queries pre-computed Scorecard results for GitHub repositories.
    Results are cached by the Scorecard service and typically refresh weekly.
    """

    BASE_URL = "https://api.scorecard.dev"

    # Known PURL-to-GitHub repo mappings for common packages
    PURL_REPO_MAP = {
        'pkg:maven/org.apache.logging.log4j': 'github.com/apache/logging-log4j2',
        'pkg:npm/express': 'github.com/expressjs/express',
        'pkg:npm/lodash': 'github.com/lodash/lodash',
        'pkg:pypi/django': 'github.com/django/django',
        'pkg:pypi/flask': 'github.com/pallets/flask',
        'pkg:pypi/requests': 'github.com/psf/requests',
        'pkg:golang/golang.org/x/crypto': 'github.com/golang/crypto',
        'pkg:cargo/serde': 'github.com/serde-rs/serde',
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'User-Agent': 'flox-sca/2.0',
        })
        # In-memory cache: repo -> ScorecardResult
        self._cache: Dict[str, ScorecardResult] = {}

    def get_score(self, repo: str) -> Optional[ScorecardResult]:
        """
        Get Scorecard result for a GitHub repository.

        Args:
            repo: Repository in format "github.com/owner/repo"

        Returns:
            ScorecardResult or None if not found/scored
        """
        if repo in self._cache:
            return self._cache[repo]

        # Normalize repo format
        repo = self._normalize_repo(repo)
        if not repo:
            return None

        try:
            # Use the projects endpoint: GET /projects/{platform}/{org}/{repo}
            parts = repo.split('/')
            if len(parts) != 3:
                logger.warning(f"Invalid repo format: {repo}")
                return None

            platform, org, name = parts
            resp = self.session.get(
                f"{self.BASE_URL}/projects/{platform}/{org}/{name}",
                timeout=self.timeout
            )

            if resp.status_code == 404:
                logger.debug(f"Scorecard not available for {repo}")
                return None

            resp.raise_for_status()
            data = resp.json()
            result = self._parse_result(data)
            self._cache[repo] = result
            return result

        except requests.RequestException as e:
            logger.error(f"Scorecard query failed for {repo}: {e}")
            return None

    def get_score_by_purl(self, purl: str) -> Optional[ScorecardResult]:
        """
        Get Scorecard result for a package identified by PURL.

        Attempts to resolve the PURL to a GitHub repository using
        known mappings and heuristics.

        Args:
            purl: Package URL (e.g., "pkg:npm/express@4.18.2")

        Returns:
            ScorecardResult or None if repo cannot be resolved
        """
        repo = self.purl_to_repo(purl)
        if repo:
            return self.get_score(repo)
        return None

    def purl_to_repo(self, purl: str) -> Optional[str]:
        """
        Resolve a PURL to a GitHub repository.

        Uses static mappings and heuristics. Not exhaustive — returns
        None for packages with unknown repos.
        """
        if not purl:
            return None

        # Strip version and qualifiers
        base_purl = purl.split('?')[0]
        if '@' in base_purl:
            base_purl = base_purl.rsplit('@', 1)[0]

        # Check static map
        if base_purl in self.PURL_REPO_MAP:
            return self.PURL_REPO_MAP[base_purl]

        # Try prefix match (e.g., pkg:maven/org.apache.logging.log4j/log4j-core)
        for prefix, repo in self.PURL_REPO_MAP.items():
            if base_purl.startswith(prefix):
                return repo

        # Heuristic: GitHub PURLs map directly
        # pkg:github/owner/repo -> github.com/owner/repo
        if base_purl.startswith('pkg:github/'):
            path = base_purl.replace('pkg:github/', '')
            return f"github.com/{path}"

        return None

    def _normalize_repo(self, repo: str) -> Optional[str]:
        """Normalize repository string to github.com/owner/repo format."""
        if not repo:
            return None
        # Strip https:// prefix
        repo = re.sub(r'^https?://', '', repo)
        # Ensure it starts with github.com
        if not repo.startswith('github.com/'):
            return None
        # Strip trailing .git
        repo = repo.rstrip('/').removesuffix('.git')
        return repo

    def _parse_result(self, data: Dict) -> ScorecardResult:
        """Parse Scorecard API response."""
        repo_info = data.get('repo', {})
        scorecard = data.get('scorecard', {})
        score_data = data.get('score', 0)

        checks = []
        for check_data in data.get('checks', []):
            checks.append(ScorecardCheck(
                name=check_data.get('name', ''),
                score=check_data.get('score', -1),
                reason=check_data.get('reason', ''),
                details=check_data.get('details', []),
            ))

        return ScorecardResult(
            repo=repo_info.get('name', ''),
            score=float(score_data),
            date=data.get('date'),
            checks=checks,
            commit=repo_info.get('commit'),
        )


def demo():
    """Demonstrate Scorecard client functionality."""
    client = ScorecardClient()

    print("=== OpenSSF Scorecard Client Demo ===\n")

    test_repos = [
        "github.com/apache/logging-log4j2",
        "github.com/expressjs/express",
        "github.com/django/django",
    ]

    for repo in test_repos:
        print(f"Querying Scorecard for {repo}...")
        result = client.get_score(repo)
        if result:
            print(f"  Aggregate score: {result.score}/10")
            print(f"  Maintenance: {result.maintenance_score}/10")
            print(f"  Vulnerabilities: {result.vulnerability_score}/10")
            if result.checks:
                print(f"  Checks: {len(result.checks)}")
                for c in sorted(result.checks, key=lambda x: x.score):
                    marker = "!" if c.score <= 3 else " "
                    print(f"    {marker} {c.name}: {c.score}/10")
        else:
            print(f"  Not available")
        print()

    # Test PURL resolution
    print("PURL -> Repo resolution:")
    test_purls = [
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        "pkg:npm/express@4.18.2",
        "pkg:nix/openssl@3.0.13",
    ]
    for purl in test_purls:
        repo = client.purl_to_repo(purl)
        print(f"  {purl} -> {repo or 'unknown'}")


if __name__ == "__main__":
    demo()
