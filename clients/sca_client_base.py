"""
Base class for SCA Tool API Clients

Provides a unified interface for interacting with external SCA tools.
All tool-specific clients inherit from this base class.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class SCAVulnerability:
    """Normalized vulnerability finding from any SCA tool."""
    cve_id: str
    source_id: str  # Tool-specific ID (e.g., SNYK-JAVA-...)
    package: str
    version: str
    purl: Optional[str]
    severity: str  # critical, high, medium, low
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None  # Only some tools provide this
    remediation: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class SCAResponse:
    """Normalized response from any SCA tool scan."""
    source: str  # snyk|blackduck|sonar|sonatype
    scan_id: str
    status: str  # completed|failed
    latency_ms: int
    total_packages: int
    packages_with_issues: int
    critical: int
    high: int
    medium: int
    low: int
    vulnerabilities: List[SCAVulnerability]
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            'source': self.source,
            'scan_id': self.scan_id,
            'status': self.status,
            'latency_ms': self.latency_ms,
            'error_message': self.error_message,
            'results': {
                'summary': {
                    'total_packages': self.total_packages,
                    'packages_with_issues': self.packages_with_issues,
                    'critical': self.critical,
                    'high': self.high,
                    'medium': self.medium,
                    'low': self.low,
                },
                'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
            }
        }
        return result


class SCAClientBase(ABC):
    """
    Abstract base class for SCA tool API clients.

    All SCA tool clients must implement these methods to provide
    a unified interface for SBOM scanning and vulnerability retrieval.
    """

    def __init__(self, timeout: int = 300, poll_interval: int = 5):
        """
        Initialize the SCA client.

        Args:
            timeout: Maximum time to wait for scan completion (seconds)
            poll_interval: Time between status polls for async APIs (seconds)
        """
        self.timeout = timeout
        self.poll_interval = poll_interval

    @property
    @abstractmethod
    def source_name(self) -> str:
        """
        Return the source identifier for this tool.

        Returns:
            One of: snyk, blackduck, sonar, sonatype
        """
        pass

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """
        Check if required environment variables are set.

        Returns:
            True if all required credentials are available
        """
        pass

    @abstractmethod
    async def submit_sbom(self, sbom: dict) -> str:
        """
        Submit an SBOM for vulnerability scanning.

        Args:
            sbom: The SBOM payload (with packages list)

        Returns:
            Job/scan ID for tracking the submission

        Raises:
            ValueError: If SBOM format is invalid
            ConnectionError: If API is unreachable
            PermissionError: If authentication fails
        """
        pass

    @abstractmethod
    async def poll_status(self, job_id: str) -> str:
        """
        Poll the status of a submitted scan.

        Args:
            job_id: The job ID returned from submit_sbom

        Returns:
            Status string: pending|in_progress|completed|failed
        """
        pass

    @abstractmethod
    async def get_results(self, job_id: str) -> dict:
        """
        Retrieve vulnerability results for a completed scan.

        Args:
            job_id: The job ID returned from submit_sbom

        Returns:
            Raw API response (tool-specific format)

        Raises:
            ValueError: If job_id is invalid or scan not complete
        """
        pass

    @abstractmethod
    def normalize_response(self, raw: dict, latency_ms: int) -> SCAResponse:
        """
        Normalize a raw API response to the common SCAResponse schema.

        Args:
            raw: Raw API response from get_results
            latency_ms: Time taken for the scan (milliseconds)

        Returns:
            Normalized SCAResponse object
        """
        pass

    async def scan_sbom(self, sbom: dict) -> SCAResponse:
        """
        High-level method to submit SBOM and wait for results.

        This is a convenience method that handles the full scan lifecycle:
        1. Submit SBOM
        2. Poll for completion
        3. Retrieve and normalize results

        Args:
            sbom: The SBOM payload

        Returns:
            Normalized SCAResponse with vulnerability findings
        """
        import asyncio
        import time

        if not self.is_configured:
            return SCAResponse(
                source=self.source_name,
                scan_id="not-configured",
                status="failed",
                latency_ms=0,
                total_packages=0,
                packages_with_issues=0,
                critical=0,
                high=0,
                medium=0,
                low=0,
                vulnerabilities=[],
                error_message=f"{self.source_name} credentials not configured"
            )

        start_time = time.time()
        elapsed_ms = 0

        try:
            # Submit SBOM
            logger.info(f"[{self.source_name}] Submitting SBOM...")
            job_id = await self.submit_sbom(sbom)
            logger.info(f"[{self.source_name}] Job ID: {job_id}")

            # Poll for completion
            deadline = start_time + self.timeout
            while time.time() < deadline:
                status = await self.poll_status(job_id)
                logger.debug(f"[{self.source_name}] Status: {status}")

                if status == "completed":
                    break
                elif status == "failed":
                    elapsed_ms = int((time.time() - start_time) * 1000)
                    return SCAResponse(
                        source=self.source_name,
                        scan_id=job_id,
                        status="failed",
                        latency_ms=elapsed_ms,
                        total_packages=0,
                        packages_with_issues=0,
                        critical=0,
                        high=0,
                        medium=0,
                        low=0,
                        vulnerabilities=[],
                        error_message="Scan failed on remote server"
                    )

                await asyncio.sleep(self.poll_interval)
            else:
                # Timeout reached
                elapsed_ms = int((time.time() - start_time) * 1000)
                return SCAResponse(
                    source=self.source_name,
                    scan_id=job_id,
                    status="failed",
                    latency_ms=elapsed_ms,
                    total_packages=0,
                    packages_with_issues=0,
                    critical=0,
                    high=0,
                    medium=0,
                    low=0,
                    vulnerabilities=[],
                    error_message=f"Scan timed out after {self.timeout}s"
                )

            # Get results
            elapsed_ms = int((time.time() - start_time) * 1000)
            raw_results = await self.get_results(job_id)
            return self.normalize_response(raw_results, elapsed_ms)

        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            logger.error(f"[{self.source_name}] Error: {e}")
            return SCAResponse(
                source=self.source_name,
                scan_id="error",
                status="failed",
                latency_ms=elapsed_ms,
                total_packages=0,
                packages_with_issues=0,
                critical=0,
                high=0,
                medium=0,
                low=0,
                vulnerabilities=[],
                error_message=str(e)
            )

    def _count_severity(self, vulnerabilities: List[SCAVulnerability]) -> dict:
        """Helper to count vulnerabilities by severity."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            sev = vuln.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts
