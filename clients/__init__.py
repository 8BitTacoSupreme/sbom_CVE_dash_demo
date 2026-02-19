"""
SCA API Clients

Clients for querying live vulnerability databases:
- OSV (Open Source Vulnerabilities) - PURL-based queries
- NVD (National Vulnerability Database) - CPE-based queries
- KEV (CISA Known Exploited Vulnerabilities) - Active exploitation status
- EPSS (Exploit Prediction Scoring System) - Exploitation probability scores
- GHSA (GitHub Security Advisories) - GitHub-curated vulnerability data

Vulnerability Management:
- DefectDojo - Remediation workflows, SLA tracking, CycloneDX import

OpenSSF Standards:
- Scorecard - Upstream repository health scores (0-10)

External SCA Tool Clients:
- Snyk - Developer-focused vulnerability scanning
- Black Duck - Enterprise SCA with BDSA advisories (coming soon)
- SonarQube - Integrated code + dependency analysis
- Sonatype Nexus IQ - Policy-driven vulnerability management (coming soon)
- FOSSA - License compliance and vulnerability scanning
"""

# Core clients (only need requests - always available)
from .osv_client import OSVClient
from .nvd_client import NVDClient
from .kev_client import KEVClient
from .epss_client import EPSSClient
from .ghsa_client import GHSAClient

# Vulnerability management and OpenSSF clients
from .defectdojo_client import DefectDojoClient
from .scorecard_client import ScorecardClient

# Base class for external SCA clients
from .sca_client_base import SCAClientBase, SCAResponse, SCAVulnerability

# External SCA tool clients (may need optional dependencies like aiohttp)
# Import with graceful fallback so missing deps don't break core functionality
SnykClient = None
BlackDuckClient = None
SonarQubeClient = None
SonatypeClient = None
FOSSAClient = None

try:
    from .snyk_client import SnykClient
except ImportError:
    pass  # aiohttp not available

try:
    from .blackduck_client import BlackDuckClient
except ImportError:
    pass

try:
    from .sonarqube_client import SonarQubeClient
except ImportError:
    pass

try:
    from .sonatype_client import SonatypeClient
except ImportError:
    pass

try:
    from .fossa_client import FOSSAClient
except ImportError:
    pass

__all__ = [
    # Vulnerability database clients
    'OSVClient',
    'NVDClient',
    'KEVClient',
    'EPSSClient',
    'GHSAClient',
    # Vulnerability management and OpenSSF
    'DefectDojoClient',
    'ScorecardClient',
    # External SCA tool clients
    'SCAClientBase',
    'SCAResponse',
    'SCAVulnerability',
    'SnykClient',
    'BlackDuckClient',
    'SonarQubeClient',
    'SonatypeClient',
    'FOSSAClient',
]
