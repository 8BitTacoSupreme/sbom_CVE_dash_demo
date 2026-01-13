"""
SCA API Clients

Clients for querying live vulnerability databases:
- OSV (Open Source Vulnerabilities) - PURL-based queries
- NVD (National Vulnerability Database) - CPE-based queries
- KEV (CISA Known Exploited Vulnerabilities) - Active exploitation status

External SCA Tool Clients:
- Snyk - Developer-focused vulnerability scanning
- Black Duck - Enterprise SCA with BDSA advisories (coming soon)
- SonarQube - Integrated code + dependency analysis
- Sonatype Nexus IQ - Policy-driven vulnerability management (coming soon)
- FOSSA - License compliance and vulnerability scanning
"""

from .osv_client import OSVClient
from .nvd_client import NVDClient
from .kev_client import KEVClient

# External SCA tool clients
from .sca_client_base import SCAClientBase, SCAResponse, SCAVulnerability
from .snyk_client import SnykClient
from .blackduck_client import BlackDuckClient
from .sonarqube_client import SonarQubeClient
from .sonatype_client import SonatypeClient
from .fossa_client import FOSSAClient

__all__ = [
    # Vulnerability database clients
    'OSVClient',
    'NVDClient',
    'KEVClient',
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
