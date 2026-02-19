"""
DefectDojo API Client

Integrates with DefectDojo v2 API for vulnerability management workflows.
Imports CycloneDX SBOMs with embedded vulnerabilities, manages products/engagements,
and queries findings.

API Documentation: https://demo.defectdojo.org/api/v2/doc/
"""

import requests
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class DefectDojoFinding:
    """A DefectDojo finding (vulnerability instance)."""
    id: int
    title: str
    severity: str
    cve: Optional[str] = None
    cwe: Optional[int] = None
    description: str = ""
    component_name: Optional[str] = None
    component_version: Optional[str] = None
    epss_score: Optional[float] = None
    active: bool = True
    verified: bool = False
    false_p: bool = False
    out_of_scope: bool = False
    risk_accepted: bool = False

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'title': self.title,
            'severity': self.severity,
            'cve': self.cve,
            'cwe': self.cwe,
            'description': self.description,
            'component_name': self.component_name,
            'component_version': self.component_version,
            'epss_score': self.epss_score,
            'active': self.active,
            'verified': self.verified,
            'false_p': self.false_p,
            'out_of_scope': self.out_of_scope,
            'risk_accepted': self.risk_accepted,
        }


@dataclass
class ReimportResult:
    """Result of a reimport-scan API call."""
    test_id: int
    finding_count: int
    created: int
    closed: int
    reactivated: int
    left_untouched: int
    scan_type: str = "CycloneDX Scan"

    def to_dict(self) -> Dict:
        return {
            'test_id': self.test_id,
            'finding_count': self.finding_count,
            'created': self.created,
            'closed': self.closed,
            'reactivated': self.reactivated,
            'left_untouched': self.left_untouched,
            'scan_type': self.scan_type,
        }


class DefectDojoClient:
    """
    Client for the DefectDojo v2 API.

    Handles CycloneDX SBOM imports, product/engagement lifecycle,
    and finding queries for vulnerability management workflows.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8443",
        api_token: Optional[str] = None,
        product_type_name: str = "Flox SCA",
        timeout: int = 60,
        verify_ssl: bool = True
    ):
        self.base_url = base_url.rstrip('/')
        self.api_url = f"{self.base_url}/api/v2"
        self.api_token = api_token
        self.product_type_name = product_type_name
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        if api_token:
            self.session.headers.update({
                'Authorization': f'Token {api_token}',
                'Accept': 'application/json',
            })
        # Cache for product type / product IDs
        self._product_type_id: Optional[int] = None
        self._product_cache: Dict[str, int] = {}  # environment_id -> product_id
        self._engagement_cache: Dict[int, int] = {}  # product_id -> engagement_id

    def health_check(self) -> bool:
        """Check if DefectDojo API is reachable."""
        try:
            resp = self.session.get(
                f"{self.api_url}/product_types/",
                params={"limit": 1},
                timeout=10,
                verify=self.verify_ssl
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    # -------------------------------------------------------------------------
    # Product Type management
    # -------------------------------------------------------------------------

    def get_or_create_product_type(self) -> int:
        """Get or create the 'Flox SCA' product type."""
        if self._product_type_id:
            return self._product_type_id

        # Search for existing
        resp = self.session.get(
            f"{self.api_url}/product_types/",
            params={"name": self.product_type_name},
            timeout=self.timeout,
            verify=self.verify_ssl
        )
        resp.raise_for_status()
        results = resp.json().get('results', [])
        if results:
            self._product_type_id = results[0]['id']
            return self._product_type_id

        # Create new
        resp = self.session.post(
            f"{self.api_url}/product_types/",
            json={"name": self.product_type_name},
            timeout=self.timeout,
            verify=self.verify_ssl
        )
        resp.raise_for_status()
        self._product_type_id = resp.json()['id']
        logger.info(f"Created product type '{self.product_type_name}' (id={self._product_type_id})")
        return self._product_type_id

    # -------------------------------------------------------------------------
    # Product management (1 product per environment_id)
    # -------------------------------------------------------------------------

    def get_or_create_product(self, environment_id: str) -> int:
        """Get or create a DD product for the given environment."""
        if environment_id in self._product_cache:
            return self._product_cache[environment_id]

        product_type_id = self.get_or_create_product_type()

        # Search existing
        resp = self.session.get(
            f"{self.api_url}/products/",
            params={"name": environment_id, "prod_type": product_type_id},
            timeout=self.timeout,
            verify=self.verify_ssl
        )
        resp.raise_for_status()
        results = resp.json().get('results', [])
        if results:
            pid = results[0]['id']
            self._product_cache[environment_id] = pid
            return pid

        # Create
        resp = self.session.post(
            f"{self.api_url}/products/",
            json={
                "name": environment_id,
                "description": f"Flox SCA environment: {environment_id}",
                "prod_type": product_type_id,
            },
            timeout=self.timeout,
            verify=self.verify_ssl
        )
        resp.raise_for_status()
        pid = resp.json()['id']
        self._product_cache[environment_id] = pid
        logger.info(f"Created product '{environment_id}' (id={pid})")
        return pid

    # -------------------------------------------------------------------------
    # Engagement management (1 engagement per product for continuous monitoring)
    # -------------------------------------------------------------------------

    def get_or_create_engagement(self, product_id: int) -> int:
        """Get or create a 'Continuous Monitoring' engagement for the product."""
        if product_id in self._engagement_cache:
            return self._engagement_cache[product_id]

        engagement_name = "Continuous Monitoring"

        resp = self.session.get(
            f"{self.api_url}/engagements/",
            params={"product": product_id, "name": engagement_name},
            timeout=self.timeout,
            verify=self.verify_ssl
        )
        resp.raise_for_status()
        results = resp.json().get('results', [])
        if results:
            eid = results[0]['id']
            self._engagement_cache[product_id] = eid
            return eid

        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        resp = self.session.post(
            f"{self.api_url}/engagements/",
            json={
                "name": engagement_name,
                "product": product_id,
                "target_start": today,
                "target_end": "2099-12-31",
                "engagement_type": "CI/CD",
                "status": "In Progress",
                "deduplication_on_engagement": True,
            },
            timeout=self.timeout,
            verify=self.verify_ssl
        )
        resp.raise_for_status()
        eid = resp.json()['id']
        self._engagement_cache[product_id] = eid
        logger.info(f"Created engagement '{engagement_name}' for product {product_id} (id={eid})")
        return eid

    # -------------------------------------------------------------------------
    # CycloneDX SBOM import (reimport for dedup)
    # -------------------------------------------------------------------------

    def reimport_scan(
        self,
        environment_id: str,
        cyclonedx_sbom: Dict[str, Any],
        scan_type: str = "CycloneDX Scan",
        auto_create_context: bool = True,
    ) -> Optional[ReimportResult]:
        """
        Import a CycloneDX SBOM with embedded vulnerabilities to DefectDojo.

        Uses the reimport-scan endpoint for deduplication — re-importing the
        same SBOM updates existing findings rather than creating duplicates.

        Args:
            environment_id: Maps to DD Product name
            cyclonedx_sbom: CycloneDX 1.4+ SBOM dict with vulnerabilities array
            scan_type: DefectDojo scan type (default: "CycloneDX Scan")
            auto_create_context: Let DD auto-create product/engagement if needed

        Returns:
            ReimportResult with counts, or None on failure
        """
        sbom_json = json.dumps(cyclonedx_sbom)

        if auto_create_context:
            # Use auto_create_context=true — DD handles product/engagement creation
            data = {
                'scan_type': scan_type,
                'auto_create_context': 'true',
                'product_type_name': self.product_type_name,
                'product_name': environment_id,
                'engagement_name': 'Continuous Monitoring',
                'active': 'true',
                'verified': 'false',
                'close_old_findings': 'true',
                'deduplication_on_engagement': 'true',
            }
        else:
            product_id = self.get_or_create_product(environment_id)
            engagement_id = self.get_or_create_engagement(product_id)
            data = {
                'scan_type': scan_type,
                'engagement': str(engagement_id),
                'active': 'true',
                'verified': 'false',
                'close_old_findings': 'true',
                'deduplication_on_engagement': 'true',
            }

        try:
            resp = self.session.post(
                f"{self.api_url}/reimport-scan/",
                data=data,
                files={'file': ('sbom.json', sbom_json, 'application/json')},
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            resp.raise_for_status()
            result = resp.json()

            return ReimportResult(
                test_id=result.get('test', 0),
                finding_count=result.get('finding_count', 0),
                created=result.get('created', 0),
                closed=result.get('closed', 0),
                reactivated=result.get('reactivated', 0),
                left_untouched=result.get('left_untouched', 0),
                scan_type=scan_type,
            )
        except requests.RequestException as e:
            logger.error(f"DefectDojo reimport failed for {environment_id}: {e}")
            return None

    # -------------------------------------------------------------------------
    # Finding queries
    # -------------------------------------------------------------------------

    def get_findings(
        self,
        product_name: Optional[str] = None,
        severity: Optional[str] = None,
        active: bool = True,
        limit: int = 100,
    ) -> List[DefectDojoFinding]:
        """Query findings from DefectDojo."""
        params: Dict[str, Any] = {
            'active': str(active).lower(),
            'limit': limit,
        }
        if product_name:
            params['test__engagement__product__name'] = product_name
        if severity:
            params['severity'] = severity.capitalize()

        try:
            resp = self.session.get(
                f"{self.api_url}/findings/",
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            resp.raise_for_status()
            results = resp.json().get('results', [])
            return [self._parse_finding(f) for f in results]
        except requests.RequestException as e:
            logger.error(f"DefectDojo findings query failed: {e}")
            return []

    def get_finding_count(
        self,
        product_name: Optional[str] = None,
        active: bool = True,
    ) -> Dict[str, int]:
        """Get finding counts by severity for a product."""
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for sev in counts:
            params: Dict[str, Any] = {
                'active': str(active).lower(),
                'severity': sev,
                'limit': 1,
            }
            if product_name:
                params['test__engagement__product__name'] = product_name
            try:
                resp = self.session.get(
                    f"{self.api_url}/findings/",
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                resp.raise_for_status()
                counts[sev] = resp.json().get('count', 0)
            except requests.RequestException:
                pass
        return counts

    def _parse_finding(self, data: Dict) -> DefectDojoFinding:
        """Parse a DefectDojo finding API response into a dataclass."""
        return DefectDojoFinding(
            id=data.get('id', 0),
            title=data.get('title', ''),
            severity=data.get('severity', 'Info'),
            cve=data.get('cve'),
            cwe=data.get('cwe'),
            description=data.get('description', ''),
            component_name=data.get('component_name'),
            component_version=data.get('component_version'),
            epss_score=data.get('epss_score'),
            active=data.get('active', True),
            verified=data.get('verified', False),
            false_p=data.get('false_p', False),
            out_of_scope=data.get('out_of_scope', False),
            risk_accepted=data.get('risk_accepted', False),
        )

    # -------------------------------------------------------------------------
    # CycloneDX SBOM builder (from vulnerability_matches records)
    # -------------------------------------------------------------------------

    @staticmethod
    def build_cyclonedx_sbom(
        environment_id: str,
        matches: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Build a CycloneDX 1.4 SBOM with embedded vulnerabilities array
        from vulnerability_matches Kafka records.

        This is the format DefectDojo expects for "CycloneDX Scan" import.

        Args:
            environment_id: Environment identifier (becomes SBOM metadata)
            matches: List of vulnerability_matches records from Kafka

        Returns:
            CycloneDX 1.4 SBOM dict ready for reimport
        """
        # Collect unique components from matches
        components = {}  # bom-ref -> component dict
        vulnerabilities = []

        for match in matches:
            purl = match.get('package_purl') or ''
            cpe = match.get('package_cpe') or ''
            cve_id = match.get('cve_id', '')
            severity = match.get('severity', 'unknown')

            # Parse component info from PURL
            comp_name = 'unknown'
            comp_version = 'unknown'
            if purl:
                # pkg:type/name@version?qualifiers
                purl_path = purl.split('?')[0]  # strip qualifiers
                if '@' in purl_path:
                    base, comp_version = purl_path.rsplit('@', 1)
                    comp_name = base.split('/')[-1]
                else:
                    comp_name = purl_path.split('/')[-1]

            bom_ref = purl or cpe or comp_name
            if bom_ref not in components:
                comp = {
                    'type': 'library',
                    'bom-ref': bom_ref,
                    'name': comp_name,
                    'version': comp_version,
                }
                if purl:
                    comp['purl'] = purl
                if cpe:
                    comp['cpe'] = cpe
                components[bom_ref] = comp

            # Map severity to CycloneDX rating
            cvss_score = match.get('cvss_score')
            ratings = []
            if cvss_score:
                ratings.append({
                    'score': float(cvss_score),
                    'severity': severity.lower(),
                    'method': 'CVSSv3',
                })

            # Build vulnerability entry
            vuln = {
                'id': cve_id,
                'ratings': ratings,
                'description': f"{cve_id} affecting {comp_name}",
                'affects': [{'ref': bom_ref}],
            }

            # Map VEX status to CycloneDX analysis
            vex_status = match.get('vex_status', 'affected')
            if vex_status == 'not_affected':
                vuln['analysis'] = {
                    'state': 'not_affected',
                    'justification': match.get('vex_justification', ''),
                }
            elif vex_status == 'fixed':
                vuln['analysis'] = {'state': 'resolved'}

            # Add CWE if present
            cwe_ids = match.get('cwe_ids') or []
            if cwe_ids:
                vuln['cwes'] = []
                for cwe in cwe_ids:
                    if isinstance(cwe, str) and cwe.startswith('CWE-'):
                        try:
                            vuln['cwes'].append(int(cwe.replace('CWE-', '')))
                        except ValueError:
                            pass

            # Add source reference
            vuln['source'] = {'name': match.get('source', 'flox-sca')}

            # Add properties for DefectDojo enrichment
            properties = []
            if match.get('epss_score') is not None:
                properties.append({
                    'name': 'epss:score',
                    'value': str(match['epss_score']),
                })
            if match.get('cisa_kev'):
                properties.append({
                    'name': 'cisa:kev',
                    'value': 'true',
                })
            if match.get('risk_score') is not None:
                properties.append({
                    'name': 'flox:risk_score',
                    'value': str(match['risk_score']),
                })
            if match.get('alert_tier') is not None:
                properties.append({
                    'name': 'flox:alert_tier',
                    'value': str(match['alert_tier']),
                })
            if match.get('nix_hash'):
                properties.append({
                    'name': 'flox:nix_hash',
                    'value': match['nix_hash'],
                })
            if properties:
                vuln['properties'] = properties

            vulnerabilities.append(vuln)

        # Assemble CycloneDX 1.4 BOM
        return {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'version': 1,
            'metadata': {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'component': {
                    'type': 'application',
                    'name': environment_id,
                    'bom-ref': environment_id,
                },
                'tools': [{
                    'vendor': 'Flox',
                    'name': 'flox-sca',
                    'version': '2.0',
                }],
            },
            'components': list(components.values()),
            'vulnerabilities': vulnerabilities,
        }


def demo():
    """Demonstrate DefectDojo client functionality."""
    import os

    url = os.environ.get('DEFECTDOJO_URL', 'http://localhost:8443')
    token = os.environ.get('DEFECTDOJO_API_TOKEN', '')

    client = DefectDojoClient(base_url=url, api_token=token)

    print("=== DefectDojo Client Demo ===\n")

    # Health check
    healthy = client.health_check()
    print(f"DefectDojo at {url}: {'reachable' if healthy else 'unreachable'}")

    if not healthy:
        print("\nDefectDojo not available. Demonstrating CycloneDX SBOM builder:\n")

        # Build a sample CycloneDX SBOM from vulnerability matches
        sample_matches = [
            {
                'cve_id': 'CVE-2021-44228',
                'package_purl': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
                'severity': 'critical',
                'cvss_score': 10.0,
                'epss_score': 0.975,
                'cisa_kev': True,
                'risk_score': 100,
                'alert_tier': 1,
                'vex_status': 'affected',
                'cwe_ids': ['CWE-502', 'CWE-400'],
                'source': 'nvd',
                'nix_hash': 'abc123def456',
            },
            {
                'cve_id': 'CVE-2023-29491',
                'package_purl': 'pkg:nix/ncurses6@6.5',
                'severity': 'high',
                'cvss_score': 7.8,
                'vex_status': 'not_affected',
                'vex_justification': 'Patched in nixpkgs via CVE-2023-29491.patch',
                'source': 'osv',
            },
        ]

        sbom = DefectDojoClient.build_cyclonedx_sbom('demo-env', sample_matches)
        print(json.dumps(sbom, indent=2))
        return

    # If DD is available, show product/finding info
    print(f"\nQuerying findings...")
    counts = client.get_finding_count()
    print(f"Active findings: {counts}")


if __name__ == "__main__":
    demo()
