#!/usr/bin/env python3
"""
Demo SBOM Producer - Generates SBOMs that trigger real CVE hits.

Queries live vulnerability feeds (OSV/NVD) and creates SBOMs with packages
that match real CVEs. Designed for compelling demos with realistic data.

Severity distribution (configurable):
  - Critical: 1-2 hits
  - High: ~12 hits
  - Medium: ~50 hits
  - Low: ~100 hits

Usage:
    python producers/demo_sbom_producer.py --demo          # Show what would be generated
    python producers/demo_sbom_producer.py --kafka         # Publish to Kafka
    python producers/demo_sbom_producer.py --continuous    # Stream SBOMs every N seconds
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clients.osv_client import OSVClient
from clients.nvd_client import NVDClient
from clients.kev_client import KEVClient

# Kafka imports (optional)
try:
    from kafka import KafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False


# Realistic environment names in user/project or team/service format
ENVIRONMENT_NAMES = [
    # Individual developers
    'jhogan/account_lookups',
    'jhogan/api_gateway',
    'rsmith/frontend',
    'rsmith/data_pipeline',
    'fmiller/auth_service',
    'fmiller/user_mgmt',
    'alee/ml_models',
    'alee/recommendation_engine',
    # Teams
    'frontdesk/ticketing',
    'frontdesk/customer_portal',
    'payments/processor',
    'payments/fraud_detection',
    'accounting/reports',
    'accounting/invoicing',
    'support/chatbot',
    'support/knowledge_base',
    # Infrastructure
    'platform/monitoring',
    'platform/logging',
    'devops/ci_runner',
    'devops/deploy_tools',
]

# Well-known packages with CVE history - these are real packages with real CVEs
VULNERABLE_PACKAGES = {
    'critical': [
        # npm packages with critical CVEs
        {'name': 'node-serialize', 'ecosystem': 'npm', 'purl_type': 'npm'},  # RCE
        {'name': 'event-stream', 'ecosystem': 'npm', 'purl_type': 'npm'},    # Supply chain
        {'name': 'ua-parser-js', 'ecosystem': 'npm', 'purl_type': 'npm'},    # Supply chain
        {'name': 'coa', 'ecosystem': 'npm', 'purl_type': 'npm'},             # Supply chain
        {'name': 'rc', 'ecosystem': 'npm', 'purl_type': 'npm'},              # Supply chain
        # Python packages with critical CVEs
        {'name': 'pyyaml', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},        # Arbitrary code exec
        {'name': 'pillow', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},        # Memory corruption
    ],
    'high': [
        # Libraries with frequent high-severity CVEs
        {'name': 'lodash', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'axios', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'minimist', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'node-forge', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'json5', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'jsonwebtoken', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'tar', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'got', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'shell-quote', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'django', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'requests', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'jinja2', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'cryptography', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'sqlalchemy', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
    ],
    'medium': [
        # Common packages with medium-severity CVEs
        {'name': 'express', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'moment', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'underscore', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'qs', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'semver', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'glob-parent', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'async', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'serialize-javascript', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'y18n', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'yargs-parser', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'flask', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'numpy', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'scipy', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'pandas', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'urllib3', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'certifi', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
    ],
    'low': [
        # Packages with low-severity CVEs (info disclosure, minor issues)
        {'name': 'debug', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'chalk', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'commander', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'colors', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'ini', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'marked', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'highlight.js', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'prismjs', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'sanitize-html', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'dompurify', 'ecosystem': 'npm', 'purl_type': 'npm'},
        {'name': 'bleach', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'lxml', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'paramiko', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'werkzeug', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'setuptools', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
        {'name': 'pip', 'ecosystem': 'PyPI', 'purl_type': 'pypi'},
    ]
}


class DemoSBOMProducer:
    """
    Produces demo SBOMs that trigger real CVE matches.

    Queries OSV to find real CVEs for well-known packages,
    then generates SBOMs with vulnerable versions.
    """

    def __init__(self):
        self.osv_client = OSVClient()
        self.nvd_client = NVDClient()
        self.kev_client = KEVClient()

        # Cache of package -> CVE mappings
        self.cve_cache: Dict[str, List[Dict]] = {}

        # Target severity distribution
        self.severity_targets = {
            'critical': 2,
            'high': 12,
            'medium': 50,
            'low': 100,
        }

    def query_real_cves(self, severity: str, limit: int = 20) -> List[Dict]:
        """
        Query real CVEs from OSV for packages in a severity tier.

        The severity tier determines which packages to query - we use the
        package categorization as a proxy for CVE severity since OSV
        severity data is inconsistent.

        Returns list of {package, version, purl, cve_id, severity, cwe_ids, cisa_kev}
        """
        results = []
        packages = VULNERABLE_PACKAGES.get(severity, [])
        random.shuffle(packages)  # Vary which packages we pick

        for pkg_info in packages:
            if len(results) >= limit:
                break

            cache_key = f"{pkg_info['ecosystem']}:{pkg_info['name']}"

            if cache_key not in self.cve_cache:
                try:
                    # Query OSV for this package
                    vulns = self.osv_client.query_by_package(
                        name=pkg_info['name'],
                        ecosystem=pkg_info['ecosystem']
                    )
                    self.cve_cache[cache_key] = vulns
                except Exception as e:
                    print(f"  Warning: OSV query failed for {pkg_info['name']}: {e}")
                    continue

            vulns = self.cve_cache.get(cache_key, [])

            # Pick vulnerabilities from this package (limit per package)
            vulns_used = 0
            max_per_pkg = max(1, limit // len(packages)) if packages else limit

            for vuln in vulns:
                if len(results) >= limit or vulns_used >= max_per_pkg:
                    break

                # Find an affected version (or fixed version for VEX demo)
                # ~30% of medium/low will use fixed versions to show VEX filtering
                use_fixed = False
                version = None
                if severity in ('medium', 'low') and random.random() < 0.3:
                    fixed_version = self._get_fixed_version(vuln)
                    if fixed_version:
                        version = fixed_version
                        use_fixed = True

                if not version:
                    version = self._get_affected_version(vuln)
                    if not version:
                        continue

                # Build PURL
                purl = self._build_purl(pkg_info, version)

                # Check KEV status
                cve_id = vuln.id if hasattr(vuln, 'id') else vuln.get('id', '')
                is_kev = self.kev_client.is_actively_exploited(cve_id)

                # Extract CWE IDs
                cwe_ids = []
                if hasattr(vuln, 'cwe_ids'):
                    cwe_ids = vuln.cwe_ids
                elif hasattr(vuln, 'database_specific'):
                    db = vuln.database_specific
                    if isinstance(db, dict):
                        cwe_ids = db.get('cwe_ids', [])

                # Extract CVSS score
                cvss_score = None
                if hasattr(vuln, 'cvss_score'):
                    cvss_score = vuln.cvss_score

                # Extract affected version ranges for VEX inference
                affected_versions = []
                if hasattr(vuln, 'affected'):
                    for affected in vuln.affected:
                        affected_entry = {}
                        if hasattr(affected, 'ranges'):
                            affected_entry['ranges'] = [
                                {
                                    'type': r.type,
                                    'events': r.events
                                }
                                for r in affected.ranges
                            ]
                        if hasattr(affected, 'versions'):
                            affected_entry['versions'] = affected.versions
                        if affected_entry:
                            affected_versions.append(affected_entry)

                results.append({
                    'name': pkg_info['name'],
                    'version': version,
                    'purl': purl,
                    'ecosystem': pkg_info['ecosystem'],
                    'cve_id': cve_id,
                    'severity': severity,  # Use tier severity
                    'cisa_kev': is_kev,
                    'cwe_ids': cwe_ids,
                    'cvss_score': cvss_score,
                    'affected_versions': affected_versions,
                    'use_fixed_version': use_fixed,  # For demo tracking
                })
                vulns_used += 1

        return results

    def _get_severity(self, vuln) -> str:
        """Extract severity from OSV vulnerability."""
        # Try database_specific first
        if hasattr(vuln, 'database_specific'):
            db = vuln.database_specific
            if isinstance(db, dict):
                severity = db.get('severity', '').lower()
                if severity in ('critical', 'high', 'medium', 'low'):
                    return severity

        # Try severity field
        if hasattr(vuln, 'severity') and vuln.severity:
            for sev in vuln.severity:
                if hasattr(sev, 'type') and sev.type == 'CVSS_V3':
                    score = getattr(sev, 'score', None)
                    if score:
                        # Parse CVSS vector for severity
                        if isinstance(score, str) and '/' in score:
                            # It's a vector string, try to extract score
                            pass
                        elif isinstance(score, (int, float)):
                            if score >= 9.0:
                                return 'critical'
                            elif score >= 7.0:
                                return 'high'
                            elif score >= 4.0:
                                return 'medium'
                            else:
                                return 'low'

        # Default based on package tier
        return 'medium'

    def _get_affected_version(self, vuln) -> Optional[str]:
        """Find an affected version from vulnerability data."""
        if not hasattr(vuln, 'affected') or not vuln.affected:
            return None

        for affected in vuln.affected:
            # Try explicit versions list first
            if hasattr(affected, 'versions') and affected.versions:
                # Pick a version from the middle of the list
                versions = list(affected.versions)
                if versions:
                    return versions[len(versions) // 2]

            # Try to extract from ranges
            if hasattr(affected, 'ranges') and affected.ranges:
                for range_info in affected.ranges:
                    if hasattr(range_info, 'events'):
                        for event in range_info.events:
                            if hasattr(event, 'introduced') and event.introduced != '0':
                                return event.introduced

        return None

    def _get_fixed_version(self, vuln) -> Optional[str]:
        """Find a fixed version from vulnerability data (for VEX demo)."""
        if not hasattr(vuln, 'affected') or not vuln.affected:
            return None

        for affected in vuln.affected:
            # Try to extract fixed version from ranges
            if hasattr(affected, 'ranges') and affected.ranges:
                for range_info in affected.ranges:
                    if hasattr(range_info, 'events'):
                        for event in range_info.events:
                            if isinstance(event, dict) and 'fixed' in event:
                                return event['fixed']
                            elif hasattr(event, 'get') and event.get('fixed'):
                                return event.get('fixed')

        return None

    def _build_purl(self, pkg_info: Dict, version: str) -> str:
        """Build a Package URL."""
        purl_type = pkg_info.get('purl_type', 'generic')
        name = pkg_info['name']

        if purl_type == 'maven' and 'group' in pkg_info:
            # Maven uses namespace/name format
            return f"pkg:{purl_type}/{pkg_info['group']}/{name}@{version}"
        else:
            return f"pkg:{purl_type}/{name}@{version}"

    def generate_demo_sbom(
        self,
        environment_id: str = None,
        severity_counts: Dict[str, int] = None
    ) -> Dict:
        """
        Generate a demo SBOM with packages that will trigger CVE matches.

        Args:
            environment_id: Name for the environment (auto-generated if None)
            severity_counts: Override default severity distribution

        Returns:
            SBOM dict ready for Kafka
        """
        if environment_id is None:
            environment_id = random.choice(ENVIRONMENT_NAMES)

        counts = severity_counts or self.severity_targets
        packages = []

        print(f"\nGenerating SBOM: {environment_id}")
        print("  Querying OSV for real vulnerable packages...")

        for severity in ['critical', 'high', 'medium', 'low']:
            target = counts.get(severity, 0)
            if target == 0:
                continue

            print(f"  - {severity}: querying {target} packages...", end=" ", flush=True)

            vulns = self.query_real_cves(severity, limit=target)

            for vuln_info in vulns:
                packages.append({
                    'name': vuln_info['name'],
                    'version': vuln_info['version'],
                    'purl': vuln_info['purl'],
                    'vex_status': 'affected',
                    '_cve_id': vuln_info['cve_id'],  # For demo display
                    '_severity': vuln_info['severity'],
                    '_kev': vuln_info.get('cisa_kev', False),
                    '_cwe_ids': vuln_info.get('cwe_ids', []),
                    '_cvss_score': vuln_info.get('cvss_score'),
                    '_affected_versions': vuln_info.get('affected_versions', []),
                })

            kev_count = sum(1 for v in vulns if v.get('cisa_kev'))
            vex_count = sum(1 for v in vulns if v.get('use_fixed_version'))
            markers = []
            if kev_count:
                markers.append(f"{kev_count} KEV")
            if vex_count:
                markers.append(f"{vex_count} fixed→VEX")
            marker_str = f" ({', '.join(markers)})" if markers else ""
            print(f"found {len(vulns)}{marker_str}")

        return {
            'environment_id': environment_id,
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
            'packages': packages,
        }

    def generate_cve_feed(self, sbom: Dict) -> List[Dict]:
        """
        Generate CVE feed entries for packages in SBOM.

        This ensures the CVEs exist in the stream processor's state
        before the SBOM arrives.
        """
        cve_feed = []
        seen_cves = set()

        for pkg in sbom.get('packages', []):
            cve_id = pkg.get('_cve_id')
            if not cve_id or cve_id in seen_cves:
                continue

            seen_cves.add(cve_id)

            cve_feed.append({
                'cve_id': cve_id,
                'package_purl': pkg['purl'].rsplit('@', 1)[0],  # Base PURL without version
                'severity': pkg.get('_severity', 'medium'),
                'status': 'active',
                'source': 'osv',
                'published_at': datetime.now(timezone.utc).isoformat(),
                'cwe_ids': pkg.get('_cwe_ids', []),
                'cvss_score': pkg.get('_cvss_score'),
                'affected_versions': pkg.get('_affected_versions', []),
            })

        return cve_feed


def create_kafka_producer() -> Optional['KafkaProducer']:
    """Create Kafka producer if available."""
    if not KAFKA_AVAILABLE:
        print("Warning: kafka-python not installed")
        return None

    bootstrap_servers = os.environ.get('KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092')

    try:
        return KafkaProducer(
            bootstrap_servers=bootstrap_servers.split(','),
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            key_serializer=lambda k: k.encode('utf-8') if k else None,
        )
    except Exception as e:
        print(f"Warning: Could not connect to Kafka: {e}")
        return None


def publish_to_kafka(producer: 'KafkaProducer', cve_feed: List[Dict], sbom: Dict):
    """Publish CVE feed and SBOM to Kafka."""
    # First publish CVEs so stream processor has them
    print(f"\nPublishing {len(cve_feed)} CVEs to cve_feed topic...")
    for cve in cve_feed:
        producer.send('cve_feed', key=cve['cve_id'], value=cve)
    producer.flush()

    # Small delay to ensure CVEs are processed
    time.sleep(1)

    # Clean SBOM (remove internal fields)
    clean_sbom = {
        'environment_id': sbom['environment_id'],
        'scan_timestamp': sbom['scan_timestamp'],
        'packages': [
            {k: v for k, v in pkg.items() if not k.startswith('_')}
            for pkg in sbom['packages']
        ]
    }

    # Publish SBOM
    print(f"Publishing SBOM ({len(clean_sbom['packages'])} packages) to sbom_events topic...")
    producer.send('sbom_events', key=sbom['environment_id'], value=clean_sbom)
    producer.flush()

    print("Done!")


def demo_mode(producer_instance: DemoSBOMProducer):
    """Show what would be generated without publishing."""
    print("\n" + "="*60)
    print("DEMO MODE - Showing generated data (not publishing)")
    print("="*60)

    sbom = producer_instance.generate_demo_sbom(
        environment_id="demo-preview",
        severity_counts={'critical': 2, 'high': 5, 'medium': 10, 'low': 15}
    )

    print(f"\nGenerated SBOM: {sbom['environment_id']}")
    print(f"Total packages: {len(sbom['packages'])}")

    # Count by severity
    by_severity = {}
    kev_count = 0
    for pkg in sbom['packages']:
        sev = pkg.get('_severity', 'unknown')
        by_severity[sev] = by_severity.get(sev, 0) + 1
        if pkg.get('_kev'):
            kev_count += 1

    print(f"\nSeverity distribution:")
    for sev in ['critical', 'high', 'medium', 'low']:
        count = by_severity.get(sev, 0)
        print(f"  {sev}: {count}")

    if kev_count:
        print(f"\nKEV (actively exploited): {kev_count}")

    print(f"\nSample packages:")
    for pkg in sbom['packages'][:10]:
        kev_marker = " [KEV!]" if pkg.get('_kev') else ""
        print(f"  {pkg['_severity']:8} | {pkg['_cve_id']:15} | {pkg['name']}@{pkg['version']}{kev_marker}")

    if len(sbom['packages']) > 10:
        print(f"  ... and {len(sbom['packages']) - 10} more")


def continuous_mode(
    producer_instance: DemoSBOMProducer,
    kafka_producer: 'KafkaProducer',
    interval: int = 30
):
    """Continuously generate and publish SBOMs."""
    print(f"\nContinuous mode: Publishing SBOM every {interval} seconds")
    print("Press Ctrl+C to stop\n")

    counter = 0
    try:
        while True:
            counter += 1
            env_id = f"continuous-demo-{counter:03d}"

            # Vary the severity counts a bit for realism
            counts = {
                'critical': random.randint(0, 2),
                'high': random.randint(5, 15),
                'medium': random.randint(20, 60),
                'low': random.randint(50, 120),
            }

            sbom = producer_instance.generate_demo_sbom(
                environment_id=env_id,
                severity_counts=counts
            )

            cve_feed = producer_instance.generate_cve_feed(sbom)
            publish_to_kafka(kafka_producer, cve_feed, sbom)

            print(f"\nWaiting {interval}s before next SBOM...")
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nStopped.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate demo SBOMs that trigger real CVE matches"
    )
    parser.add_argument('--demo', action='store_true',
                        help='Show what would be generated (no Kafka)')
    parser.add_argument('--kafka', action='store_true',
                        help='Publish to Kafka')
    parser.add_argument('--continuous', action='store_true',
                        help='Continuously generate SBOMs')
    parser.add_argument('--interval', type=int, default=30,
                        help='Seconds between SBOMs in continuous mode')
    parser.add_argument('--env', type=str, default=None,
                        help='Environment ID for SBOM')
    parser.add_argument('--critical', type=int, default=2,
                        help='Number of critical severity hits')
    parser.add_argument('--high', type=int, default=12,
                        help='Number of high severity hits')
    parser.add_argument('--medium', type=int, default=50,
                        help='Number of medium severity hits')
    parser.add_argument('--low', type=int, default=100,
                        help='Number of low severity hits')

    args = parser.parse_args()

    producer_instance = DemoSBOMProducer()

    if args.demo:
        demo_mode(producer_instance)
        return

    if args.kafka or args.continuous:
        kafka_producer = create_kafka_producer()
        if not kafka_producer:
            print("Error: Could not connect to Kafka")
            sys.exit(1)

        if args.continuous:
            continuous_mode(producer_instance, kafka_producer, args.interval)
        else:
            # Single SBOM
            counts = {
                'critical': args.critical,
                'high': args.high,
                'medium': args.medium,
                'low': args.low,
            }

            sbom = producer_instance.generate_demo_sbom(
                environment_id=args.env,
                severity_counts=counts
            )

            cve_feed = producer_instance.generate_cve_feed(sbom)
            publish_to_kafka(kafka_producer, cve_feed, sbom)

            # Summary
            print(f"\n{'='*60}")
            print("Published to Kafka! Check Grafana:")
            print("  http://localhost:3000/d/sca-overview")
            print(f"{'='*60}")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
