#!/usr/bin/env python3
"""
Live CVE Producer

Fetches real vulnerability data from OSV and NVD APIs.
Replaces mock CVE data with live feeds for production use.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import List, Dict, Optional, Set
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clients.osv_client import OSVClient, Vulnerability as OSVVuln
from clients.nvd_client import NVDClient, CVE as NVDCVE

try:
    from kafka import KafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class LiveCVEProducer:
    """
    Producer for live CVE data from OSV and NVD.

    Combines vulnerability data from multiple sources:
    - OSV: Language ecosystem packages (npm, PyPI, Go, etc.) via PURL
    - NVD: Native C/C++ libraries via CPE
    """

    def __init__(self, nvd_api_key: Optional[str] = None,
                 kafka_servers: Optional[str] = None):
        """
        Initialize live CVE producer.

        Args:
            nvd_api_key: NVD API key for higher rate limits
            kafka_servers: Kafka bootstrap servers
        """
        self.osv = OSVClient()
        self.nvd = NVDClient(api_key=nvd_api_key)

        self.kafka_servers = kafka_servers or os.environ.get(
            'KAFKA_BOOTSTRAP_SERVERS', 'localhost:9092'
        )
        self.producer = None
        self._seen_cves: Set[str] = set()

    def connect_kafka(self):
        """Connect to Kafka."""
        if not KAFKA_AVAILABLE:
            logger.warning("kafka-python not installed, Kafka output disabled")
            return

        self.producer = KafkaProducer(
            bootstrap_servers=self.kafka_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            key_serializer=lambda k: k.encode('utf-8') if k else None,
        )
        logger.info(f"Connected to Kafka at {self.kafka_servers}")

    def fetch_for_purl(self, purl: str) -> List[Dict]:
        """
        Fetch CVEs affecting a specific PURL from OSV.

        Args:
            purl: Package URL (e.g., "pkg:npm/lodash@4.17.20")

        Returns:
            List of CVE records
        """
        vulns = self.osv.query_by_purl(purl)
        return [self._osv_to_cve_record(v, purl) for v in vulns]

    def fetch_for_cpe(self, cpe: str) -> List[Dict]:
        """
        Fetch CVEs affecting a specific CPE from NVD.

        Args:
            cpe: CPE 2.3 string

        Returns:
            List of CVE records
        """
        cves = self.nvd.query_by_cpe(cpe)
        return [self._nvd_to_cve_record(c, cpe) for c in cves]

    def fetch_for_packages(self, packages: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Fetch CVEs for a list of packages.

        Args:
            packages: List of package dicts with 'purl' and/or 'cpe' keys

        Returns:
            Dict mapping package identifier to list of CVEs
        """
        results: Dict[str, List[Dict]] = {}

        for pkg in packages:
            pkg_id = pkg.get('purl') or pkg.get('cpe') or pkg.get('name')
            pkg_cves = []

            # Query OSV by PURL
            if pkg.get('purl'):
                try:
                    osv_cves = self.fetch_for_purl(pkg['purl'])
                    pkg_cves.extend(osv_cves)
                    logger.info(f"OSV: {len(osv_cves)} CVEs for {pkg['purl']}")
                except Exception as e:
                    logger.error(f"OSV query failed for {pkg['purl']}: {e}")

            # Query NVD by CPE
            if pkg.get('cpe'):
                try:
                    nvd_cves = self.fetch_for_cpe(pkg['cpe'])
                    pkg_cves.extend(nvd_cves)
                    logger.info(f"NVD: {len(nvd_cves)} CVEs for {pkg['cpe']}")
                except Exception as e:
                    logger.error(f"NVD query failed for {pkg['cpe']}: {e}")

            # Deduplicate by CVE ID
            seen = set()
            deduped = []
            for cve in pkg_cves:
                if cve['cve_id'] not in seen:
                    seen.add(cve['cve_id'])
                    deduped.append(cve)

            results[pkg_id] = deduped

        return results

    def publish_cve(self, cve: Dict, topic: str = 'cve_feed'):
        """
        Publish a CVE record to Kafka.

        Args:
            cve: CVE record dict
            topic: Kafka topic name
        """
        if self.producer is None:
            self._print_cve(cve)
            return

        key = cve.get('package_purl') or cve.get('package_cpe')
        self.producer.send(topic, key=key, value=cve)
        logger.debug(f"Published {cve['cve_id']} to {topic}")

    def publish_batch(self, cves: List[Dict], topic: str = 'cve_feed'):
        """Publish multiple CVEs to Kafka."""
        for cve in cves:
            if cve['cve_id'] not in self._seen_cves:
                self.publish_cve(cve, topic)
                self._seen_cves.add(cve['cve_id'])

        if self.producer:
            self.producer.flush()
            logger.info(f"Published {len(cves)} CVEs to {topic}")

    def run_for_sbom(self, sbom_path: str, output_kafka: bool = True):
        """
        Fetch and publish CVEs for all packages in an SBOM.

        Args:
            sbom_path: Path to SPDX JSON file
            output_kafka: If True, publish to Kafka
        """
        # Load SBOM
        with open(sbom_path) as f:
            sbom = json.load(f)

        # Extract packages
        packages = []
        for pkg in sbom.get('packages', []):
            pkg_info = {
                'name': pkg.get('name', ''),
                'version': pkg.get('versionInfo', ''),
            }

            # Check for PURL in external refs
            for ref in pkg.get('externalRefs', []):
                if ref.get('referenceType') == 'purl':
                    pkg_info['purl'] = ref.get('referenceLocator')
                elif ref.get('referenceType') == 'cpe23Type':
                    pkg_info['cpe'] = ref.get('referenceLocator')

            # Only include if we have an identifier
            if pkg_info.get('purl') or pkg_info.get('cpe'):
                packages.append(pkg_info)

        logger.info(f"Found {len(packages)} packages with PURL/CPE in SBOM")

        # Connect to Kafka if needed
        if output_kafka:
            self.connect_kafka()

        # Fetch CVEs
        results = self.fetch_for_packages(packages)

        # Publish
        all_cves = []
        for pkg_id, cves in results.items():
            all_cves.extend(cves)

        self.publish_batch(all_cves)

        return all_cves

    def run_for_package_list(self, packages: List[Dict], output_kafka: bool = True):
        """
        Fetch and publish CVEs for a list of packages.

        Args:
            packages: List of package dicts with purl/cpe
            output_kafka: If True, publish to Kafka
        """
        if output_kafka:
            self.connect_kafka()

        results = self.fetch_for_packages(packages)

        all_cves = []
        for pkg_id, cves in results.items():
            all_cves.extend(cves)

        self.publish_batch(all_cves)
        return all_cves

    def _osv_to_cve_record(self, vuln: OSVVuln, purl: str) -> Dict:
        """Convert OSV vulnerability to standard CVE record."""
        return {
            'cve_id': vuln.cve_id or vuln.id,
            'osv_id': vuln.id,
            'package_purl': purl,
            'severity': vuln.severity_level,
            'cvss_score': vuln.cvss_score,
            'description': vuln.summary or vuln.details[:500] if vuln.details else '',
            'source': 'osv',
            'published': datetime.utcnow().isoformat(),
        }

    def _nvd_to_cve_record(self, cve: NVDCVE, cpe: str) -> Dict:
        """Convert NVD CVE to standard CVE record."""
        return {
            'cve_id': cve.id,
            'package_cpe': cpe,
            'severity': cve.severity_level,
            'cvss_score': cve.cvss_score,
            'description': cve.description[:500] if cve.description else '',
            'source': 'nvd',
            'published': cve.published.isoformat() if cve.published else datetime.utcnow().isoformat(),
        }

    def _print_cve(self, cve: Dict):
        """Print CVE to stdout (when Kafka not available)."""
        severity_colors = {
            'critical': '\033[91m',  # Red
            'high': '\033[93m',      # Yellow
            'medium': '\033[94m',    # Blue
            'low': '\033[92m',       # Green
        }
        reset = '\033[0m'

        sev = cve.get('severity', 'unknown')
        color = severity_colors.get(sev, '')

        print(f"  {color}{cve['cve_id']}{reset} ({sev.upper()})")
        print(f"    Package: {cve.get('package_purl') or cve.get('package_cpe')}")
        print(f"    Source: {cve.get('source', 'unknown')}")
        if cve.get('description'):
            print(f"    {cve['description'][:80]}...")


def demo_packages():
    """Demo packages for testing live feeds."""
    return [
        # Native libraries (NVD via CPE)
        {'name': 'openssl', 'purl': 'pkg:nix/openssl@3.0.0',
         'cpe': 'cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*'},
        {'name': 'curl', 'purl': 'pkg:nix/curl@8.5.0',
         'cpe': 'cpe:2.3:a:haxx:curl:8.5.0:*:*:*:*:*:*:*'},
        {'name': 'zlib', 'purl': 'pkg:nix/zlib@1.3.0',
         'cpe': 'cpe:2.3:a:zlib:zlib:1.3:*:*:*:*:*:*:*'},

        # Language packages (OSV via PURL)
        {'name': 'lodash', 'purl': 'pkg:npm/lodash@4.17.20'},
        {'name': 'requests', 'purl': 'pkg:pypi/requests@2.28.0'},
    ]


def main():
    parser = argparse.ArgumentParser(
        description='Fetch live CVE data from OSV and NVD'
    )
    parser.add_argument('--sbom', help='Path to SPDX JSON SBOM file')
    parser.add_argument('--packages', help='JSON file with package list')
    parser.add_argument('--demo', action='store_true',
                       help='Run with demo packages')
    parser.add_argument('--purl', help='Query single PURL')
    parser.add_argument('--cpe', help='Query single CPE')
    parser.add_argument('--kafka', action='store_true',
                       help='Publish to Kafka')
    parser.add_argument('--nvd-key', help='NVD API key')

    args = parser.parse_args()

    producer = LiveCVEProducer(nvd_api_key=args.nvd_key)

    if args.demo:
        print("=== Live CVE Producer Demo ===\n")
        packages = demo_packages()
        print(f"Querying CVEs for {len(packages)} demo packages...\n")
        cves = producer.run_for_package_list(packages, output_kafka=args.kafka)
        print(f"\nTotal: {len(cves)} CVEs found")

    elif args.sbom:
        print(f"Fetching CVEs for SBOM: {args.sbom}\n")
        cves = producer.run_for_sbom(args.sbom, output_kafka=args.kafka)
        print(f"\nTotal: {len(cves)} CVEs found")

    elif args.packages:
        with open(args.packages) as f:
            packages = json.load(f)
        cves = producer.run_for_package_list(packages, output_kafka=args.kafka)
        print(f"\nTotal: {len(cves)} CVEs found")

    elif args.purl:
        print(f"Querying OSV for: {args.purl}\n")
        cves = producer.fetch_for_purl(args.purl)
        for cve in cves:
            producer._print_cve(cve)
        print(f"\nTotal: {len(cves)} CVEs")

    elif args.cpe:
        print(f"Querying NVD for: {args.cpe}\n")
        cves = producer.fetch_for_cpe(args.cpe)
        for cve in cves:
            producer._print_cve(cve)
        print(f"\nTotal: {len(cves)} CVEs")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
