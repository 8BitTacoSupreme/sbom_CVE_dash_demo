#!/usr/bin/env python3
"""
Flox Demo Producer - Generates realistic SBOMs for nixpkgs ecosystems.

This producer creates SBOMs that represent real Flox environments by:
1. Targeting packages that actually exist in nixpkgs
2. Querying NVD (CPE) and OSV (PURL) for real CVEs
3. Generating SBOMs with vulnerable versions that will trigger matches
4. Using both CPE and PURL identifiers (as Flox does)

Ecosystems covered:
- System packages: curl, openssl, zlib, glibc, sqlite
- Python: python3Packages.* (requests, django, flask, etc.)
- Go: go packages (hugo, terraform, etc.)
- Rust: rustPackages.* (ripgrep, fd, etc.)
- Java: openjdk, maven artifacts
- C/C++: gcc, llvm, boost, etc.

Usage:
    python producers/flox_demo_producer.py --demo     # Preview without publishing
    python producers/flox_demo_producer.py --kafka    # Publish to Kafka
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clients.nvd_client import NVDClient
from clients.osv_client import OSVClient
from clients.kev_client import KEVClient

# Kafka imports (optional)
try:
    from kafka import KafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False


# =============================================================================
# Nixpkgs Package Definitions
# =============================================================================

@dataclass
class NixPackage:
    """Represents a package in nixpkgs with its identifiers."""
    name: str                    # nixpkgs attribute name
    display_name: str            # Human-readable name
    cpe_vendor: Optional[str]    # CPE vendor (for NVD)
    cpe_product: Optional[str]   # CPE product (for NVD)
    purl_type: Optional[str]     # PURL type (pypi, golang, cargo, etc.)
    purl_name: Optional[str]     # PURL package name
    ecosystem: str               # OSV ecosystem name
    severity_tier: str           # Expected severity tier


# System packages (matched via CPE from NVD)
SYSTEM_PACKAGES = [
    NixPackage('curl', 'curl', 'haxx', 'curl', None, None, 'linux', 'high'),
    NixPackage('openssl', 'OpenSSL', 'openssl', 'openssl', None, None, 'linux', 'critical'),
    NixPackage('zlib', 'zlib', 'zlib', 'zlib', None, None, 'linux', 'medium'),
    NixPackage('sqlite', 'SQLite', 'sqlite', 'sqlite', None, None, 'linux', 'medium'),
    NixPackage('libxml2', 'libxml2', 'xmlsoft', 'libxml2', None, None, 'linux', 'high'),
    NixPackage('libpng', 'libpng', 'libpng', 'libpng', None, None, 'linux', 'medium'),
    NixPackage('libtiff', 'libtiff', 'libtiff', 'libtiff', None, None, 'linux', 'medium'),
    NixPackage('expat', 'expat', 'libexpat_project', 'libexpat', None, None, 'linux', 'high'),
    NixPackage('glibc', 'glibc', 'gnu', 'glibc', None, None, 'linux', 'critical'),
    NixPackage('busybox', 'BusyBox', 'busybox', 'busybox', None, None, 'linux', 'high'),
]

# Python packages (matched via PURL from OSV, exist in python3Packages.*)
PYTHON_PACKAGES = [
    NixPackage('python3Packages.requests', 'requests', None, None, 'pypi', 'requests', 'PyPI', 'high'),
    NixPackage('python3Packages.django', 'Django', None, None, 'pypi', 'django', 'PyPI', 'high'),
    NixPackage('python3Packages.flask', 'Flask', None, None, 'pypi', 'flask', 'PyPI', 'medium'),
    NixPackage('python3Packages.jinja2', 'Jinja2', None, None, 'pypi', 'jinja2', 'PyPI', 'high'),
    NixPackage('python3Packages.cryptography', 'cryptography', None, None, 'pypi', 'cryptography', 'PyPI', 'high'),
    NixPackage('python3Packages.pillow', 'Pillow', None, None, 'pypi', 'pillow', 'PyPI', 'critical'),
    NixPackage('python3Packages.numpy', 'NumPy', None, None, 'pypi', 'numpy', 'PyPI', 'medium'),
    NixPackage('python3Packages.urllib3', 'urllib3', None, None, 'pypi', 'urllib3', 'PyPI', 'medium'),
    NixPackage('python3Packages.pyyaml', 'PyYAML', None, None, 'pypi', 'pyyaml', 'PyPI', 'critical'),
    NixPackage('python3Packages.lxml', 'lxml', None, None, 'pypi', 'lxml', 'PyPI', 'medium'),
    NixPackage('python3Packages.paramiko', 'Paramiko', None, None, 'pypi', 'paramiko', 'PyPI', 'high'),
    NixPackage('python3Packages.werkzeug', 'Werkzeug', None, None, 'pypi', 'werkzeug', 'PyPI', 'medium'),
]

# Go packages (matched via PURL from OSV)
GO_PACKAGES = [
    NixPackage('go-ethereum', 'go-ethereum', None, None, 'golang', 'github.com/ethereum/go-ethereum', 'Go', 'critical'),
    NixPackage('hugo', 'Hugo', None, None, 'golang', 'github.com/gohugoio/hugo', 'Go', 'medium'),
    NixPackage('terraform', 'Terraform', 'hashicorp', 'terraform', 'golang', 'github.com/hashicorp/terraform', 'Go', 'high'),
    NixPackage('consul', 'Consul', 'hashicorp', 'consul', 'golang', 'github.com/hashicorp/consul', 'Go', 'high'),
    NixPackage('vault', 'Vault', 'hashicorp', 'vault', 'golang', 'github.com/hashicorp/vault', 'Go', 'critical'),
    NixPackage('prometheus', 'Prometheus', 'prometheus', 'prometheus', 'golang', 'github.com/prometheus/prometheus', 'Go', 'medium'),
    NixPackage('grafana', 'Grafana', 'grafana', 'grafana', 'golang', 'github.com/grafana/grafana', 'Go', 'high'),
]

# Rust packages (matched via PURL from OSV, exist in rustPackages.*)
RUST_PACKAGES = [
    NixPackage('ripgrep', 'ripgrep', None, None, 'cargo', 'ripgrep', 'crates.io', 'low'),
    NixPackage('fd', 'fd', None, None, 'cargo', 'fd-find', 'crates.io', 'low'),
    NixPackage('bat', 'bat', None, None, 'cargo', 'bat', 'crates.io', 'low'),
    NixPackage('exa', 'exa', None, None, 'cargo', 'exa', 'crates.io', 'low'),
    NixPackage('tokio', 'Tokio', None, None, 'cargo', 'tokio', 'crates.io', 'high'),
    NixPackage('hyper', 'Hyper', None, None, 'cargo', 'hyper', 'crates.io', 'high'),
]

# Realistic environment names
ENVIRONMENT_NAMES = [
    # Individual developers
    'jhogan/data_pipeline', 'jhogan/ml_training', 'jhogan/web_scraper',
    'rsmith/api_server', 'rsmith/auth_service', 'rsmith/monitoring',
    'fmiller/etl_jobs', 'fmiller/analytics', 'fmiller/reporting',
    # Teams
    'platform/base_image', 'platform/ci_runner', 'platform/build_tools',
    'backend/api_gateway', 'backend/user_service', 'backend/payment_processor',
    'data/kafka_consumer', 'data/spark_jobs', 'data/airflow_dags',
    'infra/terraform_runner', 'infra/ansible_controller', 'infra/vault_agent',
    'security/scanner', 'security/siem_collector', 'security/compliance_checker',
]


class FloxDemoProducer:
    """
    Produces realistic demo data for Flox SCA pipeline.

    Queries real vulnerability sources and generates SBOMs with
    packages that will trigger CVE matches.
    """

    def __init__(self, use_nvd: bool = True):
        """
        Initialize the producer.

        Args:
            use_nvd: Whether to query NVD (rate-limited, but has CPE data)
        """
        self.osv_client = OSVClient()
        self.nvd_client = NVDClient() if use_nvd else None
        self.kev_client = KEVClient()

        # Cache of package -> vulnerability mappings
        self.vuln_cache: Dict[str, List[Dict]] = {}

    def query_vulnerabilities(self, pkg: NixPackage) -> List[Dict]:
        """
        Query vulnerabilities for a package from appropriate sources.

        Returns list of {version, cve_id, severity, cwe_ids, cvss_score, affected_versions, cpe, purl}
        """
        cache_key = f"{pkg.ecosystem}:{pkg.display_name}"
        if cache_key in self.vuln_cache:
            return self.vuln_cache[cache_key]

        results = []

        # Query OSV for PURL-based packages
        if pkg.purl_type and pkg.purl_name:
            try:
                vulns = self.osv_client.query_by_package(
                    name=pkg.purl_name,
                    ecosystem=pkg.ecosystem
                )
                for vuln in vulns:
                    version = self._get_affected_version(vuln)
                    fixed_version = self._get_fixed_version(vuln)
                    if not version:
                        continue

                    # Build PURL - Flox uses pkg:nix/ for all packages
                    purl = f"pkg:nix/{pkg.purl_name}@{version}"

                    # Extract affected ranges for VEX
                    affected_versions = self._extract_affected_versions(vuln)

                    results.append({
                        'nix_attr': pkg.name,
                        'name': pkg.display_name,
                        'version': version,
                        'fixed_version': fixed_version,
                        'purl': purl,
                        'cpe': None,
                        'cve_id': vuln.id,
                        'severity': self._get_severity(vuln) or pkg.severity_tier,
                        'cwe_ids': vuln.cwe_ids if hasattr(vuln, 'cwe_ids') else [],
                        'cvss_score': vuln.cvss_score if hasattr(vuln, 'cvss_score') else None,
                        'affected_versions': affected_versions,
                        'source': 'osv',
                        'cisa_kev': self.kev_client.is_actively_exploited(vuln.id),
                    })
            except Exception as e:
                print(f"  Warning: OSV query failed for {pkg.display_name}: {e}")

        # Query NVD for CPE-based packages (system libraries)
        if self.nvd_client and pkg.cpe_vendor and pkg.cpe_product:
            try:
                # Use keyword search - more reliable than CPE match
                keyword = f"{pkg.cpe_product} vulnerability"
                cves = self.nvd_client.query_by_keyword(keyword)

                for cve in cves[:5]:  # Limit to avoid rate limits
                    # Extract version from CPE matches
                    version = self._get_version_from_cpe_matches(cve.cpe_matches)
                    if not version:
                        continue

                    # Build CPE with specific version
                    specific_cpe = self.nvd_client.build_cpe(
                        pkg.cpe_vendor, pkg.cpe_product, version
                    )

                    # Build PURL in pkg:nix/ format
                    purl = f"pkg:nix/{pkg.display_name.lower()}@{version}"

                    results.append({
                        'nix_attr': pkg.name,
                        'name': pkg.display_name,
                        'version': version,
                        'fixed_version': None,
                        'purl': purl,
                        'cpe': specific_cpe,
                        'cve_id': cve.id,
                        'severity': cve.severity_level,
                        'cwe_ids': cve.cwe_ids,
                        'cvss_score': cve.cvss_score,
                        'affected_versions': [],  # NVD uses CPE matching
                        'cpe_matches': [
                            {
                                'vulnerable': m.vulnerable,
                                'criteria': m.cpe23Uri,
                                'versionStartIncluding': m.version_start_including,
                                'versionEndExcluding': m.version_end_excluding,
                                'versionEndIncluding': m.version_end_including,
                            }
                            for m in cve.cpe_matches if m.vulnerable
                        ],
                        'source': 'nvd',
                        'cisa_kev': self.kev_client.is_actively_exploited(cve.id),
                    })
            except Exception as e:
                print(f"  Warning: NVD query failed for {pkg.display_name}: {e}")

        self.vuln_cache[cache_key] = results
        return results

    def _get_affected_version(self, vuln) -> Optional[str]:
        """Extract an affected version from OSV vulnerability."""
        if not hasattr(vuln, 'affected') or not vuln.affected:
            return None

        for affected in vuln.affected:
            if hasattr(affected, 'versions') and affected.versions:
                versions = list(affected.versions)
                if versions:
                    return versions[len(versions) // 2]

            if hasattr(affected, 'ranges') and affected.ranges:
                for range_info in affected.ranges:
                    if hasattr(range_info, 'events'):
                        for event in range_info.events:
                            if isinstance(event, dict) and 'introduced' in event:
                                intro = event['introduced']
                                if intro != '0':
                                    return intro
        return None

    def _get_fixed_version(self, vuln) -> Optional[str]:
        """Extract fixed version from OSV vulnerability."""
        if not hasattr(vuln, 'affected') or not vuln.affected:
            return None

        for affected in vuln.affected:
            if hasattr(affected, 'ranges') and affected.ranges:
                for range_info in affected.ranges:
                    if hasattr(range_info, 'events'):
                        for event in range_info.events:
                            if isinstance(event, dict) and 'fixed' in event:
                                return event['fixed']
        return None

    def _get_severity(self, vuln) -> Optional[str]:
        """Extract severity from OSV vulnerability."""
        if hasattr(vuln, 'database_specific'):
            db = vuln.database_specific
            if isinstance(db, dict):
                sev = db.get('severity', '').lower()
                if sev in ('critical', 'high', 'medium', 'low'):
                    return sev

        if hasattr(vuln, 'cvss_score') and vuln.cvss_score:
            score = vuln.cvss_score
            if score >= 9.0:
                return 'critical'
            if score >= 7.0:
                return 'high'
            if score >= 4.0:
                return 'medium'
            return 'low'

        return None

    def _extract_affected_versions(self, vuln) -> List[Dict]:
        """Extract affected version ranges for VEX inference."""
        affected_versions = []
        if hasattr(vuln, 'affected'):
            for affected in vuln.affected:
                entry = {}
                if hasattr(affected, 'ranges'):
                    entry['ranges'] = [
                        {'type': r.type, 'events': r.events}
                        for r in affected.ranges
                    ]
                if hasattr(affected, 'versions'):
                    entry['versions'] = affected.versions
                if entry:
                    affected_versions.append(entry)
        return affected_versions

    def _get_version_from_cpe_matches(self, cpe_matches: List) -> Optional[str]:
        """Extract a vulnerable version from NVD CPE matches."""
        for match in cpe_matches:
            if not match.vulnerable:
                continue

            # Try to extract version from versionStartIncluding
            if match.version_start_including:
                return match.version_start_including

            # Try to parse from CPE URI
            parts = match.cpe23Uri.split(':')
            if len(parts) >= 6:
                version = parts[5]
                if version != '*' and version != '-':
                    return version

        return None

    def generate_sbom(
        self,
        environment_id: Optional[str] = None,
        include_system: bool = True,
        include_python: bool = True,
        include_go: bool = True,
        include_rust: bool = True,
        vex_demo_pct: float = 0.3,
    ) -> Tuple[Dict, List[Dict]]:
        """
        Generate a demo SBOM and corresponding CVE feed entries.

        Args:
            environment_id: Name for the environment
            include_*: Which package types to include
            vex_demo_pct: Percentage of packages to use fixed versions (VEX demo)

        Returns:
            Tuple of (sbom_dict, cve_feed_list)
        """
        if environment_id is None:
            environment_id = random.choice(ENVIRONMENT_NAMES)

        packages = []
        cve_feed = []
        seen_cves = set()

        print(f"\nGenerating SBOM: {environment_id}")

        # Collect all package types
        all_packages = []
        if include_system:
            all_packages.extend(('system', p) for p in SYSTEM_PACKAGES)
        if include_python:
            all_packages.extend(('python', p) for p in PYTHON_PACKAGES)
        if include_go:
            all_packages.extend(('go', p) for p in GO_PACKAGES)
        if include_rust:
            all_packages.extend(('rust', p) for p in RUST_PACKAGES)

        # Shuffle and limit
        random.shuffle(all_packages)

        stats = {'system': 0, 'python': 0, 'go': 0, 'rust': 0, 'vex': 0, 'kev': 0}

        for pkg_type, pkg in all_packages[:20]:  # Limit to 20 packages per SBOM
            print(f"  Querying {pkg.display_name}...", end=" ", flush=True)
            vulns = self.query_vulnerabilities(pkg)

            if not vulns:
                print("no vulns")
                continue

            # Pick a vulnerability
            vuln = random.choice(vulns[:3])  # Pick from top 3

            # Decide if we use fixed version for VEX demo
            use_fixed = (
                vuln.get('fixed_version') and
                random.random() < vex_demo_pct
            )
            version = vuln['fixed_version'] if use_fixed else vuln['version']

            # Build package entry with both CPE and PURL
            # Flox uses pkg:nix/<name>@<version> for all packages
            purl = f"pkg:nix/{pkg.display_name.lower()}@{version}"

            pkg_entry = {
                'name': pkg.name,
                'display_name': pkg.display_name,
                'version': version,
                'purl': purl,
                'cpe': vuln['cpe'],
            }
            packages.append(pkg_entry)

            # Build CVE feed entry
            cve_id = vuln['cve_id']
            if cve_id not in seen_cves:
                seen_cves.add(cve_id)
                # Use pkg:nix/ format for base PURL (without version)
                base_purl = f"pkg:nix/{pkg.display_name.lower()}"
                cve_entry = {
                    'cve_id': cve_id,
                    'package_purl': base_purl,
                    'package_cpe': self._base_cpe(vuln['cpe']) if vuln['cpe'] else None,
                    'severity': vuln['severity'],
                    'status': 'active',
                    'source': vuln['source'],
                    'published_at': datetime.now(timezone.utc).isoformat(),
                    'cwe_ids': vuln['cwe_ids'],
                    'cvss_score': vuln['cvss_score'],
                    'affected_versions': vuln.get('affected_versions', []),
                    'cpe_matches': vuln.get('cpe_matches', []),
                }
                cve_feed.append(cve_entry)

            stats[pkg_type] += 1
            if use_fixed:
                stats['vex'] += 1
            if vuln['cisa_kev']:
                stats['kev'] += 1

            print(f"{vuln['cve_id']} ({vuln['severity']})" +
                  (" [VEX]" if use_fixed else "") +
                  (" [KEV]" if vuln['cisa_kev'] else ""))

        print(f"\n  Summary: {len(packages)} packages, {len(cve_feed)} CVEs")
        print(f"    System: {stats['system']}, Python: {stats['python']}, " +
              f"Go: {stats['go']}, Rust: {stats['rust']}")
        print(f"    VEX demo (fixed versions): {stats['vex']}")
        print(f"    CISA KEV: {stats['kev']}")

        sbom = {
            'environment_id': environment_id,
            'scan_timestamp': datetime.now(timezone.utc).isoformat(),
            'packages': packages,
        }

        return sbom, cve_feed

    def _base_cpe(self, cpe: str) -> Optional[str]:
        """Extract base CPE without version for matching."""
        if not cpe:
            return None
        parts = cpe.split(':')
        if len(parts) >= 6:
            # cpe:2.3:a:vendor:product:* -> base
            return ':'.join(parts[:5])
        return cpe


def create_kafka_producer():
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


def publish_to_kafka(producer, cve_feed: List[Dict], sbom: Dict):
    """Publish CVE feed and SBOM to Kafka."""
    # First publish CVEs
    print(f"\nPublishing {len(cve_feed)} CVEs to cve_feed topic...")
    for cve in cve_feed:
        producer.send('cve_feed', key=cve['cve_id'], value=cve)
    producer.flush()

    time.sleep(1)

    # Publish SBOM
    print(f"Publishing SBOM ({len(sbom['packages'])} packages) to sbom_events topic...")
    producer.send('sbom_events', key=sbom['environment_id'], value=sbom)
    producer.flush()


def main():
    parser = argparse.ArgumentParser(
        description="Flox Demo Producer - Generates realistic SBOMs for nixpkgs ecosystems"
    )
    parser.add_argument('--demo', action='store_true',
                        help="Preview without publishing")
    parser.add_argument('--kafka', action='store_true',
                        help="Publish to Kafka")
    parser.add_argument('--env', type=str,
                        help="Environment ID (default: random)")
    parser.add_argument('--no-nvd', action='store_true',
                        help="Skip NVD queries (faster, no CPE data)")
    parser.add_argument('--count', type=int, default=1,
                        help="Number of SBOMs to generate")

    args = parser.parse_args()

    if not args.demo and not args.kafka:
        args.demo = True

    producer_instance = FloxDemoProducer(use_nvd=not args.no_nvd)
    kafka_producer = None

    if args.kafka:
        kafka_producer = create_kafka_producer()
        if not kafka_producer:
            print("Failed to connect to Kafka")
            sys.exit(1)

    try:
        for i in range(args.count):
            sbom, cve_feed = producer_instance.generate_sbom(
                environment_id=args.env if args.count == 1 else None
            )

            if args.kafka and kafka_producer:
                publish_to_kafka(kafka_producer, cve_feed, sbom)
                print(f"\n{'='*60}")
                print("Published to Kafka! Check Grafana:")
                print("  http://localhost:3000/d/sca-overview")
                print(f"{'='*60}")
            else:
                print("\n[DEMO MODE - not publishing]")
                print(f"SBOM: {sbom['environment_id']}")
                print(f"Packages: {len(sbom['packages'])}")
                print(f"CVEs: {len(cve_feed)}")

            if i < args.count - 1:
                time.sleep(2)

    finally:
        if kafka_producer:
            kafka_producer.close()


if __name__ == "__main__":
    main()
