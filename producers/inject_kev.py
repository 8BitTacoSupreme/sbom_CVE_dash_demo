#!/usr/bin/env python3
"""
KEV Injection Script - Instantly inject known exploited vulnerabilities.

Usage:
    python producers/inject_kev.py --list                    # Show available scenarios
    python producers/inject_kev.py --inject log4shell       # Inject Log4Shell
    python producers/inject_kev.py --inject spring4shell    # Inject Spring4Shell
    python producers/inject_kev.py --inject all             # Inject all KEVs
    python producers/inject_kev.py --inject log4shell --env payments/api  # Custom env name
"""

import argparse
import hashlib
import json
import random
import sys
from datetime import datetime, timezone
from typing import Dict, List

from kafka import KafkaProducer

# Known Exploited Vulnerabilities with real data
# Includes CPE for NVD matching (Flox-style enrichment)
KEV_SCENARIOS = {
    'log4shell': {
        'cve_id': 'CVE-2021-44228',
        'name': 'Log4Shell',
        'package': 'log4j-core',
        'version': '2.14.1',
        'cpe_vendor': 'apache',
        'cpe_product': 'log4j',
        'severity': 'critical',
        'cvss_score': 10.0,
        'cwe_ids': ['CWE-917', 'CWE-502', 'CWE-400'],
        'published_at': '2021-12-10T00:00:00Z',
        'description': 'Apache Log4j2 JNDI RCE - actively exploited in the wild',
        'default_envs': ['payments/processor', 'platform/api-gateway', 'backend/order-service'],
    },
    'spring4shell': {
        'cve_id': 'CVE-2022-22965',
        'name': 'Spring4Shell',
        'package': 'spring-beans',
        'version': '5.3.17',
        'cpe_vendor': 'vmware',
        'cpe_product': 'spring_framework',
        'severity': 'critical',
        'cvss_score': 9.8,
        'cwe_ids': ['CWE-94'],
        'published_at': '2022-03-31T00:00:00Z',
        'description': 'Spring Framework RCE via data binding',
        'default_envs': ['backend/user-service', 'platform/auth-service', 'api/rest-gateway'],
    },
    'http2-rapid-reset': {
        'cve_id': 'CVE-2023-44487',
        'name': 'HTTP/2 Rapid Reset',
        'package': 'nginx',
        'version': '1.25.2',
        'cpe_vendor': 'nginx',
        'cpe_product': 'nginx',
        'severity': 'high',
        'cvss_score': 7.5,
        'cwe_ids': ['CWE-400'],
        'published_at': '2023-10-10T00:00:00Z',
        'description': 'HTTP/2 protocol DoS - record-breaking DDoS attacks',
        'default_envs': ['platform/ingress', 'frontend/loadbalancer', 'edge/cdn-proxy'],
    },
    'moveit': {
        'cve_id': 'CVE-2023-34362',
        'name': 'MOVEit SQLi',
        'package': 'moveit-transfer',
        'version': '2023.0.1',
        'cpe_vendor': 'progress',
        'cpe_product': 'moveit_transfer',
        'severity': 'critical',
        'cvss_score': 9.8,
        'cwe_ids': ['CWE-89'],
        'published_at': '2023-05-31T00:00:00Z',
        'description': 'MOVEit Transfer SQL injection - Cl0p ransomware campaigns',
        'default_envs': ['enterprise/file-transfer', 'compliance/secure-upload'],
    },
    'citrix-bleed': {
        'cve_id': 'CVE-2023-4966',
        'name': 'Citrix Bleed',
        'package': 'citrix-adc',
        'version': '13.1-49.13',
        'cpe_vendor': 'citrix',
        'cpe_product': 'netscaler_application_delivery_controller',
        'severity': 'critical',
        'cvss_score': 9.4,
        'cwe_ids': ['CWE-119'],
        'published_at': '2023-10-10T00:00:00Z',
        'description': 'Citrix NetScaler session token leak - LockBit ransomware',
        'default_envs': ['network/vpn-gateway', 'remote/citrix-access'],
    },
    'exchange-proxyshell': {
        'cve_id': 'CVE-2021-34473',
        'name': 'ProxyShell',
        'package': 'exchange-server',
        'version': '2019-CU10',
        'cpe_vendor': 'microsoft',
        'cpe_product': 'exchange_server',
        'severity': 'critical',
        'cvss_score': 9.8,
        'cwe_ids': ['CWE-918'],
        'published_at': '2021-07-13T00:00:00Z',
        'description': 'Microsoft Exchange pre-auth RCE chain',
        'default_envs': ['mail/exchange-prod', 'corporate/mail-server'],
    },
    'apache-path-traversal': {
        'cve_id': 'CVE-2021-41773',
        'name': 'Apache Path Traversal',
        'package': 'httpd',
        'version': '2.4.49',
        'cpe_vendor': 'apache',
        'cpe_product': 'http_server',
        'severity': 'high',
        'cvss_score': 7.5,
        'cwe_ids': ['CWE-22'],
        'published_at': '2021-10-05T00:00:00Z',
        'description': 'Apache HTTP Server path traversal and RCE',
        'default_envs': ['web/apache-frontend', 'legacy/httpd-server'],
    },
    'confluence-ognl': {
        'cve_id': 'CVE-2022-26134',
        'name': 'Confluence OGNL Injection',
        'package': 'confluence-server',
        'version': '7.18.0',
        'cpe_vendor': 'atlassian',
        'cpe_product': 'confluence_server',
        'severity': 'critical',
        'cvss_score': 9.8,
        'cwe_ids': ['CWE-917'],
        'published_at': '2022-06-02T00:00:00Z',
        'description': 'Atlassian Confluence OGNL injection RCE',
        'default_envs': ['collab/confluence-prod', 'wiki/knowledge-base'],
    },
}


def generate_nix_hash(name: str, version: str) -> str:
    """Generate deterministic Nix-style hash."""
    content = f"{name}@{version}"
    return hashlib.sha256(content.encode()).hexdigest()[:32]


def generate_env_hash(packages: List[Dict]) -> str:
    """Generate environment hash from packages."""
    nix_hashes = sorted([p['nix_hash'] for p in packages])
    content = '\n'.join(nix_hashes)
    return hashlib.sha256(content.encode()).hexdigest()[:32]


def create_producer() -> KafkaProducer:
    """Create Kafka producer."""
    return KafkaProducer(
        bootstrap_servers='localhost:9092',
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        key_serializer=lambda k: k.encode('utf-8') if k else None,
    )


def inject_kev(producer: KafkaProducer, scenario_key: str, custom_env: str = None):
    """Inject a KEV scenario into Kafka."""
    scenario = KEV_SCENARIOS[scenario_key]

    # Pick environment name
    if custom_env:
        env_name = custom_env
    else:
        env_name = random.choice(scenario['default_envs'])

    # Build identifiers
    purl_base = f"pkg:nix/{scenario['package']}"
    cpe = f"cpe:2.3:a:{scenario['cpe_vendor']}:{scenario['cpe_product']}:{scenario['version']}:*:*:*:*:*:*:*"
    cpe_base = f"cpe:2.3:a:{scenario['cpe_vendor']}:{scenario['cpe_product']}"

    # Create CVE record (with both PURL and CPE for matching)
    cve = {
        'cve_id': scenario['cve_id'],
        'package_purl': purl_base,
        'package_cpe': cpe_base,  # Base CPE for matching
        'severity': scenario['severity'],
        'status': 'active',
        'source': 'nvd',
        'published_at': scenario['published_at'],
        'cvss_score': scenario['cvss_score'],
        'cwe_ids': scenario['cwe_ids'],
    }

    # Create package with Nix hash and CPE (Flox-style)
    nix_hash = generate_nix_hash(scenario['package'], scenario['version'])
    nix_store_path = f"/nix/store/{nix_hash}-{scenario['package']}-{scenario['version']}"

    pkg = {
        'name': scenario['package'],
        'version': scenario['version'],
        'nix_hash': nix_hash,
        'nix_store_path': nix_store_path,
        'purl': f"{purl_base}@{scenario['version']}?nix-hash={nix_hash}",
        'purl_base': purl_base,
        'cpe': cpe,  # Full CPE for NVD matching
        'ecosystem': 'nix',
        'vex_status': 'affected',
    }

    # Create SBOM
    env_hash = generate_env_hash([pkg])
    sbom = {
        'hash': env_hash,
        'environment_id': env_name,
        'scan_timestamp': datetime.now(timezone.utc).isoformat(),
        'packages': [pkg],
    }

    # Publish CVE first, then SBOM
    producer.send('cve_feed', key=scenario['cve_id'], value=cve)
    producer.flush()

    producer.send('sbom_events', key=env_hash, value=sbom)
    producer.flush()

    print(f"  {scenario['name']:25} | {scenario['cve_id']:18} | {env_name} (hash={env_hash[:8]}...)")

    return env_hash


def list_scenarios():
    """Print available KEV scenarios."""
    print("\nAvailable KEV Scenarios:")
    print("=" * 80)
    print(f"{'Key':<20} {'Name':<25} {'CVE':<18} {'Severity':<10}")
    print("-" * 80)
    for key, s in KEV_SCENARIOS.items():
        print(f"{key:<20} {s['name']:<25} {s['cve_id']:<18} {s['severity']:<10}")
    print()
    print("Usage:")
    print("  python producers/inject_kev.py --inject log4shell")
    print("  python producers/inject_kev.py --inject all")
    print("  python producers/inject_kev.py --inject log4shell,spring4shell,moveit")
    print()


def main():
    parser = argparse.ArgumentParser(description="Inject KEV scenarios for demo")
    parser.add_argument('--list', action='store_true', help='List available scenarios')
    parser.add_argument('--inject', type=str, help='Scenario(s) to inject (comma-separated, or "all")')
    parser.add_argument('--env', type=str, help='Custom environment name')
    parser.add_argument('--count', type=int, default=1, help='Number of environments per scenario')

    args = parser.parse_args()

    if args.list or not args.inject:
        list_scenarios()
        return

    # Determine which scenarios to inject
    if args.inject.lower() == 'all':
        scenarios = list(KEV_SCENARIOS.keys())
    else:
        scenarios = [s.strip().lower() for s in args.inject.split(',')]

    # Validate scenarios
    invalid = [s for s in scenarios if s not in KEV_SCENARIOS]
    if invalid:
        print(f"Error: Unknown scenarios: {', '.join(invalid)}")
        print("Use --list to see available scenarios")
        sys.exit(1)

    # Create producer and inject
    producer = create_producer()

    print(f"\nInjecting {len(scenarios) * args.count} KEV scenario(s)...")
    print("-" * 80)

    for scenario in scenarios:
        for i in range(args.count):
            env_suffix = f"-{i+1}" if args.count > 1 else ""
            custom_env = f"{args.env}{env_suffix}" if args.env else None
            inject_kev(producer, scenario, custom_env)

    print("-" * 80)
    print(f"\nDone! Check Grafana: http://localhost:3000/d/sca-overview")
    print("KEV/EPSS enrichment is automatic - vulnerabilities will show:")
    print("  - cisa_kev: true")
    print("  - epss_score: (from FIRST API)")
    print("  - alert_tier: 1 (Break Glass)")
    print("  - tier_reason: KEV + Critical")


if __name__ == '__main__':
    main()
