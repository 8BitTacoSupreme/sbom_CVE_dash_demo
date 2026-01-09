#!/usr/bin/env python3
"""
SBOM Producer - Demonstrates the importance of PURL enrichment for CVE matching.

This producer reads real Flox SPDX JSON files and can output in two modes:
  - legacy: No PURL enrichment (CVE matching will FAIL)
  - enhanced: With PURL enrichment (CVE matching will WORK)

Usage:
    # Legacy mode (no PURL) - will NOT match CVEs
    python sbom_producer.py --sbom=emacs-30.2.spdx.json --format=legacy

    # Enhanced mode (with PURL) - WILL match CVEs
    python sbom_producer.py --sbom=emacs-30.2.spdx.json --format=enhanced

    # Produce to Kafka
    python sbom_producer.py --sbom=emacs-30.2.spdx.json --format=enhanced --kafka

    # Inject a known vulnerable package for demo
    python sbom_producer.py --sbom=emacs-30.2.spdx.json --format=enhanced --inject-hit --kafka

    # Generate random mock SBOMs (legacy behavior)
    python sbom_producer.py --mock --env=web-app-v1 --inject-hit
"""

import argparse
import json
import os
import random
import re
import string
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from kafka import KafkaProducer
from kafka.errors import KafkaError

# Configuration
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
SBOM_TOPIC = "sbom_events"


# =============================================================================
# PURL Generation (for enhanced mode)
# =============================================================================

def normalize_package_name(name):
    """
    Normalize package name for PURL generation.
    Remove common suffixes like -out, -lib, -dev, etc.
    """
    suffixes = ['-out', '-lib', '-dev', '-bin', '-doc', '-man', '-info']
    normalized = name.lower()
    for suffix in suffixes:
        if normalized.endswith(suffix):
            normalized = normalized[:-len(suffix)]
            break
    return normalized


def extract_nix_hash(store_path):
    """Extract the hash portion from a nix store path."""
    match = re.search(r'/nix/store/([a-z0-9]+)-', store_path)
    return match.group(1) if match else None


def generate_purl(name, version, nix_hash=None):
    """
    Generate a Package URL (PURL) for a Nix package.
    Format: pkg:nix/<name>@<version>[?nix-hash=<hash>]
    """
    normalized_name = normalize_package_name(name)
    purl = f"pkg:nix/{normalized_name}@{version}"
    if nix_hash:
        purl += f"?nix-hash={nix_hash}"
    return purl


def extract_purl_from_spdx_package(pkg, include_purl=True):
    """
    Extract or generate PURL from an SPDX package.

    Returns a simplified package dict for the stream processor:
    {
        'purl': 'pkg:nix/name@version',
        'name': 'name',
        'version': 'version'
    }
    """
    name = pkg.get("name", "unknown")
    version = pkg.get("versionInfo", "unknown")

    # Try to get existing PURL from externalRefs
    purl = None
    nix_hash = None

    for ref in pkg.get("externalRefs", []):
        ref_type = ref.get("referenceType", "")
        ref_loc = ref.get("referenceLocator", "")

        if ref_type == "purl":
            purl = ref_loc
        elif ref_type == "nix-store-path":
            nix_hash = extract_nix_hash(ref_loc)

    # Generate PURL if not present and enhanced mode is requested
    if purl is None and include_purl:
        purl = generate_purl(name, version, nix_hash)

    return {
        'purl': purl,  # None in legacy mode
        'name': name,
        'version': version
    }


# =============================================================================
# Demo Package Injection
# =============================================================================

def create_vulnerable_package(include_purl=True):
    """
    Create the demo vulnerable package (log4j@2.14.1 for Log4Shell).

    PURL will be: pkg:nix/log4j@2.14.1
    This matches the CVE seeded by cve_producer.py --seed-flox
    """
    pkg = {
        'name': 'log4j',
        'version': '2.14.1'
    }

    if include_purl:
        pkg['purl'] = 'pkg:nix/log4j@2.14.1'
    else:
        pkg['purl'] = None

    return pkg


# =============================================================================
# SPDX File Processing
# =============================================================================

def process_spdx_file(sbom_path, format_mode, environment_id=None, inject_hit=False):
    """
    Process an SPDX SBOM file and convert to stream processor format.

    Args:
        sbom_path: Path to SPDX JSON file
        format_mode: 'legacy' (no PURL) or 'enhanced' (with PURL)
        environment_id: Optional environment identifier
        inject_hit: If True, inject log4j@2.14.1 for demo

    Returns:
        SBOM event dict ready for Kafka
    """
    with open(sbom_path) as f:
        spdx = json.load(f)

    include_purl = (format_mode == "enhanced")

    # Convert SPDX packages to simple format
    packages = []
    for pkg in spdx.get("packages", []):
        simple_pkg = extract_purl_from_spdx_package(pkg, include_purl=include_purl)
        # Only include packages with valid names
        if simple_pkg['name'] != 'unknown':
            packages.append(simple_pkg)

    # Inject vulnerable package if requested
    if inject_hit:
        vuln_pkg = create_vulnerable_package(include_purl=include_purl)
        packages.insert(0, vuln_pkg)
        print(f"  [INJECT] Added vulnerable package: log4j@2.14.1" +
              (f" (purl: {vuln_pkg['purl']})" if vuln_pkg['purl'] else " (no purl - legacy mode)"))

    # Derive environment_id from SBOM name if not provided
    if not environment_id:
        environment_id = spdx.get("name", sbom_path.stem).replace(" ", "-").lower()

    return {
        "environment_id": environment_id,
        "environment_hash": f"sha256:{hash(str(spdx)) & 0xFFFFFFFFFFFFFFFF:016x}",
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "format_mode": format_mode,
        "source_file": sbom_path.name,
        "packages": packages
    }


# =============================================================================
# Mock SBOM Generation (legacy behavior for random SBOMs)
# =============================================================================

MOCK_PACKAGES = [
    {"name": "lodash", "versions": ["4.17.21", "4.17.20", "4.17.19"]},
    {"name": "express", "versions": ["4.18.2", "4.17.1", "4.16.4"]},
    {"name": "react", "versions": ["18.2.0", "17.0.2", "16.14.0"]},
    {"name": "axios", "versions": ["1.4.0", "0.27.2", "0.21.1"]},
    {"name": "moment", "versions": ["2.29.4", "2.29.1", "2.24.0"]},
]

# The vulnerable package for the original demo
VULNERABLE_PACKAGE = {
    "purl": "pkg:generic/vulnerable-lib@1.0.0",
    "name": "vulnerable-lib",
    "version": "1.0.0"
}


def generate_random_environment_id():
    """Generate a random environment ID."""
    prefixes = ["web-app", "api-service", "worker", "scheduler", "gateway"]
    return f"{random.choice(prefixes)}-v{random.randint(1, 99)}"


def generate_random_digest():
    """Generate a random SHA256 digest."""
    return f"sha256:{''.join(random.choices(string.hexdigits.lower(), k=64))}"


def generate_mock_sbom(environment_id=None, inject_hit=False):
    """Generate a mock SBOM with random packages."""
    packages = []

    # Add random packages
    selected = random.sample(MOCK_PACKAGES, min(5, len(MOCK_PACKAGES)))
    for pkg in selected:
        version = random.choice(pkg["versions"])
        packages.append({
            "purl": f"pkg:npm/{pkg['name']}@{version}",
            "name": pkg["name"],
            "version": version
        })

    # Inject vulnerable package
    if inject_hit:
        packages.insert(0, VULNERABLE_PACKAGE.copy())
        print(f"  [INJECT] Added vulnerable package: {VULNERABLE_PACKAGE['purl']}")

    return {
        "environment_id": environment_id or generate_random_environment_id(),
        "environment_hash": generate_random_digest(),
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "format_mode": "mock",
        "packages": packages
    }


# =============================================================================
# Kafka Producer
# =============================================================================

def create_producer():
    """Create and return a Kafka producer."""
    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            acks="all",
            retries=3
        )
        return producer
    except KafkaError as e:
        print(f"Failed to create Kafka producer: {e}")
        sys.exit(1)


def publish_sbom(producer, sbom):
    """Publish an SBOM to Kafka."""
    try:
        future = producer.send(
            SBOM_TOPIC,
            key=sbom["environment_id"],
            value=sbom
        )
        record_metadata = future.get(timeout=10)
        print(f"  Published to {record_metadata.topic}:{record_metadata.partition} @ offset {record_metadata.offset}")
        return True
    except KafkaError as e:
        print(f"  Failed to publish SBOM: {e}")
        return False


# =============================================================================
# Output Helpers
# =============================================================================

def print_summary(sbom):
    """Print a human-readable summary of the SBOM."""
    format_mode = sbom.get('format_mode', 'unknown')

    print(f"\n{'='*60}")
    print(f"SBOM Producer - {format_mode.upper()} MODE")
    print(f"{'='*60}")
    print(f"Environment: {sbom['environment_id']}")
    if 'source_file' in sbom:
        print(f"Source:      {sbom['source_file']}")
    print(f"Packages:    {len(sbom['packages'])}")
    print(f"Timestamp:   {sbom['scan_timestamp']}")
    print(f"{'='*60}")

    # Show sample packages
    print("\nSample packages:")
    for pkg in sbom['packages'][:5]:
        purl = pkg.get('purl')
        name = pkg.get('name', 'unknown')
        version = pkg.get('version', '?')

        if purl:
            print(f"  - {name}@{version}")
            print(f"      purl: {purl}  <-- JOIN KEY")
        else:
            print(f"  - {name}@{version}")
            print(f"      purl: (none - legacy mode)")

    if len(sbom['packages']) > 5:
        print(f"\n  ... and {len(sbom['packages']) - 5} more packages")

    # Highlight PURL status
    has_purls = any(pkg.get('purl') for pkg in sbom['packages'])

    print(f"\n{'='*60}")
    if has_purls:
        print("STATUS: Packages have PURLs - CVE matching ENABLED")
    else:
        print("STATUS: No PURLs found - CVE matching will FAIL")
    print(f"{'='*60}\n")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SBOM Producer for SCA Demo - supports real SPDX files and mock generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # SPDX file mode
    parser.add_argument("--sbom", "-s", type=Path,
                        help="Path to SPDX JSON file (e.g., emacs-30.2.spdx.json)")
    parser.add_argument("--format", "-f", dest="format_mode",
                        choices=["legacy", "enhanced"], default="enhanced",
                        help="Output format: 'legacy' (no PURL) or 'enhanced' (with PURL)")

    # Mock mode (legacy behavior)
    parser.add_argument("--mock", action="store_true",
                        help="Generate mock SBOM instead of reading SPDX file")
    parser.add_argument("--continuous", action="store_true",
                        help="Continuously generate mock SBOMs")
    parser.add_argument("--interval", type=int, default=10,
                        help="Interval between mock SBOMs in continuous mode (seconds)")
    parser.add_argument("--count", type=int, default=1,
                        help="Number of mock SBOMs to generate")

    # Common options
    parser.add_argument("--env", "-e", dest="environment_id",
                        help="Environment identifier (default: derived from SBOM or random)")
    parser.add_argument("--inject-hit", action="store_true",
                        help="Inject a vulnerable package for demo")
    parser.add_argument("--kafka", "-k", action="store_true",
                        help="Produce to Kafka (otherwise just print)")
    parser.add_argument("--json", action="store_true",
                        help="Output full JSON instead of summary")

    args = parser.parse_args()

    # Validate arguments
    if not args.mock and not args.sbom:
        parser.print_help()
        print("\nError: Either --sbom or --mock is required")
        sys.exit(1)

    if args.sbom and not args.sbom.exists():
        print(f"ERROR: SBOM file not found: {args.sbom}", file=sys.stderr)
        sys.exit(1)

    print(f"SBOM Producer starting...")
    print(f"  Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"  Topic: {SBOM_TOPIC}")
    print(f"  Mode: {'SPDX file' if args.sbom else 'Mock generation'}")
    if args.sbom:
        print(f"  Format: {args.format_mode}")

    producer = None
    if args.kafka:
        producer = create_producer()
        print("  Connected to Kafka")

    try:
        if args.sbom:
            # Process SPDX file
            sbom = process_spdx_file(
                sbom_path=args.sbom,
                format_mode=args.format_mode,
                environment_id=args.environment_id,
                inject_hit=args.inject_hit
            )

            if args.kafka:
                publish_sbom(producer, sbom)

            if args.json:
                print(json.dumps(sbom, indent=2))
            else:
                print_summary(sbom)

        elif args.mock:
            # Generate mock SBOMs
            if args.continuous:
                print(f"\nContinuous mode: generating SBOM every {args.interval}s (Ctrl+C to stop)")
                while True:
                    sbom = generate_mock_sbom(
                        environment_id=args.environment_id,
                        inject_hit=args.inject_hit
                    )
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] SBOM for {sbom['environment_id']} ({len(sbom['packages'])} packages)")

                    if args.kafka:
                        publish_sbom(producer, sbom)
                    elif args.json:
                        print(json.dumps(sbom, indent=2))
                    else:
                        print_summary(sbom)

                    time.sleep(args.interval)
            else:
                for i in range(args.count):
                    sbom = generate_mock_sbom(
                        environment_id=args.environment_id,
                        inject_hit=args.inject_hit
                    )
                    print(f"\n[{i+1}/{args.count}] SBOM for {sbom['environment_id']} ({len(sbom['packages'])} packages)")

                    if args.kafka:
                        publish_sbom(producer, sbom)
                    elif args.json:
                        print(json.dumps(sbom, indent=2))
                    else:
                        print_summary(sbom)

                    if i < args.count - 1:
                        time.sleep(0.5)

        print("\nDone!")

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        if producer:
            producer.close()


if __name__ == "__main__":
    main()
