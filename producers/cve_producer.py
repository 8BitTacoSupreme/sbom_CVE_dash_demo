#!/usr/bin/env python3
"""
CVE Producer - Publishes CVE records to the Kafka cve_feed topic.

Usage:
    python cve_producer.py --publish-new-cve --target=vulnerable-lib --severity=critical
    python cve_producer.py --update-status --cve=CVE-2024-0001 --status=fixed
    python cve_producer.py --list-cves
"""

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone

from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError

# Configuration
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
CVE_TOPIC = "cve_feed"

# Pre-defined CVE for the demo "hit" (generic vulnerable-lib)
DEMO_CVE = {
    "cve_id": "CVE-2024-99999",
    "package_purl": "pkg:generic/vulnerable-lib",
    "affected_versions": ">=1.0.0,<1.0.5",
    "severity": "critical",
    "status": "active",
    "description": "Remote code execution vulnerability in vulnerable-lib",
    "cvss_score": 9.8
}

# Additional mock CVEs for realistic feed (npm packages)
MOCK_CVES = [
    {
        "cve_id": "CVE-2024-0001",
        "package_purl": "pkg:npm/lodash",
        "affected_versions": "<4.17.21",
        "severity": "high",
        "description": "Prototype pollution vulnerability",
        "cvss_score": 7.5
    },
    {
        "cve_id": "CVE-2024-0002",
        "package_purl": "pkg:npm/express",
        "affected_versions": "<4.17.3",
        "severity": "medium",
        "description": "Open redirect vulnerability",
        "cvss_score": 5.4
    },
    {
        "cve_id": "CVE-2024-0003",
        "package_purl": "pkg:npm/jsonwebtoken",
        "affected_versions": "<9.0.0",
        "severity": "critical",
        "description": "Algorithm confusion attack",
        "cvss_score": 9.1
    },
    {
        "cve_id": "CVE-2024-0004",
        "package_purl": "pkg:npm/moment",
        "affected_versions": "<2.29.4",
        "severity": "high",
        "description": "Path traversal vulnerability",
        "cvss_score": 7.8
    },
]

# =============================================================================
# Flox SEM Demo CVEs - Match packages in real Flox SBOMs (e.g., emacs-30.2.spdx.json)
# =============================================================================

# Log4Shell - the demo "hit" for Flox SBOMs (injected via --inject-hit)
FLOX_DEMO_CVE = {
    "cve_id": "CVE-2021-44228",
    "package_purl": "pkg:nix/log4j",
    "affected_versions": ">=2.0.0,<2.15.0",
    "severity": "critical",
    "status": "active",
    "description": "Log4Shell - Remote code execution via JNDI lookup in log messages",
    "cvss_score": 10.0
}

# CVEs that match real packages in Flox SBOMs
# Distribution: 1 critical, 4 high, 10 medium, 20 low
FLOX_CVES = [
    # HIGH severity (4)
    {"cve_id": "CVE-2023-29491", "package_purl": "pkg:nix/ncurses6", "severity": "high", "cvss_score": 7.8,
     "description": "ncurses memory corruption via malformed terminfo database"},
    {"cve_id": "CVE-2024-4603", "package_purl": "pkg:nix/readline", "severity": "high", "cvss_score": 7.5,
     "description": "readline buffer overflow in history expansion"},
    {"cve_id": "CVE-2023-34969", "package_purl": "pkg:nix/dbus", "severity": "high", "cvss_score": 7.1,
     "description": "D-Bus privilege escalation via activation bypass"},
    {"cve_id": "CVE-2024-2961", "package_purl": "pkg:nix/gmp", "severity": "high", "cvss_score": 7.0,
     "description": "GMP integer overflow in mpz functions"},

    # MEDIUM severity (10)
    {"cve_id": "CVE-2024-2398", "package_purl": "pkg:nix/curlhttp3", "severity": "medium", "cvss_score": 5.3,
     "description": "curl HTTP/2 push headers memory leak"},
    {"cve_id": "CVE-2024-3094", "package_purl": "pkg:nix/libssh2", "severity": "medium", "cvss_score": 5.9,
     "description": "libssh2 remote code execution via crafted SSH packets"},
    {"cve_id": "CVE-2024-45491", "package_purl": "pkg:nix/expat", "severity": "medium", "cvss_score": 5.5,
     "description": "Expat DTD parsing integer overflow"},
    {"cve_id": "CVE-2024-31449", "package_purl": "pkg:nix/zstd", "severity": "medium", "cvss_score": 5.3,
     "description": "Zstandard decompression memory corruption"},
    {"cve_id": "CVE-2024-31083", "package_purl": "pkg:nix/libjpeg_turbo", "severity": "medium", "cvss_score": 5.5,
     "description": "libjpeg-turbo heap buffer overflow in JPEG decoding"},
    {"cve_id": "CVE-2024-25082", "package_purl": "pkg:nix/harfbuzz", "severity": "medium", "cvss_score": 5.0,
     "description": "HarfBuzz font shaping memory safety issue"},
    {"cve_id": "CVE-2024-28182", "package_purl": "pkg:nix/libwebp", "severity": "medium", "cvss_score": 5.5,
     "description": "libwebp heap buffer overflow in WebP decoding"},
    {"cve_id": "CVE-2024-28757", "package_purl": "pkg:nix/libevent", "severity": "medium", "cvss_score": 5.3,
     "description": "libevent HTTP request smuggling vulnerability"},
    {"cve_id": "CVE-2024-1580", "package_purl": "pkg:nix/libX11", "severity": "medium", "cvss_score": 5.5,
     "description": "libX11 out-of-bounds write in XIM protocol handling"},
    {"cve_id": "CVE-2024-21892", "package_purl": "pkg:nix/unbound", "severity": "medium", "cvss_score": 5.3,
     "description": "Unbound DNS resolver cache poisoning"},

    # LOW severity (20)
    {"cve_id": "CVE-2024-45490", "package_purl": "pkg:nix/expat", "severity": "low", "cvss_score": 3.7,
     "description": "Expat XML parser negative length handling issue"},
    {"cve_id": "CVE-2024-32002", "package_purl": "pkg:nix/attr", "severity": "low", "cvss_score": 3.3,
     "description": "Extended attributes handling minor info disclosure"},
    {"cve_id": "CVE-2024-26461", "package_purl": "pkg:nix/libgpg-error", "severity": "low", "cvss_score": 3.3,
     "description": "libgpg-error memory leak in error string handling"},
    {"cve_id": "CVE-2024-37370", "package_purl": "pkg:nix/libidn2", "severity": "low", "cvss_score": 3.7,
     "description": "libidn2 punycode encoding edge case"},
    {"cve_id": "CVE-2024-26462", "package_purl": "pkg:nix/fribidi", "severity": "low", "cvss_score": 3.3,
     "description": "FriBidi bidirectional text handling minor issue"},
    {"cve_id": "CVE-2024-32760", "package_purl": "pkg:nix/libpsl", "severity": "low", "cvss_score": 3.7,
     "description": "libpsl public suffix list parsing edge case"},
    {"cve_id": "CVE-2024-24806", "package_purl": "pkg:nix/libunistring", "severity": "low", "cvss_score": 3.3,
     "description": "libunistring normalization table minor issue"},
    {"cve_id": "CVE-2024-22365", "package_purl": "pkg:nix/libxcb", "severity": "low", "cvss_score": 3.3,
     "description": "libxcb event handling edge case"},
    {"cve_id": "CVE-2024-0567", "package_purl": "pkg:nix/gawk", "severity": "low", "cvss_score": 3.3,
     "description": "gawk regex engine minor issue"},
    {"cve_id": "CVE-2024-28085", "package_purl": "pkg:nix/util-linuxminimal", "severity": "low", "cvss_score": 3.3,
     "description": "util-linux minor privilege issue"},
    {"cve_id": "CVE-2024-28834", "package_purl": "pkg:nix/lzo", "severity": "low", "cvss_score": 3.7,
     "description": "LZO compression minor memory issue"},
    {"cve_id": "CVE-2024-0553", "package_purl": "pkg:nix/libcap", "severity": "low", "cvss_score": 3.3,
     "description": "libcap capability handling edge case"},
    {"cve_id": "CVE-2024-0727", "package_purl": "pkg:nix/tree-sitter", "severity": "low", "cvss_score": 3.7,
     "description": "tree-sitter parser minor memory issue"},
    {"cve_id": "CVE-2024-2236", "package_purl": "pkg:nix/libXt", "severity": "low", "cvss_score": 3.3,
     "description": "libXt widget handling minor issue"},
    {"cve_id": "CVE-2024-25629", "package_purl": "pkg:nix/libXfixes", "severity": "low", "cvss_score": 3.3,
     "description": "libXfixes region handling edge case"},
    {"cve_id": "CVE-2024-24577", "package_purl": "pkg:nix/libXcursor", "severity": "low", "cvss_score": 3.3,
     "description": "libXcursor cursor loading minor issue"},
    {"cve_id": "CVE-2024-0985", "package_purl": "pkg:nix/libotf", "severity": "low", "cvss_score": 3.3,
     "description": "libotf OpenType font parsing edge case"},
    {"cve_id": "CVE-2024-1394", "package_purl": "pkg:nix/gdk-pixbuf", "severity": "low", "cvss_score": 3.7,
     "description": "gdk-pixbuf image loading minor issue"},
    {"cve_id": "CVE-2024-22667", "package_purl": "pkg:nix/lerc", "severity": "low", "cvss_score": 3.3,
     "description": "LERC compression edge case handling"},
    {"cve_id": "CVE-2024-34397", "package_purl": "pkg:nix/libdeflate", "severity": "low", "cvss_score": 3.3,
     "description": "libdeflate decompression minor issue"},
]


def create_producer() -> KafkaProducer:
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


def publish_cve(producer: KafkaProducer, cve: dict) -> bool:
    """Publish a CVE to Kafka. Key is package_purl for compaction."""
    try:
        # Add timestamp if not present
        if "published_at" not in cve:
            cve["published_at"] = datetime.now(timezone.utc).isoformat()

        # Key is package_purl for compaction (latest CVE per package)
        key = cve["package_purl"]

        future = producer.send(CVE_TOPIC, key=key, value=cve)
        record_metadata = future.get(timeout=10)
        print(f"  Published to {record_metadata.topic}:{record_metadata.partition} @ offset {record_metadata.offset}")
        return True
    except KafkaError as e:
        print(f"  Failed to publish CVE: {e}")
        return False


def publish_demo_cve(producer: KafkaProducer, target: str, severity: str) -> bool:
    """Publish the demo CVE that triggers the alert."""
    cve = DEMO_CVE.copy()

    if target != "vulnerable-lib":
        cve["package_purl"] = f"pkg:generic/{target}"
        cve["cve_id"] = f"CVE-2024-{random.randint(10000, 99999)}"

    if severity:
        cve["severity"] = severity

    cve["published_at"] = datetime.now(timezone.utc).isoformat()
    cve["status"] = "active"

    print(f"\n[DEMO CVE] Publishing CVE for {cve['package_purl']}")
    print(f"  CVE ID: {cve['cve_id']}")
    print(f"  Severity: {cve['severity']}")
    print(f"  Affected: {cve['affected_versions']}")

    return publish_cve(producer, cve)


def update_cve_status(producer: KafkaProducer, cve_id: str, package_purl: str, status: str) -> bool:
    """Update the status of an existing CVE (e.g., mark as fixed)."""
    # Find the CVE in our mock data or create a minimal update
    cve = None
    for mock in MOCK_CVES + [DEMO_CVE]:
        if mock["cve_id"] == cve_id:
            cve = mock.copy()
            break

    if cve is None:
        if not package_purl:
            print(f"Error: CVE {cve_id} not found. Provide --package-purl for unknown CVEs.")
            return False
        cve = {
            "cve_id": cve_id,
            "package_purl": package_purl,
            "affected_versions": "*",
            "severity": "unknown"
        }

    cve["status"] = status
    cve["updated_at"] = datetime.now(timezone.utc).isoformat()

    print(f"\n[STATUS UPDATE] {cve_id} -> {status}")
    return publish_cve(producer, cve)


def seed_cve_feed(producer: KafkaProducer) -> None:
    """Seed the CVE feed with mock CVEs (excluding the demo CVE)."""
    print("\n[SEED] Populating CVE feed with mock npm CVEs...")
    for cve in MOCK_CVES:
        cve_copy = cve.copy()
        cve_copy["status"] = "active"
        cve_copy["published_at"] = datetime.now(timezone.utc).isoformat()
        print(f"  {cve_copy['cve_id']} -> {cve_copy['package_purl']}")
        publish_cve(producer, cve_copy)
    print(f"  Seeded {len(MOCK_CVES)} CVEs")


def seed_flox_cves(producer: KafkaProducer, include_log4j: bool = True, gradual: bool = False, duration: int = 120) -> None:
    """
    Seed the CVE feed with Flox-specific CVEs that match packages in real Flox SBOMs.

    Args:
        producer: Kafka producer
        include_log4j: Include the Log4Shell critical CVE
        gradual: If True, spread CVE publishing over time for dramatic effect
        duration: Total duration in seconds for gradual mode (default: 120s = 2 min)
    """
    print("\n[SEED-FLOX] Populating CVE feed with Flox-specific CVEs...")
    print("  These CVEs match packages in real Flox SBOMs (e.g., emacs-30.2.spdx.json)")

    cves_to_seed = FLOX_CVES.copy()

    # Include Log4Shell CVE (will only match if --inject-hit is used with SBOM producer)
    if include_log4j:
        cves_to_seed.insert(0, FLOX_DEMO_CVE)

    if gradual:
        # Sort by severity: low first, critical last for dramatic buildup
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        cves_to_seed.sort(key=lambda c: severity_order.get(c.get("severity", "low"), 0))

        delay = duration / len(cves_to_seed)
        print(f"  Gradual mode: publishing {len(cves_to_seed)} CVEs over {duration}s (~{delay:.1f}s each)")
        print()

    for i, cve in enumerate(cves_to_seed):
        cve_copy = cve.copy()
        cve_copy["status"] = "active"
        cve_copy["published_at"] = datetime.now(timezone.utc).isoformat()

        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵"
        }.get(cve_copy["severity"], "⚪")

        print(f"  {severity_emoji} {cve_copy['cve_id']:<16} [{cve_copy['severity']:<8}] -> {cve_copy['package_purl']}")
        publish_cve(producer, cve_copy)

        if gradual and i < len(cves_to_seed) - 1:
            time.sleep(delay)

    print(f"\n  Seeded {len(cves_to_seed)} Flox CVEs")


def list_cves() -> None:
    """List CVEs currently in the topic (reads from beginning)."""
    print(f"\nReading CVEs from {CVE_TOPIC}...")

    try:
        consumer = KafkaConsumer(
            CVE_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            consumer_timeout_ms=5000,
            value_deserializer=lambda m: json.loads(m.decode("utf-8"))
        )

        cves = {}
        for message in consumer:
            cve = message.value
            # Keep latest per package (simulates compaction view)
            cves[cve["package_purl"]] = cve

        consumer.close()

        if not cves:
            print("  No CVEs found in topic")
            return

        print(f"\nFound {len(cves)} unique package CVEs:\n")
        print(f"{'CVE ID':<20} {'Package':<30} {'Severity':<10} {'Status':<10}")
        print("-" * 70)
        for purl, cve in sorted(cves.items()):
            print(f"{cve.get('cve_id', 'N/A'):<20} {purl:<30} {cve.get('severity', 'N/A'):<10} {cve.get('status', 'N/A'):<10}")

    except KafkaError as e:
        print(f"Error reading topic: {e}")


def main():
    parser = argparse.ArgumentParser(description="CVE Producer for SCA Demo")

    # Actions
    parser.add_argument("--publish-new-cve", action="store_true",
                        help="Publish a new CVE (triggers demo alert)")
    parser.add_argument("--update-status", action="store_true",
                        help="Update status of existing CVE")
    parser.add_argument("--seed", action="store_true",
                        help="Seed the CVE feed with mock npm CVEs")
    parser.add_argument("--seed-flox", action="store_true",
                        help="Seed the CVE feed with Flox-specific CVEs (matches emacs SBOM)")
    parser.add_argument("--list-cves", action="store_true",
                        help="List CVEs in the topic")

    # Parameters
    parser.add_argument("--target", type=str, default="vulnerable-lib",
                        help="Target package name (default: vulnerable-lib)")
    parser.add_argument("--severity", type=str, choices=["critical", "high", "medium", "low"],
                        default="critical", help="CVE severity")
    parser.add_argument("--cve", type=str, help="CVE ID for status updates")
    parser.add_argument("--package-purl", type=str, help="Package PURL for status updates")
    parser.add_argument("--status", type=str, choices=["active", "disputed", "fixed"],
                        default="active", help="CVE status")
    parser.add_argument("--gradual", action="store_true",
                        help="Publish CVEs gradually over time (for dramatic demo effect)")
    parser.add_argument("--duration", type=int, default=120,
                        help="Duration in seconds for gradual mode (default: 120)")

    args = parser.parse_args()

    # Handle list separately (read-only)
    if args.list_cves:
        list_cves()
        return

    # Require an action
    if not any([args.publish_new_cve, args.update_status, args.seed, args.seed_flox]):
        parser.print_help()
        print("\nError: Specify an action: --publish-new-cve, --update-status, --seed, --seed-flox, or --list-cves")
        sys.exit(1)

    print(f"CVE Producer starting...")
    print(f"  Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"  Topic: {CVE_TOPIC}")

    producer = create_producer()
    print("  Connected to Kafka")

    try:
        if args.seed:
            seed_cve_feed(producer)

        if args.seed_flox:
            seed_flox_cves(producer, include_log4j=True, gradual=args.gradual, duration=args.duration)

        if args.publish_new_cve:
            publish_demo_cve(producer, args.target, args.severity)

        if args.update_status:
            if not args.cve:
                print("Error: --cve required for status updates")
                sys.exit(1)
            update_cve_status(producer, args.cve, args.package_purl, args.status)

        print("\nDone!")

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        producer.close()


if __name__ == "__main__":
    main()
