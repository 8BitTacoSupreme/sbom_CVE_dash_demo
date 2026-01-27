#!/usr/bin/env python3
"""
GHSA Producer - Fetches GitHub Security Advisories and publishes to cve_feed.

GHSA provides high-quality, GitHub-reviewed vulnerability data in OSV format.
This producer queries the GHSA API and publishes advisories to the cve_feed topic
for processing by the stream processor.

Usage:
    python ghsa_producer.py --recent        # Fetch recent advisories
    python ghsa_producer.py --severity critical  # Fetch critical only
    python ghsa_producer.py --continuous    # Poll continuously
    python ghsa_producer.py --package npm lodash  # Query specific package
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clients.ghsa_client import GHSAClient

# Kafka imports (optional)
try:
    from kafka import KafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False


def create_kafka_producer():
    """Create Kafka producer if available."""
    if not KAFKA_AVAILABLE:
        print("Warning: kafka-python not installed")
        return None

    bootstrap_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

    try:
        return KafkaProducer(
            bootstrap_servers=bootstrap_servers.split(","),
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
        )
    except Exception as e:
        print(f"Warning: Could not connect to Kafka: {e}")
        return None


def publish_advisories(producer, advisories, client):
    """Publish advisories to Kafka cve_feed topic."""
    published = 0
    for advisory in advisories:
        record = client.to_cve_record(advisory)
        key = record["cve_id"]
        producer.send("cve_feed", key=key, value=record)
        print(f"  Published: {key} ({record['severity']})")
        published += 1

    producer.flush()
    return published


def main():
    parser = argparse.ArgumentParser(
        description="Fetch GitHub Security Advisories and publish to cve_feed"
    )
    parser.add_argument("--recent", action="store_true",
                        help="Fetch recent advisories")
    parser.add_argument("--severity", type=str,
                        choices=["critical", "high", "medium", "low"],
                        help="Filter by severity")
    parser.add_argument("--since-hours", type=int, default=24,
                        help="Hours to look back (default: 24)")
    parser.add_argument("--continuous", action="store_true",
                        help="Poll continuously")
    parser.add_argument("--interval", type=int, default=300,
                        help="Poll interval in seconds (default: 300)")
    parser.add_argument("--package", nargs=2, metavar=("ECOSYSTEM", "NAME"),
                        help="Query specific package (e.g., --package npm lodash)")
    parser.add_argument("--cve", type=str,
                        help="Query specific CVE ID")
    parser.add_argument("--demo", action="store_true",
                        help="Demo mode - show what would be published without Kafka")

    args = parser.parse_args()

    client = GHSAClient()

    # Demo mode - just show advisories
    if args.demo:
        print("=== GHSA Demo Mode ===\n")

        if args.package:
            ecosystem, name = args.package
            print(f"Querying advisories for {ecosystem}/{name}...")
            advisories = client.query_by_package(ecosystem, name)
        elif args.cve:
            print(f"Querying advisory for {args.cve}...")
            advisory = client.query_by_cve(args.cve)
            advisories = [advisory] if advisory else []
        else:
            since = datetime.now(timezone.utc) - timedelta(hours=args.since_hours)
            print(f"Querying recent advisories (since {since.isoformat()})...")
            advisories = client.query_recent(since=since, severity=args.severity)

        print(f"Found {len(advisories)} advisories\n")

        for advisory in advisories[:10]:
            cve_id = advisory.cve_id or advisory.ghsa_id
            print(f"{cve_id} ({advisory.severity})")
            print(f"  {advisory.summary[:70]}...")
            if advisory.cvss_score:
                print(f"  CVSS: {advisory.cvss_score}")
            if advisory.vulnerabilities:
                for vuln in advisory.vulnerabilities[:2]:
                    pkg = vuln.get("package", {})
                    print(f"  Package: {pkg.get('ecosystem')}/{pkg.get('name')}")
                    print(f"  Vulnerable: {vuln.get('vulnerable_version_range', 'unknown')}")
            print()

        if len(advisories) > 10:
            print(f"... and {len(advisories) - 10} more advisories")

        return

    # Kafka mode
    producer = create_kafka_producer()
    if not producer:
        print("Error: Could not connect to Kafka")
        sys.exit(1)

    since = datetime.now(timezone.utc) - timedelta(hours=args.since_hours)

    print(f"[GHSA] Starting GHSA producer")
    print(f"  Severity filter: {args.severity or 'all'}")
    print(f"  Looking back: {args.since_hours} hours")
    if args.continuous:
        print(f"  Continuous mode: polling every {args.interval}s")
    print()

    try:
        while True:
            # Fetch advisories
            if args.package:
                ecosystem, name = args.package
                advisories = client.query_by_package(ecosystem, name)
                print(f"[GHSA] Fetched {len(advisories)} advisories for {ecosystem}/{name}")
            elif args.cve:
                advisory = client.query_by_cve(args.cve)
                advisories = [advisory] if advisory else []
                print(f"[GHSA] Fetched {len(advisories)} advisories for {args.cve}")
            else:
                advisories = client.query_recent(since=since, severity=args.severity)
                print(f"[GHSA] Fetched {len(advisories)} advisories since {since.isoformat()}")

            # Publish to Kafka
            if advisories:
                published = publish_advisories(producer, advisories, client)
                print(f"[GHSA] Published {published} advisories to cve_feed")

            if not args.continuous:
                break

            # Update since for next iteration
            since = datetime.now(timezone.utc)
            print(f"\n[GHSA] Sleeping {args.interval}s until next poll...")
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[GHSA] Stopped")
    finally:
        producer.close()


if __name__ == "__main__":
    main()
