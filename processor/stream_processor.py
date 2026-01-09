#!/usr/bin/env python3
"""
Python Stream Processor - Joins SBOM events with CVE feed.

Replaces Flink for demo purposes. Maintains in-memory state and performs
bi-directional joins:
  1. New SBOM arrives → check against known CVEs
  2. New CVE arrives → check against cached SBOMs

Enhanced with:
  - Version range matching for automatic VEX inference (~80% resolution)
  - CISA KEV enrichment for prioritization of actively exploited CVEs
  - CWE tracking for vulnerability pattern analysis

Usage:
    python stream_processor.py
    python stream_processor.py --replay  # Replay from beginning of topics
"""

import argparse
import json
import os
import re
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from collections import defaultdict

import psycopg2
from psycopg2.extras import execute_values
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

# Add parent directory to path for imports (when running locally)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Optional imports for v3 features (version range VEX + KEV + EPSS + Risk)
# These may not be available in the Docker container
try:
    from analyzers.version_matcher import VersionMatcher
    from analyzers.risk_calculator import RiskCalculator
    from clients.kev_client import KEVClient
    from clients.epss_client import EPSSClient
    V3_FEATURES_AVAILABLE = True
except ImportError:
    V3_FEATURES_AVAILABLE = False
    VersionMatcher = None
    RiskCalculator = None
    KEVClient = None
    EPSSClient = None

# Configuration
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.environ.get("POSTGRES_PORT", "5432")
POSTGRES_DB = os.environ.get("POSTGRES_DB", "sca_demo")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "sca")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "sca_password")

# Topics
SBOM_TOPIC = "sbom_events"
CVE_TOPIC = "cve_feed"
MATCHES_TOPIC = "vulnerability_matches"

# State
cve_state = {}  # package_purl -> CVE record
cpe_state = {}  # package_cpe -> CVE record (for NVD matching)
sbom_state = defaultdict(dict)  # environment_id -> {package_purl: package_record}
sbom_cpe_state = defaultdict(dict)  # environment_id -> {package_cpe: package_record}
matches_state = set()  # (environment_id, cve_id) - for deduplication

# VEX inference, KEV enrichment, EPSS, and Risk scoring (v3 features - optional)
if V3_FEATURES_AVAILABLE:
    version_matcher = VersionMatcher()
    kev_client = KEVClient(cache_ttl_hours=1)  # Refresh KEV every hour
    epss_client = EPSSClient(cache_ttl_hours=24)  # EPSS updates daily
    risk_calculator = RiskCalculator()
else:
    version_matcher = None
    kev_client = None
    epss_client = None
    risk_calculator = None

# Threading
shutdown_event = threading.Event()


def get_db_connection():
    """Create a database connection."""
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD
    )


def extract_base_purl(purl: str) -> str:
    """Extract base package identifier without version (for matching)."""
    # pkg:npm/lodash@4.17.21 -> pkg:npm/lodash
    # pkg:generic/vulnerable-lib@1.0.0 -> pkg:generic/vulnerable-lib
    if not purl:
        return None
    match = re.match(r'^([^@]+)', purl)
    return match.group(1) if match else purl


def extract_base_cpe(cpe: str) -> str:
    """Extract base CPE identifier without version (for matching)."""
    # cpe:2.3:a:vendor:product:version:* -> cpe:2.3:a:vendor:product
    if not cpe:
        return None
    parts = cpe.split(':')
    if len(parts) >= 5:
        # Return type:part:vendor:product
        return ':'.join(parts[:5])
    return cpe


def create_producer() -> KafkaProducer:
    """Create Kafka producer for output topic."""
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
        acks="all"
    )


def publish_match(producer: KafkaProducer, match: dict):
    """Publish a vulnerability match to Kafka and PostgreSQL."""
    match_key = f"{match['environment_id']}:{match['cve_id']}"

    # Check for duplicate
    if match_key in matches_state:
        return
    matches_state.add(match_key)

    # Publish to Kafka
    try:
        producer.send(MATCHES_TOPIC, key=match_key, value=match)
        producer.flush()
    except KafkaError as e:
        print(f"  [ERROR] Failed to publish match to Kafka: {e}")

    # Write to PostgreSQL
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO vulnerability_matches
                (environment_id, cve_id, package_purl, package_cpe, severity,
                 cvss_score, detected_at, status, vex_status, vex_reason,
                 vex_justification, source, cwe_ids, cisa_kev, kev_date_added,
                 kev_ransomware, cve_published_at, epss_score, epss_percentile,
                 risk_score, alert_tier, tier_reason)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (environment_id, cve_id) DO UPDATE SET
                package_purl = COALESCE(EXCLUDED.package_purl, vulnerability_matches.package_purl),
                package_cpe = COALESCE(EXCLUDED.package_cpe, vulnerability_matches.package_cpe),
                severity = EXCLUDED.severity,
                cvss_score = EXCLUDED.cvss_score,
                detected_at = EXCLUDED.detected_at,
                status = EXCLUDED.status,
                vex_status = EXCLUDED.vex_status,
                vex_reason = EXCLUDED.vex_reason,
                vex_justification = EXCLUDED.vex_justification,
                source = EXCLUDED.source,
                cwe_ids = EXCLUDED.cwe_ids,
                cisa_kev = EXCLUDED.cisa_kev,
                kev_date_added = EXCLUDED.kev_date_added,
                kev_ransomware = EXCLUDED.kev_ransomware,
                cve_published_at = EXCLUDED.cve_published_at,
                epss_score = EXCLUDED.epss_score,
                epss_percentile = EXCLUDED.epss_percentile,
                risk_score = EXCLUDED.risk_score,
                alert_tier = EXCLUDED.alert_tier,
                tier_reason = EXCLUDED.tier_reason
        """, (
            match['environment_id'],
            match['cve_id'],
            match.get('package_purl'),
            match.get('package_cpe'),
            match['severity'],
            match.get('cvss_score'),
            match['detected_at'],
            match['status'],
            match.get('vex_status', 'affected'),
            match.get('vex_reason'),
            match.get('vex_justification'),
            match.get('source', 'mock'),
            match.get('cwe_ids'),
            match.get('cisa_kev', False),
            match.get('kev_date_added'),
            match.get('kev_ransomware', False),
            match.get('cve_published_at'),
            match.get('epss_score'),
            match.get('epss_percentile'),
            match.get('risk_score'),
            match.get('alert_tier', 3),
            match.get('tier_reason')
        ))

        # Also log to audit table
        cur.execute("""
            INSERT INTO detection_audit_log
                (environment_id, cve_id, package_purl, severity, event_type, cve_published_at)
            VALUES (%s, %s, %s, %s, 'detected', %s)
        """, (
            match['environment_id'],
            match['cve_id'],
            match.get('package_purl') or match.get('package_cpe'),
            match['severity'],
            match.get('cve_published_at')
        ))

        conn.commit()
        cur.close()
        conn.close()
    except psycopg2.Error as e:
        print(f"  [ERROR] Failed to write match to PostgreSQL: {e}")

    # Build status indicators for logging
    markers = []
    tier = match.get('alert_tier', 3)
    tier_names = {1: "BREAK-GLASS", 2: "IMMEDIATE", 3: "STANDARD"}
    markers.append(f"T{tier}:{tier_names.get(tier, 'STANDARD')}")
    if match.get('risk_score'):
        markers.append(f"Risk={match['risk_score']:.0f}")
    if match.get('epss_score'):
        markers.append(f"EPSS={match['epss_score']:.1%}")
    if match.get('cisa_kev'):
        markers.append("KEV!")
    if match.get('vex_status') == 'not_affected':
        markers.append(f"VEX:{match.get('vex_reason', 'not_affected')}")
    marker_str = f" [{', '.join(markers)}]" if markers else ""
    print(f"  [MATCH] {match['environment_id']} <-> {match['cve_id']} ({match['severity']}){marker_str}")


def create_enriched_match(
    environment_id: str,
    cve: dict,
    pkg: dict,
    purl: str = None,
    cpe: str = None
) -> dict:
    """
    Create an enriched match record with version range VEX and KEV data.

    This function:
    1. Checks if package version is in the CVE's affected range (auto-VEX)
    2. Enriches with CISA KEV status (prioritization)
    3. Includes CWE IDs and CVSS score for analysis

    Args:
        environment_id: Environment where vulnerability was detected
        cve: CVE record with vulnerability details
        pkg: Package record from SBOM
        purl: Package URL (optional)
        cpe: CPE identifier (optional)

    Returns:
        Enriched match record ready for publish_match()
    """
    cve_id = cve.get('cve_id')
    pkg_version = pkg.get('version')

    # Start with package-level VEX status (e.g., from patch detection)
    vex_status = pkg.get('vex_status', 'affected')
    vex_reason = pkg.get('vex_reason')
    vex_justification = pkg.get('vex_justification')

    # Version range check (only if not already marked as not_affected)
    # This is a v3 feature - requires version_matcher
    if version_matcher and vex_status != 'not_affected' and pkg_version:
        affected_versions = cve.get('affected_versions', [])

        # Check OSV-style ranges
        if affected_versions:
            is_affected, reason = version_matcher.check_osv_ranges(
                pkg_version, affected_versions
            )
            if not is_affected:
                vex_status = 'not_affected'
                vex_reason = reason
                vex_justification = f"Package version {pkg_version} is not in affected range"

        # Check NVD CPE-style ranges (from cpe_matches)
        cpe_matches = cve.get('cpe_matches', [])
        if cpe_matches and vex_status != 'not_affected':
            is_affected, reason = version_matcher.check_nvd_cpe_match(
                pkg_version, cpe_matches
            )
            if not is_affected:
                vex_status = 'not_affected'
                vex_reason = reason
                vex_justification = f"Package version {pkg_version} is not in affected CPE range"

    # KEV enrichment (v3 feature - requires kev_client)
    cisa_kev = False
    kev_date_added = None
    kev_ransomware = False
    if kev_client and cve_id:
        kev_entry = kev_client.get_kev_details(cve_id)
        if kev_entry:
            cisa_kev = True
            kev_date_added = kev_entry.date_added.isoformat() if kev_entry.date_added else None
            kev_ransomware = kev_entry.known_ransomware_use

    # EPSS enrichment (v3 feature - requires epss_client)
    epss_score = None
    epss_percentile = None
    if epss_client and cve_id:
        epss_data = epss_client.get_epss(cve_id)
        if epss_data:
            epss_score = epss_data.score
            epss_percentile = epss_data.percentile

    # Risk calculation and tier assignment (v3 feature - requires risk_calculator)
    risk_score = None
    alert_tier = 3
    tier_reason = "Standard review"
    severity = cve.get('severity', 'unknown')
    if risk_calculator:
        risk = risk_calculator.calculate(
            cvss_score=cve.get('cvss_score'),
            epss_score=epss_score,
            cisa_kev=cisa_kev,
            severity=severity
        )
        risk_score = risk.risk_score
        alert_tier = risk.tier
        tier_reason = risk.trigger_reason

    return {
        'environment_id': environment_id,
        'cve_id': cve_id,
        'package_purl': purl or pkg.get('purl'),
        'package_cpe': cpe or pkg.get('cpe'),
        'severity': severity,
        'cvss_score': cve.get('cvss_score'),
        'detected_at': datetime.now(timezone.utc).isoformat(),
        'status': 'active',
        'vex_status': vex_status,
        'vex_reason': vex_reason,
        'vex_justification': vex_justification,
        'source': cve.get('source', 'mock'),
        'cve_published_at': cve.get('published_at'),
        'cwe_ids': cve.get('cwe_ids'),
        'cisa_kev': cisa_kev,
        'kev_date_added': kev_date_added,
        'kev_ransomware': kev_ransomware,
        'epss_score': epss_score,
        'epss_percentile': epss_percentile,
        'risk_score': risk_score,
        'alert_tier': alert_tier,
        'tier_reason': tier_reason,
    }


def process_sbom(sbom: dict, producer: KafkaProducer):
    """Process an incoming SBOM event."""
    environment_id = sbom.get('environment_id')
    packages = sbom.get('packages', [])

    print(f"[SBOM] {environment_id} with {len(packages)} packages")

    # Update SBOM state
    for pkg in packages:
        purl = pkg.get('purl')
        cpe = pkg.get('cpe')

        pkg_record = {
            'purl': purl,
            'cpe': cpe,
            'name': pkg.get('name'),
            'version': pkg.get('version'),
            'vex_status': pkg.get('vex_status', 'affected'),
            'vex_reason': pkg.get('vex_reason'),
            'vex_justification': pkg.get('vex_justification'),
            'scan_timestamp': sbom.get('scan_timestamp')
        }

        # Store by PURL
        if purl:
            base_purl = extract_base_purl(purl)
            sbom_state[environment_id][base_purl] = pkg_record

            # Check against known PURL CVEs
            if base_purl in cve_state:
                cve = cve_state[base_purl]
                if cve.get('status') == 'active':
                    match = create_enriched_match(
                        environment_id=environment_id,
                        cve=cve,
                        pkg=pkg_record,
                        purl=purl,
                        cpe=cpe
                    )
                    publish_match(producer, match)

        # Store by CPE
        if cpe:
            base_cpe = extract_base_cpe(cpe)
            sbom_cpe_state[environment_id][base_cpe] = pkg_record

            # Check against known CPE CVEs
            if base_cpe in cpe_state:
                cve = cpe_state[base_cpe]
                if cve.get('status') == 'active':
                    match = create_enriched_match(
                        environment_id=environment_id,
                        cve=cve,
                        pkg=pkg_record,
                        purl=purl,
                        cpe=cpe
                    )
                    publish_match(producer, match)


def process_cve(cve: dict, producer: KafkaProducer):
    """Process an incoming CVE event."""
    package_purl = cve.get('package_purl')
    package_cpe = cve.get('package_cpe')
    cve_id = cve.get('cve_id')
    status = cve.get('status', 'active')
    source = cve.get('source', 'mock')

    identifier = package_purl or package_cpe
    kev_marker = ""
    if kev_client and kev_client.is_actively_exploited(cve_id):
        kev_marker = " [KEV!]"
    print(f"[CVE] {cve_id} for {identifier} (status={status}, source={source}){kev_marker}")

    # Update CVE state (by PURL and/or CPE)
    if package_purl:
        cve_state[package_purl] = cve

    if package_cpe:
        base_cpe = extract_base_cpe(package_cpe)
        cpe_state[base_cpe] = cve

    # If CVE is active, check against all cached SBOMs
    if status == 'active':
        # Check PURL matches
        if package_purl:
            for environment_id, packages in sbom_state.items():
                if package_purl in packages:
                    pkg = packages[package_purl]
                    match = create_enriched_match(
                        environment_id=environment_id,
                        cve=cve,
                        pkg=pkg
                    )
                    publish_match(producer, match)

        # Check CPE matches
        if package_cpe:
            base_cpe = extract_base_cpe(package_cpe)
            for environment_id, packages in sbom_cpe_state.items():
                if base_cpe in packages:
                    pkg = packages[base_cpe]
                    match = create_enriched_match(
                        environment_id=environment_id,
                        cve=cve,
                        pkg=pkg
                    )
                    publish_match(producer, match)


def consume_loop(replay: bool = False):
    """Main consumption loop for both topics."""
    print("Stream Processor starting...")
    print(f"  Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"  PostgreSQL: {POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}")
    print(f"  Mode: {'replay from beginning' if replay else 'latest only'}")
    if V3_FEATURES_AVAILABLE:
        print("  v3 Features: Enabled (VEX + KEV + EPSS + Risk Tiering)")
    else:
        print("  v3 Features: Disabled (run locally for full features)")

    # Wait for Kafka
    print("  Connecting to Kafka...")
    retries = 30
    consumer = None
    while retries > 0 and not shutdown_event.is_set():
        try:
            consumer = KafkaConsumer(
                SBOM_TOPIC, CVE_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
                auto_offset_reset='earliest' if replay else 'latest',
                enable_auto_commit=True,
                group_id='stream-processor',
                value_deserializer=lambda m: json.loads(m.decode("utf-8"))
            )
            print("  Connected to Kafka!")
            break
        except KafkaError as e:
            retries -= 1
            print(f"  Waiting for Kafka... ({retries} retries left)")
            time.sleep(2)

    if consumer is None:
        print("  [ERROR] Could not connect to Kafka")
        return

    # Wait for PostgreSQL
    print("  Connecting to PostgreSQL...")
    retries = 30
    while retries > 0 and not shutdown_event.is_set():
        try:
            conn = get_db_connection()
            conn.close()
            print("  Connected to PostgreSQL!")
            break
        except psycopg2.Error:
            retries -= 1
            print(f"  Waiting for PostgreSQL... ({retries} retries left)")
            time.sleep(2)

    producer = create_producer()

    print("\nProcessing streams (Ctrl+C to stop)...")
    print("─" * 60)

    try:
        while not shutdown_event.is_set():
            # Poll with timeout to allow checking shutdown
            messages = consumer.poll(timeout_ms=500)

            for topic_partition, records in messages.items():
                for record in records:
                    topic = topic_partition.topic

                    if topic == SBOM_TOPIC:
                        process_sbom(record.value, producer)
                    elif topic == CVE_TOPIC:
                        process_cve(record.value, producer)

    except KeyboardInterrupt:
        pass
    finally:
        print("\nShutting down...")
        consumer.close()
        producer.close()


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    shutdown_event.set()


def main():
    parser = argparse.ArgumentParser(description="SCA Stream Processor")
    parser.add_argument("--replay", action="store_true",
                        help="Replay from beginning of topics (rebuild state)")
    args = parser.parse_args()

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    consume_loop(replay=args.replay)


if __name__ == "__main__":
    main()
