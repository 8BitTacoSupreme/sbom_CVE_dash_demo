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

# v3 features (version range VEX + KEV + EPSS + Risk)
# Import directly from modules to avoid pulling in unnecessary dependencies
V3_FEATURES_AVAILABLE = False
VersionMatcher = None
RiskCalculator = None
KEVClient = None
EPSSClient = None

try:
    from analyzers.version_matcher import VersionMatcher
    from analyzers.risk_calculator import RiskCalculator
    V3_FEATURES_AVAILABLE = True
except ImportError:
    pass

try:
    # KEV/EPSS clients only need requests (available in Docker image)
    # clients/__init__.py now handles missing deps gracefully
    from clients.kev_client import KEVClient
    from clients.epss_client import EPSSClient
except ImportError as e:
    # KEV/EPSS not available - features will be disabled
    pass

# OpenSSF Scorecard for upstream repo health (optional enrichment)
ScorecardClient = None
try:
    from clients.scorecard_client import ScorecardClient
except ImportError:
    pass

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
VEX_TOPIC = "vex_statements"
MATCHES_TOPIC = "vulnerability_matches"
PACKAGE_INDEX_TOPIC = "package_index"

# State - Hash-based indexing for instant CVE-to-pod correlation
cve_state = {}  # purl_base -> CVE record (version-agnostic matching)
cpe_state = {}  # package_cpe -> CVE record (for NVD matching)
sbom_state = defaultdict(dict)  # hash -> {purl_base: package_record}
sbom_cpe_state = defaultdict(dict)  # hash -> {package_cpe: package_record}
sbom_metadata = {}  # hash -> {environment_id, scan_timestamp}
package_index = defaultdict(set)  # purl_base -> {hash1, hash2, ...} for blast radius
matches_state = set()  # (hash, cve_id) - for deduplication

# VEX state for vendor VEX overrides (3-way join: SBOM + CVE + VEX)
vex_state = {}  # {cve_id}:{purl_base} -> vex_statement

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

# OpenSSF Scorecard client (optional enrichment for upstream repo health)
scorecard_client = None
if ScorecardClient is not None:
    scorecard_client = ScorecardClient()

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
    """
    Extract base package identifier without version/qualifiers (for CVE matching).

    Handles both legacy and Nix-style PURLs:
    - pkg:npm/lodash@4.17.21 -> pkg:npm/lodash
    - pkg:nix/openssl@3.0.12?nix-hash=abc123 -> pkg:nix/openssl
    """
    if not purl:
        return None
    # Remove query parameters first (Nix-style PURLs have ?nix-hash=xxx)
    if '?' in purl:
        purl = purl.split('?')[0]
    # Remove version
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
    # Use hash-based match_id as primary key
    match_id = match.get('match_id', f"{match.get('hash', match['environment_id'])}:{match['cve_id']}")
    sbom_hash = match.get('hash')

    # Check for duplicate using hash:cve_id
    dedup_key = (sbom_hash or match['environment_id'], match['cve_id'])
    if dedup_key in matches_state:
        return
    matches_state.add(dedup_key)

    # Publish to Kafka keyed by match_id (hash:cve_id)
    try:
        producer.send(MATCHES_TOPIC, key=match_id, value=match)
        producer.flush()
    except KafkaError as e:
        print(f"  [ERROR] Failed to publish match to Kafka: {e}")

    # Write to PostgreSQL
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO vulnerability_matches
                (environment_id, cve_id, hash, match_id, nix_hash, package_purl, package_cpe, severity,
                 cvss_score, detected_at, status, vex_status, vex_reason,
                 vex_justification, source, cwe_ids, cisa_kev, kev_date_added,
                 kev_ransomware, cve_published_at, epss_score, epss_percentile,
                 risk_score, alert_tier, tier_reason)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (environment_id, cve_id) DO UPDATE SET
                hash = COALESCE(EXCLUDED.hash, vulnerability_matches.hash),
                match_id = COALESCE(EXCLUDED.match_id, vulnerability_matches.match_id),
                nix_hash = COALESCE(EXCLUDED.nix_hash, vulnerability_matches.nix_hash),
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
            match.get('hash'),
            match.get('match_id'),
            match.get('nix_hash'),
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
    # Include hash in log for debugging
    hash_short = match.get('hash', '')[:8] + '...' if match.get('hash') else ''
    env_display = f"{match['environment_id']} ({hash_short})" if hash_short else match['environment_id']
    print(f"  [MATCH] {env_display} <-> {match['cve_id']} ({match['severity']}){marker_str}")


def create_enriched_match(
    environment_id: str,
    cve: dict,
    pkg: dict,
    purl: str = None,
    cpe: str = None,
    sbom_hash: str = None
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

    # Check for vendor VEX override (3-way join: SBOM + CVE + VEX)
    # Vendor VEX statements take precedence over computed VEX
    purl_base = pkg.get('purl_base') or extract_base_purl(purl or pkg.get('purl'))
    if purl_base and cve_id:
        vendor_vex = get_vex_override(cve_id, purl_base)
        if vendor_vex:
            vendor_status = vendor_vex.get('vex_status')
            vendor_source = vendor_vex.get('source', 'vendor')
            # Vendor VEX overrides computed VEX
            vex_status = vendor_status
            vex_reason = f"vendor:{vendor_source}"
            vex_justification = vendor_vex.get('vex_justification') or vendor_vex.get('action_statement')

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

    # OpenSSF Scorecard enrichment (upstream repo health)
    upstream_scorecard = None
    if scorecard_client:
        sc_result = scorecard_client.get_score_by_purl(purl or pkg.get('purl', ''))
        if sc_result:
            upstream_scorecard = sc_result.score

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
            severity=severity,
            scorecard_score=upstream_scorecard,
        )
        risk_score = risk.risk_score
        alert_tier = risk.tier
        tier_reason = risk.trigger_reason

    # Build match_id from hash (or environment_id as fallback)
    effective_hash = sbom_hash or pkg.get('sbom_hash')
    match_id = f"{effective_hash}:{cve_id}" if effective_hash else f"{environment_id}:{cve_id}"

    return {
        'match_id': match_id,  # Hash-based compound key
        'hash': effective_hash,  # Environment hash for blast radius queries
        'environment_id': environment_id,  # Human-readable name
        'nix_hash': pkg.get('nix_hash'),  # Package derivation hash
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
        'scorecard_score': upstream_scorecard,
        'risk_score': risk_score,
        'alert_tier': alert_tier,
        'tier_reason': tier_reason,
    }


def update_sbom_inventory(conn, sbom_hash: str, environment_id: str, pkg: dict):
    """Update sbom_inventory table with package information."""
    try:
        cur = conn.cursor()
        purl = pkg.get('purl')
        purl_base = pkg.get('purl_base') or extract_base_purl(purl)

        cur.execute("""
            INSERT INTO sbom_inventory
                (environment_id, environment_hash, package_purl, purl_base,
                 package_name, package_version, nix_hash, scan_timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (environment_id, package_purl) DO UPDATE SET
                environment_hash = EXCLUDED.environment_hash,
                purl_base = EXCLUDED.purl_base,
                nix_hash = EXCLUDED.nix_hash,
                scan_timestamp = NOW()
        """, (
            environment_id,
            sbom_hash,
            purl,
            purl_base,
            pkg.get('name'),
            pkg.get('version'),
            pkg.get('nix_hash')
        ))
        conn.commit()
    except psycopg2.Error as e:
        print(f"  [WARN] Failed to update sbom_inventory: {e}")
        conn.rollback()


def update_package_index_topic(producer: KafkaProducer, purl_base: str):
    """Publish updated package index to Kafka for blast radius queries."""
    if not purl_base:
        return

    try:
        hashes_list = list(package_index.get(purl_base, set()))
        producer.send(PACKAGE_INDEX_TOPIC, key=purl_base, value={
            'purl_base': purl_base,
            'hashes': hashes_list,
            'environment_count': len(hashes_list),
            'updated_at': datetime.now(timezone.utc).isoformat()
        })
    except KafkaError as e:
        print(f"  [WARN] Failed to publish package_index: {e}")


def get_vex_override(cve_id: str, purl_base: str):
    """
    Check if vendor VEX statement exists for this CVE+package.

    Args:
        cve_id: CVE identifier
        purl_base: Base package URL (without version)

    Returns:
        VEX statement dict if found, None otherwise
    """
    key = f"{cve_id}:{purl_base}"
    return vex_state.get(key)


def store_vex_statement(vex: dict):
    """Store VEX statement in PostgreSQL."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO vex_statements
                (vex_id, cve_id, product_purl, product_cpe, vex_status,
                 vex_justification, action_statement, impact_statement,
                 source, source_url, published_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (vex_id) DO UPDATE SET
                vex_status = EXCLUDED.vex_status,
                vex_justification = EXCLUDED.vex_justification,
                action_statement = EXCLUDED.action_statement,
                impact_statement = EXCLUDED.impact_statement,
                updated_at = EXCLUDED.updated_at
        """, (
            vex.get('vex_id'),
            vex.get('cve_id'),
            vex.get('product_purl'),
            vex.get('product_cpe'),
            vex.get('vex_status'),
            vex.get('vex_justification'),
            vex.get('action_statement'),
            vex.get('impact_statement'),
            vex.get('source'),
            vex.get('source_url'),
            vex.get('published_at'),
            vex.get('updated_at')
        ))
        conn.commit()
        cur.close()
        conn.close()
    except psycopg2.Error as e:
        print(f"  [WARN] Failed to store VEX statement: {e}")


def reevaluate_matches_for_vex(cve_id: str, purl_base: str, vex: dict, producer: KafkaProducer):
    """
    Re-evaluate existing matches when a new VEX statement arrives.

    If a vendor VEX statement marks a CVE+package as not_affected,
    we need to update any existing matches.
    """
    vex_status = vex.get('vex_status')
    if vex_status != 'not_affected':
        return  # Only not_affected VEX statements trigger re-evaluation

    # Find all environments containing this package
    for state_key, packages in sbom_state.items():
        if purl_base in packages:
            # Check if there's a match for this CVE
            dedup_key = (state_key, cve_id)
            if dedup_key in matches_state:
                # This match exists and should be updated with VEX override
                # Note: In production, you'd update the existing match record
                # For now, we log the override
                env_id = sbom_metadata.get(state_key, {}).get('environment_id', state_key)
                print(f"  [VEX] Override applied: {env_id} / {cve_id} -> {vex_status} (source: {vex.get('source')})")


def process_vex_statement(vex: dict, producer: KafkaProducer):
    """
    Process incoming VEX statement.

    VEX statements provide vendor-specific vulnerability status overrides.
    When a vendor (e.g., Red Hat, Ubuntu) determines that a CVE doesn't
    affect their build of a package, they publish a VEX statement.
    """
    cve_id = vex.get('cve_id')
    product_purl = vex.get('product_purl')
    vex_status = vex.get('vex_status')
    source = vex.get('source', 'unknown')

    # Extract purl_base for matching
    purl_base = extract_base_purl(product_purl) if product_purl else None

    print(f"[VEX] {cve_id} / {purl_base or product_purl} -> {vex_status} (source: {source})")

    if cve_id and purl_base:
        # Store in memory state for 3-way join
        key = f"{cve_id}:{purl_base}"
        vex_state[key] = vex

        # Store in PostgreSQL
        store_vex_statement(vex)

        # Re-evaluate existing matches affected by this VEX
        reevaluate_matches_for_vex(cve_id, purl_base, vex, producer)


def process_sbom(sbom: dict, producer: KafkaProducer):
    """Process an incoming SBOM event with hash-based indexing."""
    sbom_hash = sbom.get('hash')  # Environment hash (primary key)
    environment_id = sbom.get('environment_id')  # Human-readable name
    packages = sbom.get('packages', [])

    hash_display = f"(hash={sbom_hash[:8]}...)" if sbom_hash else ""
    print(f"[SBOM] {environment_id} {hash_display} with {len(packages)} derivations")

    # Store SBOM metadata
    if sbom_hash:
        sbom_metadata[sbom_hash] = {
            'environment_id': environment_id,
            'scan_timestamp': sbom.get('scan_timestamp')
        }

    # Get DB connection for inventory updates
    try:
        conn = get_db_connection()
    except psycopg2.Error:
        conn = None

    # Update SBOM state indexed by hash
    for pkg in packages:
        purl = pkg.get('purl')
        cpe = pkg.get('cpe')

        # Extract purl_base for CVE matching (version-agnostic)
        purl_base = pkg.get('purl_base') or extract_base_purl(purl)

        # Also check legacy_purl for OSV matching
        legacy_purl = pkg.get('legacy_purl')
        legacy_purl_base = extract_base_purl(legacy_purl) if legacy_purl else None

        pkg_record = {
            'purl': purl,
            'purl_base': purl_base,
            'legacy_purl': legacy_purl,
            'cpe': cpe,
            'name': pkg.get('name'),
            'version': pkg.get('version'),
            'nix_hash': pkg.get('nix_hash'),
            'sbom_hash': sbom_hash,  # Reference back to environment
            'vex_status': pkg.get('vex_status', 'affected'),
            'vex_reason': pkg.get('vex_reason'),
            'vex_justification': pkg.get('vex_justification'),
            'scan_timestamp': sbom.get('scan_timestamp')
        }

        # Determine state key (prefer hash, fallback to environment_id)
        state_key = sbom_hash or environment_id

        # Store by PURL base
        if purl_base:
            sbom_state[state_key][purl_base] = pkg_record

            # Update package index for blast radius queries
            if sbom_hash:
                package_index[purl_base].add(sbom_hash)
                update_package_index_topic(producer, purl_base)

            # Update sbom_inventory table
            if conn and sbom_hash:
                update_sbom_inventory(conn, sbom_hash, environment_id, pkg)

            # Check against known PURL CVEs (using purl_base)
            if purl_base in cve_state:
                cve = cve_state[purl_base]
                if cve.get('status') == 'active':
                    match = create_enriched_match(
                        environment_id=environment_id,
                        cve=cve,
                        pkg=pkg_record,
                        purl=purl,
                        cpe=cpe,
                        sbom_hash=sbom_hash
                    )
                    publish_match(producer, match)

            # Also check legacy PURL for OSV-sourced CVEs
            if legacy_purl_base and legacy_purl_base != purl_base and legacy_purl_base in cve_state:
                cve = cve_state[legacy_purl_base]
                if cve.get('status') == 'active':
                    match = create_enriched_match(
                        environment_id=environment_id,
                        cve=cve,
                        pkg=pkg_record,
                        purl=purl,
                        cpe=cpe,
                        sbom_hash=sbom_hash
                    )
                    publish_match(producer, match)

        # Store by CPE
        if cpe:
            base_cpe = extract_base_cpe(cpe)
            sbom_cpe_state[state_key][base_cpe] = pkg_record

            # Check against known CPE CVEs
            if base_cpe in cpe_state:
                cve = cpe_state[base_cpe]
                if cve.get('status') == 'active':
                    match = create_enriched_match(
                        environment_id=environment_id,
                        cve=cve,
                        pkg=pkg_record,
                        purl=purl,
                        cpe=cpe,
                        sbom_hash=sbom_hash
                    )
                    publish_match(producer, match)

    if conn:
        conn.close()


def process_cve(cve: dict, producer: KafkaProducer):
    """Process an incoming CVE event with hash-based state lookup."""
    package_purl = cve.get('package_purl')
    package_cpe = cve.get('package_cpe')
    cve_id = cve.get('cve_id')
    status = cve.get('status', 'active')
    source = cve.get('source', 'mock')

    # GHSA provides affected_packages with version ranges
    affected_packages = cve.get('affected_packages', [])

    identifier = package_purl or package_cpe
    kev_marker = ""
    if kev_client and kev_client.is_actively_exploited(cve_id):
        kev_marker = " [KEV!]"

    if affected_packages:
        print(f"[CVE] {cve_id} affects {len(affected_packages)} packages (status={status}, source={source}){kev_marker}")
    else:
        print(f"[CVE] {cve_id} for {identifier} (status={status}, source={source}){kev_marker}")

    # Update CVE state (by PURL base and/or CPE)
    purl_base = extract_base_purl(package_purl) if package_purl else None
    if purl_base:
        cve_state[purl_base] = cve

    if package_cpe:
        base_cpe = extract_base_cpe(package_cpe)
        cpe_state[base_cpe] = cve

    # GHSA-specific: index by each affected package's purl
    for pkg in affected_packages:
        pkg_purl = pkg.get('purl')
        if pkg_purl:
            pkg_purl_base = extract_base_purl(pkg_purl)
            if pkg_purl_base:
                # Store CVE with package-specific version info
                cve_with_versions = {
                    **cve,
                    'affected_versions': [{
                        'vulnerable_versions': pkg.get('vulnerable_versions'),
                        'patched_versions': pkg.get('patched_versions'),
                        'first_patched': pkg.get('first_patched'),
                    }]
                }
                cve_state[pkg_purl_base] = cve_with_versions

    # If CVE is active, check against all cached SBOMs (keyed by hash)
    if status == 'active':
        # Check PURL matches against hash-indexed state
        if purl_base:
            for state_key, packages in sbom_state.items():
                if purl_base in packages:
                    pkg = packages[purl_base]
                    # Lookup environment_id from metadata if state_key is a hash
                    env_id = sbom_metadata.get(state_key, {}).get('environment_id', state_key)
                    match = create_enriched_match(
                        environment_id=env_id,
                        cve=cve,
                        pkg=pkg,
                        sbom_hash=state_key if state_key in sbom_metadata else None
                    )
                    publish_match(producer, match)

        # GHSA-specific: check each affected package's purl against SBOMs
        for affected_pkg in affected_packages:
            pkg_purl = affected_pkg.get('purl')
            if pkg_purl:
                pkg_purl_base = extract_base_purl(pkg_purl)
                if pkg_purl_base and pkg_purl_base != purl_base:  # Avoid duplicate checks
                    for state_key, packages in sbom_state.items():
                        if pkg_purl_base in packages:
                            pkg = packages[pkg_purl_base]
                            env_id = sbom_metadata.get(state_key, {}).get('environment_id', state_key)
                            # Include version range info from GHSA
                            cve_with_versions = {
                                **cve,
                                'affected_versions': [{
                                    'vulnerable_versions': affected_pkg.get('vulnerable_versions'),
                                    'patched_versions': affected_pkg.get('patched_versions'),
                                    'first_patched': affected_pkg.get('first_patched'),
                                }]
                            }
                            match = create_enriched_match(
                                environment_id=env_id,
                                cve=cve_with_versions,
                                pkg=pkg,
                                sbom_hash=state_key if state_key in sbom_metadata else None
                            )
                            publish_match(producer, match)

        # Check CPE matches
        if package_cpe:
            base_cpe = extract_base_cpe(package_cpe)
            for state_key, packages in sbom_cpe_state.items():
                if base_cpe in packages:
                    pkg = packages[base_cpe]
                    env_id = sbom_metadata.get(state_key, {}).get('environment_id', state_key)
                    match = create_enriched_match(
                        environment_id=env_id,
                        cve=cve,
                        pkg=pkg,
                        sbom_hash=state_key if state_key in sbom_metadata else None
                    )
                    publish_match(producer, match)


def consume_loop(replay: bool = False):
    """Main consumption loop for both topics."""
    print("Stream Processor starting...")
    print(f"  Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"  PostgreSQL: {POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}")
    print(f"  Mode: {'replay from beginning' if replay else 'latest only'}")
    print(f"  Topics: {SBOM_TOPIC}, {CVE_TOPIC}, {VEX_TOPIC}")
    if V3_FEATURES_AVAILABLE:
        print("  v3 Features: Enabled (VEX + KEV + EPSS + Risk Tiering + Vendor VEX)")
    else:
        print("  v3 Features: Disabled (run locally for full features)")
    if scorecard_client:
        print("  OpenSSF Scorecard: Enabled (upstream repo health enrichment)")
    else:
        print("  OpenSSF Scorecard: Disabled")

    # Wait for Kafka
    print("  Connecting to Kafka...")
    retries = 30
    consumer = None
    while retries > 0 and not shutdown_event.is_set():
        try:
            consumer = KafkaConsumer(
                SBOM_TOPIC, CVE_TOPIC, VEX_TOPIC,
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
                    elif topic == VEX_TOPIC:
                        process_vex_statement(record.value, producer)

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
