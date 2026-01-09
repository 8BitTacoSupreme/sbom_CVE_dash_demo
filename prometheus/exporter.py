#!/usr/bin/env python3
"""
Prometheus Metrics Exporter for SCA Demo.

Queries PostgreSQL and exposes metrics for Prometheus to scrape.
"""

import os
import time
from datetime import datetime

import psycopg2
from prometheus_client import start_http_server, Gauge, Counter, Info

# Configuration
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.environ.get("POSTGRES_PORT", "5432")
POSTGRES_DB = os.environ.get("POSTGRES_DB", "sca_demo")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "sca")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "sca_password")
SCRAPE_INTERVAL = int(os.environ.get("SCRAPE_INTERVAL", "10"))
EXPORTER_PORT = int(os.environ.get("EXPORTER_PORT", "8000"))

# Prometheus metrics
vulnerabilities_total = Gauge(
    'sca_vulnerabilities_total',
    'Total number of active vulnerabilities',
    ['severity']
)

affected_environments_total = Gauge(
    'sca_affected_environments_total',
    'Number of environments with active vulnerabilities'
)

mean_dwell_time_seconds = Gauge(
    'sca_mean_dwell_time_seconds',
    'Mean time from CVE publication to detection (seconds)'
)

p95_dwell_time_seconds = Gauge(
    'sca_p95_dwell_time_seconds',
    'P95 time from CVE publication to detection (seconds)'
)

total_detections = Counter(
    'sca_detections_total',
    'Total vulnerability detections since startup'
)

last_detection_timestamp = Gauge(
    'sca_last_detection_timestamp',
    'Unix timestamp of most recent detection'
)

exporter_info = Info(
    'sca_exporter',
    'Information about the SCA metrics exporter'
)


def get_db_connection():
    """Create a database connection."""
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD
    )


def collect_metrics():
    """Query PostgreSQL and update Prometheus metrics."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Vulnerability counts by severity
        cur.execute("""
            SELECT severity, COUNT(*)
            FROM vulnerability_matches
            WHERE status = 'active'
            GROUP BY severity
        """)
        severity_counts = dict(cur.fetchall())

        for severity in ['critical', 'high', 'medium', 'low']:
            vulnerabilities_total.labels(severity=severity).set(
                severity_counts.get(severity, 0)
            )

        # Affected environments count
        cur.execute("""
            SELECT COUNT(DISTINCT environment_id)
            FROM vulnerability_matches
            WHERE status = 'active'
        """)
        affected_environments_total.set(cur.fetchone()[0] or 0)

        # Dwell time metrics (from audit log if available)
        cur.execute("""
            SELECT
                AVG(EXTRACT(EPOCH FROM (event_timestamp - cve_published_at))) as mean_dwell,
                PERCENTILE_CONT(0.95) WITHIN GROUP (
                    ORDER BY EXTRACT(EPOCH FROM (event_timestamp - cve_published_at))
                ) as p95_dwell
            FROM detection_audit_log
            WHERE event_type = 'detected'
              AND cve_published_at IS NOT NULL
        """)
        dwell_result = cur.fetchone()
        if dwell_result[0] is not None:
            mean_dwell_time_seconds.set(dwell_result[0])
        if dwell_result[1] is not None:
            p95_dwell_time_seconds.set(dwell_result[1])

        # Last detection timestamp
        cur.execute("""
            SELECT MAX(detected_at) FROM vulnerability_matches
        """)
        last_detection = cur.fetchone()[0]
        if last_detection:
            last_detection_timestamp.set(last_detection.timestamp())

        cur.close()
        conn.close()

    except psycopg2.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Error collecting metrics: {e}")


def main():
    """Start the metrics exporter."""
    print(f"SCA Metrics Exporter starting...")
    print(f"  PostgreSQL: {POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}")
    print(f"  Exporter port: {EXPORTER_PORT}")
    print(f"  Scrape interval: {SCRAPE_INTERVAL}s")

    # Set exporter info
    exporter_info.info({
        'version': '1.0.0',
        'postgres_host': POSTGRES_HOST,
        'postgres_db': POSTGRES_DB
    })

    # Start HTTP server for Prometheus scraping
    start_http_server(EXPORTER_PORT)
    print(f"  Metrics available at http://localhost:{EXPORTER_PORT}/metrics")

    # Wait for PostgreSQL to be ready
    print("  Waiting for PostgreSQL...")
    retries = 30
    while retries > 0:
        try:
            conn = get_db_connection()
            conn.close()
            print("  PostgreSQL connected!")
            break
        except psycopg2.Error:
            retries -= 1
            time.sleep(1)
    else:
        print("  Failed to connect to PostgreSQL")
        return

    # Main loop
    print("\nCollecting metrics...")
    while True:
        collect_metrics()
        time.sleep(SCRAPE_INTERVAL)


if __name__ == "__main__":
    main()
