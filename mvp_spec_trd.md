# MVP: Real-time SCA & Vulnerability Streaming Engine
## Technical Reference Document

---

## Goal

Build a pipeline that detects vulnerabilities in "real-time" by joining an SBOM stream with a CVE threat feed using Kafka, Flink, and PostgreSQL.

---

## Architecture Overview

```
                         ┌──────────────────┐
                         │   Kafka Topics   │
                         │ (source of truth)│
                         └────────┬─────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
    ┌─────────────────┐  ┌───────────────┐  ┌─────────────────┐
    │ sbom_events     │  │ cve_feed      │  │ vulnerability_  │
    │ (append-only)   │  │ (compacted)   │  │ matches         │
    │                 │  │               │  │ (compacted)     │
    └─────────────────┘  └───────────────┘  └─────────────────┘
              │                   │                   │
              └─────────┬─────────┘                   │
                        ▼                             │
              ┌─────────────────┐                     │
              │   Flink SQL     │─────────────────────┘
              │ (temporal join) │
              └─────────────────┘
                        │
                        ▼ (materialized view only)
              ┌─────────────────┐
              │   PostgreSQL    │◄──── Grafana/Prometheus
              │ (read replica)  │      (queries here)
              └─────────────────┘
```

### Design Principles

1. **Kafka = Source of Truth** — Immutable append-only log; never lose data
2. **Flink = Stateful Computation** — Temporal joins, enrichment, exactly-once processing
3. **PostgreSQL = Disposable Materialized View** — Query-optimized projection; can be nuked and rebuilt from Kafka at any time

---

## Kafka Topic Design

### `sbom_events` (append-only)

| Property | Value |
|----------|-------|
| Key | `image_id` |
| Partitions | Multiple (for throughput) |
| Cleanup Policy | `delete` (retention-based) |
| Retention | 7 days |

**Message Schema:**
```json
{
  "image_id": "web-app-v1",
  "image_digest": "sha256:abc123...",
  "scan_timestamp": "2024-01-15T10:30:00Z",
  "packages": [
    {
      "purl": "pkg:generic/vulnerable-lib@1.0.0",
      "name": "vulnerable-lib",
      "version": "1.0.0"
    }
  ]
}
```

### `cve_feed` (compacted)

| Property | Value |
|----------|-------|
| Key | `package_purl` (e.g., `pkg:generic/vulnerable-lib`) |
| Partitions | 1 (single partition for ordering guarantee) |
| Cleanup Policy | `compact` |

**Message Schema:**
```json
{
  "cve_id": "CVE-2024-12345",
  "package_purl": "pkg:generic/vulnerable-lib",
  "affected_versions": ">=1.0.0,<1.0.5",
  "severity": "critical",
  "status": "active",
  "published_at": "2024-01-15T12:00:00Z"
}
```

**Compaction Behavior:**
```
┌─────────────────────────────────────────────────────────────┐
│  CVE Topic (compacted, single partition)                    │
│  Key: pkg:generic/vulnerable-lib                            │
├─────────────────────────────────────────────────────────────┤
│  offset=0  {cve: "CVE-2024-001", status: "active"}          │
│  offset=1  {cve: "CVE-2024-001", status: "disputed"}   ◄─┐  │
│  offset=2  {cve: "CVE-2024-001", status: "fixed"}      ◄─┼─ compaction keeps latest
│                                                          │  │
│  (after compaction, only offset=2 remains for this key)  │  │
└─────────────────────────────────────────────────────────────┘
```

### `vulnerability_matches` (compacted)

| Property | Value |
|----------|-------|
| Key | `image_id:cve_id` (composite) |
| Partitions | 1 |
| Cleanup Policy | `compact` |

**Message Schema:**
```json
{
  "image_id": "web-app-v1",
  "cve_id": "CVE-2024-12345",
  "package_purl": "pkg:generic/vulnerable-lib@1.0.0",
  "severity": "critical",
  "detected_at": "2024-01-15T12:00:05Z",
  "status": "active"
}
```

---

## Core Components

### 1. Mock Producers (Python)

#### `sbom_producer.py`
Generates random container SBOMs and publishes to `sbom_events` topic.

**Flags:**
- `--image=<name>`: Specify image ID
- `--inject-hit`: Include `pkg:generic/vulnerable-lib@1.0.0` in the SBOM
- `--continuous`: Generate SBOMs at random intervals

#### `cve_producer.py`
Publishes CVE records to `cve_feed` topic.

**Flags:**
- `--publish-new-cve`: Publish a new CVE
- `--target=<package>`: Target package name (e.g., `vulnerable-lib`)
- `--severity=<level>`: CVE severity (critical, high, medium, low)
- `--update-status=<status>`: Update existing CVE status (active, disputed, fixed)

---

### 2. Flink SQL Processing

#### Temporal Join Logic

```sql
-- Register SBOM stream
CREATE TABLE sbom_events (
    image_id STRING,
    image_digest STRING,
    scan_timestamp TIMESTAMP(3),
    packages ARRAY<ROW<purl STRING, name STRING, version STRING>>,
    WATERMARK FOR scan_timestamp AS scan_timestamp - INTERVAL '5' SECOND
) WITH (
    'connector' = 'kafka',
    'topic' = 'sbom_events',
    'properties.bootstrap.servers' = 'kafka:9092',
    'format' = 'json'
);

-- Register CVE table (compacted topic = changelog)
CREATE TABLE cve_feed (
    package_purl STRING,
    cve_id STRING,
    affected_versions STRING,
    severity STRING,
    status STRING,
    published_at TIMESTAMP(3),
    PRIMARY KEY (package_purl) NOT ENFORCED
) WITH (
    'connector' = 'upsert-kafka',
    'topic' = 'cve_feed',
    'properties.bootstrap.servers' = 'kafka:9092',
    'key.format' = 'raw',
    'value.format' = 'json'
);

-- Bi-directional join: alerts on new SBOM OR new CVE
INSERT INTO vulnerability_matches
SELECT
    s.image_id,
    c.cve_id,
    p.purl AS package_purl,
    c.severity,
    CURRENT_TIMESTAMP AS detected_at,
    c.status
FROM sbom_events s
CROSS JOIN UNNEST(s.packages) AS p(purl, name, version)
JOIN cve_feed FOR SYSTEM_TIME AS OF s.scan_timestamp AS c
    ON SPLIT_INDEX(p.purl, '@', 0) = c.package_purl
WHERE c.status = 'active';
```

#### Join Semantics

- **Bi-directional**: Alerts trigger when:
  - A new SBOM arrives containing a package with a known active CVE
  - A new CVE arrives matching packages in existing SBOMs (via Flink state)
- **Deduplication**: Output keyed by `(image_id, cve_id)` — compaction handles duplicates

---

### 3. PostgreSQL (Materialized View)

**Important:** PostgreSQL is a *disposable query cache*, not the source of truth. It can be rebuilt by replaying Kafka from offset 0.

#### Tables

```sql
-- Current vulnerability state (Flink sink)
CREATE TABLE vulnerability_matches (
    image_id VARCHAR(255),
    cve_id VARCHAR(50),
    package_purl VARCHAR(500),
    severity VARCHAR(20),
    detected_at TIMESTAMP,
    status VARCHAR(20),
    PRIMARY KEY (image_id, cve_id)
);

-- Index for Grafana queries
CREATE INDEX idx_severity ON vulnerability_matches(severity);
CREATE INDEX idx_detected_at ON vulnerability_matches(detected_at);

-- Audit log (append-only, for dwell time calculations)
CREATE TABLE detection_audit_log (
    id SERIAL PRIMARY KEY,
    image_id VARCHAR(255),
    cve_id VARCHAR(50),
    event_type VARCHAR(20),  -- 'detected', 'resolved'
    event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

### 4. Observability

#### Prometheus Exporter

Small Python service polling PostgreSQL every 10 seconds:

**Metrics:**
- `vulnerabilities_total{severity="critical|high|medium|low"}` — Gauge
- `mean_dwell_time_seconds` — Time from CVE publication to detection
- `images_affected_total` — Count of unique images with active vulnerabilities

#### Grafana Dashboard

| Panel | Type | Query |
|-------|------|-------|
| Critical CVE Count | Gauge | `vulnerabilities_total{severity="critical"}` |
| Affected Images | Table | SQL: `SELECT image_id, COUNT(*) FROM vulnerability_matches GROUP BY image_id` |
| Detection Latency | Time Series | `mean_dwell_time_seconds` |
| SBOM Drill-down | Table | SQL: `SELECT * FROM sbom_packages WHERE image_id = $selected_image` |

---

## Demo Scenario ("The Hit")

```
Timeline
────────────────────────────────────────────────────────────────►

T+0s    Start stack. Grafana shows 0 vulnerabilities.

T+10s   Run: sbom_producer.py --image=web-app-v1 --inject-hit
        → SBOM with vulnerable-lib@1.0.0 enters Kafka
        → Flink processes, no matching CVE yet
        → Dashboard still shows 0

T+20s   Run: cve_producer.py --publish-new-cve --target=vulnerable-lib --severity=critical
        → CVE enters cve_feed topic
        → Flink temporal join fires
        → Match written to vulnerability_matches topic
        → Flink sinks to PostgreSQL

T+22s   Grafana Critical Gauge: 0 → 1 (within <2 seconds of CVE publish)
```

---

## Design Decisions & Rationale

| Decision | Rationale |
|----------|-----------|
| Single partition for `cve_feed` | Guarantees total ordering of CVE state changes |
| Compacted topics for CVE + matches | Retains latest state per key indefinitely; enables replay |
| PostgreSQL as cache, not source | Kafka is immutable log; PG can be rebuilt at any time |
| Bi-directional join | Catches both "new vulnerable image" and "newly disclosed CVE" scenarios |
| Dedup by `(image_id, cve_id)` | Prevents duplicate alerts for same vulnerability |
| Dwell time = publication → detection | Measures system responsiveness, not remediation workflow |

---

## File Structure

```
flox_sca/
├── docker-compose.yml
├── mvp_spec_trd.md
├── producers/
│   ├── sbom_producer.py
│   └── cve_producer.py
├── flink/
│   └── jobs/
│       └── vulnerability_join.sql
├── postgres/
│   └── init.sql
├── prometheus/
│   ├── exporter.py
│   └── prometheus.yml
└── grafana/
    └── dashboards/
        └── sca_overview.json
```

---

## Open Questions / Future Work

- [ ] Version range matching (semver comparison in Flink)
- [ ] SBOM format support (CycloneDX, SPDX)
- [ ] Fleet management: track which images are deployed where
- [ ] Remediation workflow: integrate with ticketing systems
- [ ] Historical trending: how does vulnerability count change over time?
