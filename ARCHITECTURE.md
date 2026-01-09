# SCA Vulnerability Detection Pipeline - Architecture

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         SCA VULNERABILITY DETECTION PIPELINE                            │
└─────────────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │                           EXTERNAL DATA SOURCES (4 parallel)                        │
  │  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐                     │
  │  │    NVD    │   │    OSV    │   │   CISA    │   │   FIRST   │                     │
  │  │   (CPE)   │   │  (PURL)   │   │    KEV    │   │   EPSS    │                     │
  │  │ CVE data  │   │ CVE data  │   │ Exploited │   │ Exploit   │                     │
  │  │ + ranges  │   │ + ranges  │   │   list    │   │  scores   │                     │
  │  └─────┬─────┘   └─────┬─────┘   └─────┬─────┘   └─────┬─────┘                     │
  └────────┼───────────────┼───────────────┼───────────────┼───────────────────────────┘
           │               │               │               │
           ▼               ▼               ▼               ▼
  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │                              API CLIENTS                                             │
  │  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐                     │
  │  │nvd_client │   │osv_client │   │kev_client │   │epss_client│                     │
  │  └───────────┘   └───────────┘   └───────────┘   └───────────┘                     │
  └────────────────────────────────────┬────────────────────────────────────────────────┘
                                       │
  ┌──────────────────┐                 │
  │  SBOM Producer   │                 │
  │  (sbom_producer) │                 │
  └────────┬─────────┘                 │
           │                           │
  ┌────────┴─────────┐                 │
  │  Flox Demo       │                 │
  │  Producer        │─────────────────┤
  └────────┬─────────┘                 │
           │                           │
           ▼                           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                         KAFKA                                │
  │  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐  │
  │  │  sbom_events  │  │   cve_feed    │  │ vulnerability   │  │
  │  │    topic      │  │    topic      │  │   _matches      │  │
  │  │  (3 parts)    │  │  (compacted)  │  │    topic        │  │
  │  └───────┬───────┘  └───────┬───────┘  └────────▲────────┘  │
  └──────────┼──────────────────┼───────────────────┼───────────┘
             │                  │                   │
             └────────┬─────────┘                   │
                      │                             │
                      ▼                             │
  ┌─────────────────────────────────────────────────────────────┐
  │                    STREAM PROCESSOR                          │
  │  ┌───────────────────────────────────────────────────────┐  │
  │  │              BI-DIRECTIONAL JOIN                       │  │
  │  │         SBOM packages ◄──► CVE purls/cpes             │  │
  │  └───────────────────────────┬───────────────────────────┘  │
  │                              │                              │
  │  ┌───────────────────────────▼───────────────────────────┐  │
  │  │                  ENRICHMENT LAYER                      │  │
  │  │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐  │  │
  │  │  │ KEV Client │  │EPSS Client │  │ Version Matcher │  │  │
  │  │  │  (CISA)    │  │  (FIRST)   │  │     (VEX)       │  │  │
  │  │  └─────┬──────┘  └─────┬──────┘  └────────┬────────┘  │  │
  │  │        │               │                  │           │  │
  │  │        ▼               ▼                  ▼           │  │
  │  │  ┌─────────────────────────────────────────────────┐  │  │
  │  │  │              RISK CALCULATOR                     │  │  │
  │  │  │     Risk = (CVSS × 0.30) + (EPSS × 0.40)        │  │  │
  │  │  │            + (KEV × 0.30)                        │  │  │
  │  │  └────────────────────┬────────────────────────────┘  │  │
  │  │                       │                               │  │
  │  │  ┌────────────────────▼────────────────────────────┐  │  │
  │  │  │              TIER ASSIGNMENT                     │  │  │
  │  │  │  T1: KEV + Critical    → BREAK GLASS            │  │  │
  │  │  │  T2: Risk>80 | EPSS>40%→ IMMEDIATE              │  │  │
  │  │  │  T3: Everything else   → STANDARD               │  │  │
  │  │  └─────────────────────────────────────────────────┘  │  │
  │  └───────────────────────────────────────────────────────┘  │
  └──────────────────────────┬──────────────────────────────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │  PostgreSQL  │   │    Kafka     │   │ ES Consumer  │
  │   :5432      │   │   (output)   │   │              │
  └──────┬───────┘   └──────────────┘   └──────┬───────┘
         │                                      │
         │                                      ▼
         │                              ┌──────────────┐
         │                              │Elasticsearch │
         │                              │    :9200     │
         │                              └──────┬───────┘
         │                                     │
         ▼                                     ▼
  ┌──────────────┐                      ┌──────────────┐
  │   GRAFANA    │                      │   KIBANA     │
  │    :3000     │                      │    :5601     │
  └──────────────┘                      └──────────────┘
   Ops Dashboard                         Investigation
   - Break Glass (RED)                   - Full-text search
   - Tier Summary                        - Compliance reports
   - Risk Gauges                         - CVE drill-down


  ┌─────────────────────────────────────────────────────────────┐
  │                   ALTERNATIVE SCAN PATH                      │
  │  ┌─────────────────────────────────────────────────────────┐│
  │  │                      GRYPE                               ││
  │  │    Standalone CLI scanner (not in stream processor)     ││
  │  │    grype <sbom.json> -o json | jq (tier filtering)      ││
  │  └─────────────────────────────────────────────────────────┘│
  └─────────────────────────────────────────────────────────────┘


  ┌─────────────────────────────────────────────────────────────┐
  │                   SUPPORTING SERVICES                        │
  │  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌────────────┐  │
  │  │Zookeeper │  │Prometheus│  │ Kafka UI  │  │  Metrics   │  │
  │  │  :2181   │  │  :9090   │  │   :8080   │  │  Exporter  │  │
  │  └──────────┘  └──────────┘  └───────────┘  │   :8000    │  │
  │                                             └────────────┘  │
  └─────────────────────────────────────────────────────────────┘
```

---

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW                                               │
└─────────────────────────────────────────────────────────────────────────────────────┘

EXTERNAL SOURCES (4 parallel APIs)
──────────────────────────────────
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   NVD API   │  │   OSV API   │  │  CISA KEV   │  │ FIRST EPSS  │
│ (CPE-based) │  │(PURL-based) │  │ (24h cache) │  │ (24h cache) │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │                │
       └────────────────┴────────────────┴────────────────┘
                                │
                                ▼
PRODUCERS               TOPICS                 PROCESSOR              SINKS
─────────               ──────                 ─────────              ─────

┌─────────────┐
│ SPDX Files  │──┐
└─────────────┘  │
                 │      ┌───────────────┐
┌─────────────┐  ├─────▶│  sbom_events  │──┐
│ Flox Demo   │──┤      │   (SBOM+PURL) │  │
│  Producer   │  │      └───────────────┘  │
└─────────────┘  │                         │     ┌─────────────────┐
                 │      ┌───────────────┐  │     │ Stream          │
                 └─────▶│   cve_feed    │──┼────▶│ Processor       │
                        │  (CVE+PURL)   │  │     │                 │
                        └───────────────┘  │     │ - Join          │
                                           │     │ - KEV enrich    │
                                           │     │ - EPSS enrich   │
                                           │     │ - VEX infer     │
                                           │     │ - Risk calc     │
                                           │     │ - Tier assign   │
                                           │     └────────┬────────┘
                                           │              │
                                           └──────────────┤
                                                          ▼
                                               ┌───────────────────┐
                                               │ vulnerability     │
                                               │    _matches       │
                                               │ (enriched output) │
                                               └─────────┬─────────┘
                                                         │
                              ┌───────────────┬──────────┴──────────┐
                              ▼               ▼                     ▼
                       ┌────────────┐  ┌────────────┐        ┌────────────┐
                       │ PostgreSQL │  │   Kafka    │        │   ES       │
                       │ (primary)  │  │ (downstream│        │ Consumer   │
                       └──────┬─────┘  │  consumers)│        └──────┬─────┘
                              │        └────────────┘               │
                              │                                     ▼
                              │                              ┌────────────┐
                              ▼                              │Elasticsearch│
                       ┌────────────┐                        └──────┬─────┘
                       │  Grafana   │                               │
                       │ Dashboard  │                               ▼
                       └────────────┘                        ┌────────────┐
                                                             │  Kibana    │
                                                             │ Dashboard  │
                                                             └────────────┘
```

---

## External Data Sources

| Source | Endpoint | Purpose | Data Returned |
|--------|----------|---------|---------------|
| **NVD** | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVE lookup by CPE (system packages) | CVSS scores, CWE IDs, version ranges, references |
| **OSV** | `https://api.osv.dev/v1` | CVE lookup by PURL (language ecosystems) | Affected versions, severity, ecosystem info |
| **CISA KEV** | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Known exploited vulnerabilities | Active exploitation status, ransomware association |
| **FIRST EPSS** | `https://api.first.org/data/v1/epss` | Exploit probability scores | Score (0-1), percentile ranking |

---

## Component Summary

### Producers
- **sbom_producer.py** - Reads real SPDX JSON files, enriches with PURLs, publishes to Kafka
- **flox_demo_producer.py** - Generates mock SBOMs and queries NVD/OSV for real CVEs
- **live_cve_producer.py** - Fetches live CVE data from OSV/NVD APIs
- **cve_producer.py** - Publishes individual CVE events, supports status updates

### API Clients (`clients/`)
- **nvd_client.py** - NVD REST API client for CPE-based CVE lookup (rate-limited)
- **osv_client.py** - OSV API client for PURL-based CVE lookup (batch support)
- **kev_client.py** - CISA KEV feed client with 24-hour caching
- **epss_client.py** - FIRST EPSS API client with 24-hour caching

### Analyzers (`analyzers/`)
- **risk_calculator.py** - Computes composite risk score, assigns alert tier
- **version_matcher.py** - VEX inference (marks not_affected if version outside range)

### Stream Processor (`processor/`)
- **stream_processor.py** - Core engine:
  - Bi-directional join (SBOM ↔ CVE)
  - Enrichment (KEV, EPSS)
  - VEX inference
  - Risk calculation + tier assignment
  - Writes to PostgreSQL + publishes to Kafka

### Consumers (`consumers/`)
- **es_consumer.py** - Indexes vulnerability_matches to Elasticsearch

### Kafka Topics
| Topic | Partitions | Retention | Purpose |
|-------|------------|-----------|---------|
| `sbom_events` | 3 | 7 days | SBOM package manifests with PURLs |
| `cve_feed` | 1 | compacted | CVE vulnerability records |
| `vulnerability_matches` | 1 | compacted | Enriched matches (output) |

### Databases
- **PostgreSQL (:5432)** - Primary store for vulnerability matches, SQL queries
- **Elasticsearch (:9200)** - Full-text search, investigation workflows

### Visualization
- **Grafana (:3000)** - Ops dashboard (Break Glass panel, tier stats, trends)
- **Kibana (:5601)** - Investigation (search, compliance, drill-down)

### Grype (Standalone Scanner)
- **Location**: CLI tool in Flox environment (not part of stream processor)
- **Usage**: `grype <sbom.json> -o json` → pipe to `jq` for tier filtering
- **Purpose**: Alternative scan path for local SBOM scanning with tier-based output
- **Command**: `./demo.sh grype-scan <sbom.json>`

---

## Alert Tiers

| Tier | Name | Trigger | Action |
|------|------|---------|--------|
| **1** | Break Glass | KEV + Critical severity | PagerDuty alert, block build |
| **2** | Immediate | Risk > 80 OR EPSS > 40% | Auto-create ticket |
| **3** | Standard | Everything else | Weekly review dashboard |

### Risk Score Formula
```
Risk = (CVSS × 0.30) + (EPSS × 0.40) + (KEV × 0.30)

Where:
  - CVSS: Normalized 0-100 (base score × 10)
  - EPSS: Normalized 0-100 (probability × 100)
  - KEV:  90 if actively exploited, 0 otherwise
```

---

## Service Endpoints

| Service | Port | URL |
|---------|------|-----|
| Grafana | 3000 | http://localhost:3000/d/sca-overview |
| Kibana | 5601 | http://localhost:5601 |
| Kafka UI | 8080 | http://localhost:8080 |
| Prometheus | 9090 | http://localhost:9090 |
| PostgreSQL | 5432 | `postgresql://sca:sca_password@localhost:5432/sca_demo` |
| Elasticsearch | 9200 | http://localhost:9200 |
| Metrics Exporter | 8000 | http://localhost:8000/metrics |

---

## CLI Commands

```bash
./demo.sh up              # Start full stack
./demo.sh down            # Stop and clean
./demo.sh tiers           # Show tier summary from PostgreSQL
./demo.sh grype-scan <f>  # Scan SBOM with Grype + tier filtering
```
