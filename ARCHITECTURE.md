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

> **NVD API Key**: For higher rate limits (10x), get a free API key at https://nvd.nist.gov/developers/request-an-api-key and set `NVD_API_KEY` in your environment.

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

## External SCA Tool Integration

The pipeline supports integration with commercial SCA tools for additional vulnerability and license compliance scanning.

### Architecture
```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL SCA TOOL INTEGRATION                                │
└─────────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │                           SBOM PRODUCER (--trigger-sca)                             │
  │                                       │                                             │
  │                                       ▼                                             │
  │                           ┌───────────────────────┐                                │
  │                           │  sca_scan_requests    │                                │
  │                           │    (Kafka topic)      │                                │
  │                           └───────────┬───────────┘                                │
  └───────────────────────────────────────┼─────────────────────────────────────────────┘
                                          │
                                          ▼
  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │                              SCA ORCHESTRATOR                                        │
  │                                                                                      │
  │    ┌────────────────────────────────────────────────────────────────────────┐       │
  │    │                    ASYNC FAN-OUT (asyncio.gather)                       │       │
  │    │                                                                         │       │
  │    │   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐  ┌─────────┐  │       │
  │    │   │  SNYK   │   │  FOSSA  │   │ SONAR   │   │BLACKDUCK│  │SONATYPE │  │       │
  │    │   │   API   │   │   API   │   │   API   │   │(coming) │  │(coming) │  │       │
  │    │   └────┬────┘   └────┬────┘   └────┬────┘   └─────────┘  └─────────┘  │       │
  │    │        │             │             │                                   │       │
  │    └────────┼─────────────┼─────────────┼───────────────────────────────────┘       │
  │             └─────────────┼─────────────┘                                           │
  │                           │                                                         │
  │              ┌────────────┼────────────┐                                            │
  │              ▼            ▼            ▼                                            │
  │    ┌───────────────┐ ┌────────────┐ ┌───────────────┐                              │
  │    │Per-tool topics│ │ Unified    │ │  PostgreSQL   │                              │
  │    │sca_snyk_*     │ │ topic      │ │ (scan results)│                              │
  │    │sca_fossa_*    │ │sca_scan_*  │ │               │                              │
  │    └───────────────┘ └────────────┘ └───────────────┘                              │
  └─────────────────────────────────────────────────────────────────────────────────────┘
```

### Supported SCA Tools

| Tool | Status | Purpose | Key Features |
|------|--------|---------|--------------|
| **Snyk** | Active | Developer-focused vulnerability scanning | 3-step async API, CycloneDX support |
| **FOSSA** | Active | License compliance + vulnerabilities | 2-step signed URL upload, license violations |
| **SonarQube** | Active | Integrated code + dependency analysis | Server-based scanning |
| **Black Duck** | Coming Soon | Enterprise SCA with BDSA advisories | BDIO format, EPSS enrichment |
| **Sonatype Nexus IQ** | Coming Soon | Policy-driven vulnerability management | CycloneDX XML, remediation |

### SCA Kafka Topics

| Topic | Purpose |
|-------|---------|
| `sca_scan_requests` | SBOM scan requests (input) |
| `sca_scan_responses` | Unified responses (all tools) |
| `sca_snyk_responses` | Snyk-specific results |
| `sca_fossa_responses` | FOSSA-specific results |
| `sca_sonar_responses` | SonarQube-specific results |
| `sca_blackduck_responses` | Black Duck results (coming soon) |
| `sca_sonatype_responses` | Sonatype results (coming soon) |

### SCA Client Base Class (`clients/sca_client_base.py`)

All SCA tool clients implement a common interface:

```python
class SCAClientBase(ABC):
    @abstractmethod
    async def submit_sbom(self, sbom: dict) -> str:
        """Submit SBOM, return job ID"""

    @abstractmethod
    async def poll_status(self, job_id: str) -> str:
        """Poll job status: pending|in_progress|completed|failed"""

    @abstractmethod
    async def get_results(self, job_id: str) -> dict:
        """Retrieve vulnerability results"""

    @abstractmethod
    def normalize_response(self, raw: dict, latency_ms: int) -> SCAResponse:
        """Normalize to common SCAResponse schema"""
```

### Environment Variables

```bash
# Snyk
SNYK_TOKEN=<api-token>
SNYK_ORG_ID=<org-uuid>

# FOSSA (License Compliance)
FOSSA_TOKEN=<api-token>

# SonarQube
SONAR_URL=https://sonarqube.example.com
SONAR_TOKEN=<bearer-token>

# Black Duck (coming soon)
BD_URL=https://blackduck.example.com
BD_TOKEN=<bearer-token>

# Sonatype Nexus IQ (coming soon)
IQ_URL=https://iq.example.com
IQ_TOKEN=<bearer-token>
IQ_APP_ID=<application-id>
```

### FOSSA License Compliance

FOSSA provides license compliance scanning in addition to vulnerability detection. License issues are tracked with `LICENSE-*` pseudo-CVE IDs:

```
LICENSE-GPL-3.0      → High severity (copyleft risk)
LICENSE-UNKNOWN      → Medium severity (unlicensed)
LICENSE-MIT          → Low severity (permissive)
```

---

## Alternative SIEM Integration

### Splunk (Alternative to ELK)

The pipeline supports Splunk as an alternative to Elasticsearch/Kibana:

```
┌───────────────────┐        ┌───────────────────┐
│ vulnerability     │        │    Splunk HEC     │
│   _matches        │───────▶│     :8088         │
│   (Kafka)         │        └─────────┬─────────┘
└───────────────────┘                  │
                                       ▼
                              ┌───────────────────┐
                              │   Splunk Web UI   │
                              │     :8001         │
                              └───────────────────┘
```

| Component | Port | Purpose |
|-----------|------|---------|
| Splunk HEC | 8088 | HTTP Event Collector endpoint |
| Splunk UI | 8001 | Web interface (admin/changeme123) |
| splunk-consumer | - | Kafka → Splunk bridge |

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
| Grafana SCA Comparison | 3000 | http://localhost:3000/d/sca-comparison |
| Kibana | 5601 | http://localhost:5601 |
| Splunk UI | 8001 | http://localhost:8001 (admin/changeme123) |
| Splunk HEC | 8088 | https://localhost:8088 |
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
