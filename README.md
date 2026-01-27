# SCA Vulnerability Detection Pipeline

![Flox SCA SBOM Architecture](FLOX_SEM_SCA_SBOM.png)

## Quick Start

### 1. Start the Stack

```bash
docker-compose up -d --build
```

### 2. Generate Demo Data (Mixed Severities)

```bash
# Generate 5 environments with mixed severities
for i in 1 2 3 4 5; do
  flox activate -- python producers/demo_sbom_producer.py --kafka \
    --critical 2 --high 5 --medium 15 --low 20
  sleep 1
done
```

### 3. View Dashboard

Open Grafana: http://localhost:3000/d/sca-overview (admin/admin)

You'll see vulnerabilities across all tiers - but no KEVs yet.

### 4. Inject a KEV (Simulate an Incident)

```bash
# List available KEV scenarios
flox activate -- python producers/inject_kev.py --list

# Inject Log4Shell
flox activate -- python producers/inject_kev.py --inject log4shell

# Or inject multiple KEVs at once
flox activate -- python producers/inject_kev.py --inject log4shell,spring4shell

# Or inject all KEVs
flox activate -- python producers/inject_kev.py --inject all
```

Refresh Grafana - Log4Shell appears in **Break Glass (Tier 1)** with Risk=95, EPSS=94%, KEV=true.

### 5. Available KEV Scenarios

| Key | Name | CVE | Severity |
|-----|------|-----|----------|
| `log4shell` | Log4Shell | CVE-2021-44228 | Critical |
| `spring4shell` | Spring4Shell | CVE-2022-22965 | Critical |
| `http2-rapid-reset` | HTTP/2 Rapid Reset | CVE-2023-44487 | High |
| `moveit` | MOVEit SQLi | CVE-2023-34362 | Critical |
| `citrix-bleed` | Citrix Bleed | CVE-2023-4966 | Critical |
| `exchange-proxyshell` | ProxyShell | CVE-2021-34473 | Critical |
| `apache-path-traversal` | Apache Path Traversal | CVE-2021-41773 | High |
| `confluence-ognl` | Confluence OGNL Injection | CVE-2022-26134 | Critical |

---

## Hash-Based SBOM Joins

The pipeline uses **environment hashes** as the primary join key for instant CVE-to-pod correlation:

```
Environment: payments/processor
Hash: ca3e9e4e8b2f1a3d...

Contains derivations:
├── pkg:nix/log4j-core@2.14.1?nix-hash=abc123...
├── pkg:nix/spring-beans@5.3.17?nix-hash=def456...
└── pkg:nix/nginx@1.25.2?nix-hash=ghi789...
```

**Benefits:**
- Same package set → same hash (content-addressable)
- Instant blast radius queries: "Which pods run this vulnerable environment?"
- Kubernetes integration: Use hash as pod label for automated remediation

**Kafka Topics:**
- `sbom_events` - Keyed by environment hash
- `vulnerability_matches` - Keyed by `{hash}:{cve_id}`
- `package_index` - Maps purl_base → [environment hashes]

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         SCA VULNERABILITY DETECTION PIPELINE                            │
└─────────────────────────────────────────────────────────────────────────────────────────┘

  ┌───────────────────────────────────────────────────────────────────────────────────────────────┐
  │                              EXTERNAL DATA SOURCES (5 parallel)                               │
  │  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐              │
  │  │    NVD    │   │    OSV    │   │   GHSA    │   │   CISA    │   │   FIRST   │              │
  │  │   (CPE)   │   │  (PURL)   │   │  (GitHub) │   │    KEV    │   │   EPSS    │              │
  │  │ CVE data  │   │ CVE data  │   │ CVE data  │   │ Exploited │   │ Exploit   │              │
  │  │ + ranges  │   │ + ranges  │   │ + curated │   │   list    │   │  scores   │              │
  │  └─────┬─────┘   └─────┬─────┘   └─────┬─────┘   └─────┬─────┘   └─────┬─────┘              │
  └────────┼───────────────┼───────────────┼───────────────┼───────────────┼────────────────────┘
           │               │               │               │               │
           ▼               ▼               ▼               ▼               ▼
  ┌───────────────────────────────────────────────────────────────────────────────────────────────┐
  │                                     API CLIENTS                                               │
  │  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐              │
  │  │nvd_client │   │osv_client │   │ghsa_client│   │kev_client │   │epss_client│              │
  │  └───────────┘   └───────────┘   └───────────┘   └───────────┘   └───────────┘              │
  └──────────────────────────────────────────┬────────────────────────────────────────────────────┘
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

EXTERNAL SOURCES (5 parallel APIs)
──────────────────────────────────
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   NVD API   │  │   OSV API   │  │  GHSA API   │  │  CISA KEV   │  │ FIRST EPSS  │
│ (CPE-based) │  │(PURL-based) │  │  (GitHub)   │  │ (24h cache) │  │ (24h cache) │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │                │                │
       └────────────────┴────────────────┴────────────────┴────────────────┘
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
| **GHSA** | `https://api.github.com/advisories` | CVE lookup via GitHub Security Advisories | CVSS scores, CWE IDs, affected packages, curated data |
| **CISA KEV** | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Known exploited vulnerabilities | Active exploitation status, ransomware association |
| **FIRST EPSS** | `https://api.first.org/data/v1/epss` | Exploit probability scores | Score (0-1), percentile ranking |

> **NVD API Key**: For higher rate limits (10x), get a free API key at https://nvd.nist.gov/developers/request-an-api-key and set `NVD_API_KEY` in your environment.

> **GitHub Token**: For higher rate limits on the GitHub Security Advisory (GHSA) API, generate a personal access token:
> 1. Go to **GitHub.com → Settings → Developer settings → Personal access tokens → Tokens (classic)**
> 2. Click **Generate new token** (no special scopes needed for public advisory API)
> 3. Add `GITHUB_TOKEN=ghp_xxxxxxxxxxxx` to your `.env` file

---

## Component Summary

### Producers
- **sbom_producer.py** - Reads real SPDX JSON files, enriches with PURLs, publishes to Kafka
- **flox_demo_producer.py** - Generates mock SBOMs and queries NVD/OSV for real CVEs
- **live_cve_producer.py** - Fetches live CVE data from OSV/NVD APIs
- **cve_producer.py** - Publishes individual CVE events, supports status updates
- **ghsa_producer.py** - Fetches GitHub Security Advisories, publishes to cve_feed topic
- **vex_producer.py** - Ingests vendor VEX feeds (Red Hat, Ubuntu, Chainguard), publishes to vex_statements topic

### API Clients (`clients/`)
- **nvd_client.py** - NVD REST API client for CPE-based CVE lookup (rate-limited)
- **osv_client.py** - OSV API client for PURL-based CVE lookup (batch support)
- **ghsa_client.py** - GitHub Security Advisory API client for PURL-based CVE lookup
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
| Topic | Partitions | Retention | Key | Purpose |
|-------|------------|-----------|-----|---------|
| `sbom_events` | 3 | 7 days | env hash | SBOM package manifests with Nix hashes |
| `cve_feed` | 1 | compacted | cve_id | CVE vulnerability records |
| `vulnerability_matches` | 1 | compacted | hash:cve_id | Enriched matches (output) |
| `vex_statements` | 3 | compacted | purl:cve_id | Vendor VEX feeds (Red Hat, Ubuntu, Chainguard) |
| `package_index` | 3 | compacted | purl_base | Maps packages to environment hashes |
| `fleet_registry` | 3 | compacted | hash:pod_id | Future: k8s pod tracking |

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

The pipeline integrates with commercial SCA tools for additional vulnerability and license compliance scanning.

### Supported Tools

| Tool | Status | Purpose |
|------|--------|---------|
| **Snyk** | Active | Developer-focused vulnerability scanning |
| **FOSSA** | Active | License compliance + vulnerabilities |
| **SonarQube** | Active | Integrated code + dependency analysis |
| **Black Duck** | Coming Soon | Enterprise SCA with BDSA advisories |
| **Sonatype Nexus IQ** | Coming Soon | Policy-driven vulnerability management |

### Usage

Trigger SCA scans when producing SBOMs:

```bash
# Scan with all configured tools
python producers/sbom_producer.py --sbom=app.spdx.json --format=enhanced --kafka --trigger-sca

# Scan with specific tools
python producers/sbom_producer.py --sbom=app.spdx.json --format=enhanced --kafka --trigger-sca --sca-tools=snyk,fossa
```

### Configuration

Copy `.env.example` to `.env` and configure credentials:

```bash
# Snyk
SNYK_TOKEN=<api-token>
SNYK_ORG_ID=<org-uuid>

# FOSSA (License Compliance)
FOSSA_TOKEN=<api-token>

# SonarQube
SONAR_URL=https://sonarqube.example.com
SONAR_TOKEN=<bearer-token>
```

### Grafana Dashboard

View SCA tool comparison at: http://localhost:3000/d/sca-comparison

- Tool status and response latency
- Vulnerability counts by tool and severity
- License compliance issues (FOSSA)
- Tool agreement matrix

---

## Alternative SIEM Integration

### Splunk

Splunk is available as an alternative to Elasticsearch/Kibana:

| Component | Port | Purpose |
|-----------|------|---------|
| Splunk UI | 8001 | Web interface (admin/changeme123) |
| Splunk HEC | 8088 | HTTP Event Collector |

Search vulnerabilities: `index=sca_vulnerabilities`

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

## VEX Processing

The stream processor performs automatic VEX inference to reduce false positives:

### Automatic VEX Inference
- **Version Range Matching**: ~80% of CVE matches resolved automatically
- Supports OSV format (introduced/fixed) and NVD CPE format (versionStart/End)
- If package version is outside affected range → marked `not_affected`

### Vendor VEX Overrides
- `vex_statements` Kafka topic accepts vendor VEX feeds
- Vendor statements override computed VEX (3-way join: SBOM + CVE + VEX)
- Supported formats: Red Hat CSAF, Ubuntu VEX, Chainguard advisories

### VEX Status Values
| Status | Meaning |
|--------|---------|
| `affected` | Version is within affected range |
| `not_affected` | Version outside affected range |
| `fixed` | Patch available, version contains fix |

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
# Infrastructure
./demo.sh up              # Start full stack
./demo.sh down            # Stop and clean

# Demo Data Generation
flox activate -- python producers/demo_sbom_producer.py --kafka                    # Random env, default counts
flox activate -- python producers/demo_sbom_producer.py --kafka --env myteam/api   # Specific environment
flox activate -- python producers/demo_sbom_producer.py --kafka --critical 5 --high 10  # Custom severity counts
flox activate -- python producers/demo_sbom_producer.py --demo                     # Preview without publishing

# KEV Injection (Incident Simulation)
flox activate -- python producers/inject_kev.py --list                             # List available KEVs
flox activate -- python producers/inject_kev.py --inject log4shell                 # Inject single KEV
flox activate -- python producers/inject_kev.py --inject all                       # Inject all KEVs
flox activate -- python producers/inject_kev.py --inject log4shell --env prod/api  # Custom environment
flox activate -- python producers/inject_kev.py --inject log4shell --count 3       # Multiple instances

# GHSA Feed (GitHub Security Advisories)
flox activate -- python producers/ghsa_producer.py --recent                        # Fetch recent advisories
flox activate -- python producers/ghsa_producer.py --severity critical             # Filter by severity
flox activate -- python producers/ghsa_producer.py --package npm lodash            # Query specific package
flox activate -- python producers/ghsa_producer.py --continuous --interval 3600    # Poll hourly

# Vendor VEX Feeds
flox activate -- python producers/vex_producer.py --list                           # List supported vendor feeds
flox activate -- python producers/vex_producer.py --feed redhat                    # Ingest Red Hat CSAF (planned)
flox activate -- python producers/vex_producer.py --demo                           # Preview VEX format

# Stream Processor (Local with KEV/EPSS enrichment)
docker-compose stop stream-processor                                               # Stop Docker version
flox activate -- python processor/stream_processor.py                              # Run local with v3 features
flox activate -- python processor/stream_processor.py --replay                     # Replay from beginning

# Database Queries
./demo.sh tiers           # Show tier summary from PostgreSQL
docker exec sca-postgres psql -U sca -d sca_demo -c "SELECT * FROM blast_radius_by_hash;"
docker exec sca-postgres psql -U sca -d sca_demo -c "SELECT * FROM break_glass_vulnerabilities;"

# Grype (Standalone Scanner)
./demo.sh grype-scan <f>  # Scan SBOM with Grype + tier filtering
```
