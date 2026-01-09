# SCA Real-time Vulnerability Detection - Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SCA Real-time Vulnerability Detection                        │
└─────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────┐                              ┌──────────────────┐
  │  SBOM Producer   │                              │   CVE Producer   │
  │                  │                              │                  │
  │  Flox SPDX JSON  │                              │  CVE Feed (NVD)  │
  │  + PURL Enrichment                              │  35 vulns seeded │
  └────────┬─────────┘                              └────────┬─────────┘
           │                                                 │
           ▼                                                 ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                              KAFKA                                          │
  │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────────┐    │
  │  │  sbom_events    │  │    cve_feed     │  │  vulnerability_matches   │    │
  │  │                 │  │   (compacted)   │  │       (compacted)        │    │
  │  │  env + packages │  │  purl → CVE     │  │   env + CVE + severity   │    │
  │  └────────┬────────┘  └────────┬────────┘  └────────────▲─────────────┘    │
  │           │                    │                        │                   │
  └───────────┼────────────────────┼────────────────────────┼───────────────────┘
              │                    │                        │
              │                    ▼                        │
              │         ┌───────────────────┐               │
              └────────►│ Stream Processor  │───────────────┘
                        │                   │
                        │  Bi-directional   │
                        │  Join on PURL:    │
                        │                   │
                        │  pkg:nix/ncurses6 │◄── CVE lookup
                        │        ↕          │
                        │  pkg:nix/ncurses6 │◄── SBOM lookup
                        └─────────┬─────────┘
                                  │
                                  ▼
                        ┌───────────────────┐
                        │    PostgreSQL     │
                        │                   │
                        │  Materialized     │
                        │  View of Matches  │
                        │                   │
                        │  vulnerability_   │
                        │  matches table    │
                        └─────────┬─────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
          ┌─────────────────┐         ┌─────────────────┐
          │   Prometheus    │         │     Grafana     │
          │                 │         │                 │
          │  Metrics:       │────────►│  Dashboard:     │
          │  - vuln counts  │         │  - Status gauge │
          │  - by severity  │         │  - Time series  │
          │  - dwell time   │         │  - Tables       │
          └─────────────────┘         └─────────────────┘
```

## Access Points

| Service    | URL                                      | Credentials   |
|------------|------------------------------------------|---------------|
| Grafana    | http://localhost:3000/d/sca-overview     | admin/admin   |
| Kafka UI   | http://localhost:8080                    |               |
| Prometheus | http://localhost:9090                    |               |

## Data Flow

1. **SBOM Producer** reads Flox SPDX JSON files and enriches packages with PURLs
2. **CVE Producer** publishes vulnerability data to Kafka (keyed by PURL)
3. **Stream Processor** performs bi-directional join:
   - New SBOM → check against known CVEs
   - New CVE → check against cached SBOMs
4. **Matches** written to Kafka topic and PostgreSQL
5. **Prometheus** scrapes metrics from PostgreSQL
6. **Grafana** displays real-time dashboard

## Key Insight: PURL Enrichment

```
Legacy SBOM:    name: "ncurses6-out"     ──► No match (no join key)

Enhanced SBOM:  purl: "pkg:nix/ncurses6" ──► MATCH! CVE-2023-29491 (high)
```

The SBOM data was always accurate - it just wasn't speaking the same language as CVE databases. PURL enrichment provides the common identifier for joining.

## CVE Distribution (Demo)

| Severity | Count | Example                    |
|----------|-------|----------------------------|
| Critical | 1     | CVE-2021-44228 (Log4Shell) |
| High     | 4     | CVE-2023-29491 (ncurses)   |
| Medium   | 10    | CVE-2024-2398 (curl)       |
| Low      | 20    | CVE-2024-45490 (expat)     |

## Quick Start

```bash
./demo.sh up    # Start all services
./demo.sh sem   # Run the demo
./demo.sh down  # Stop all services
```
