#!/usr/bin/env bash
#
# SCA Demo Script - "The Hit"
#
# This script demonstrates the real-time vulnerability detection pipeline.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate Python venv with dependencies
if [ -f "$SCRIPT_DIR/.flox/cache/venv/bin/activate" ]; then
    source "$SCRIPT_DIR/.flox/cache/venv/bin/activate"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_step() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}▶ $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_url() {
    echo -e "${CYAN}  → $1${NC}"
}

case "${1:-help}" in
    up)
        print_step "Starting SCA Demo Stack"
        docker-compose up -d --build
        echo ""
        print_info "Waiting for services to initialize..."

        # Wait for Kafka topics
        echo -n "  Kafka topics: "
        for i in {1..30}; do
            if docker-compose exec -T kafka kafka-topics --list --bootstrap-server localhost:9092 2>/dev/null | grep -q sbom_events; then
                echo -e "${GREEN}ready${NC}"
                break
            fi
            echo -n "."
            sleep 2
        done

        # Wait for stream processor
        echo -n "  Stream processor: "
        for i in {1..15}; do
            if docker-compose logs stream-processor 2>&1 | grep -q "Processing streams"; then
                echo -e "${GREEN}ready${NC}"
                break
            fi
            echo -n "."
            sleep 2
        done

        echo ""
        print_info "Services started! Access points:"
        print_url "Grafana:    http://localhost:3000 (admin/admin)"
        print_url "Prometheus: http://localhost:9090"
        print_url "Metrics:    http://localhost:8000/metrics"
        echo ""
        print_info "Run './demo.sh hit' to run the demo scenario"
        ;;

    down)
        print_step "Stopping SCA Demo Stack"
        docker-compose down -v
        print_info "Volumes cleared (PostgreSQL + Kafka data purged)"
        ;;

    status)
        print_step "Service Status"
        docker-compose ps
        echo ""
        print_info "Kafka Topics:"
        docker-compose exec -T kafka kafka-topics --list --bootstrap-server localhost:9092 2>/dev/null || echo "  Kafka not ready"
        echo ""
        print_info "Stream Processor Logs (last 10 lines):"
        docker-compose logs --tail=10 stream-processor 2>/dev/null || echo "  Not running"
        ;;

    logs)
        SERVICE="${2:-}"
        if [ -n "$SERVICE" ]; then
            docker-compose logs -f "$SERVICE"
        else
            docker-compose logs -f
        fi
        ;;

    seed)
        print_step "Seeding CVE Feed with Mock npm CVEs"
        print_info "This adds baseline npm CVEs (but NOT the vulnerable-lib CVE)"
        python3 producers/cve_producer.py --seed
        ;;

    seed-flox)
        print_step "Seeding CVE Feed with Flox-specific CVEs"
        print_info "This adds CVEs that match packages in real Flox SBOMs"
        python3 producers/cve_producer.py --seed-flox
        ;;

    hit)
        print_step "THE HIT - Demo Scenario"
        echo ""
        echo -e "${CYAN}Timeline:${NC}"
        echo "  T+0s   Dashboard shows 0 critical vulnerabilities"
        echo "  T+5s   SBOM with vulnerable package published"
        echo "  T+10s  CVE for vulnerable-lib published"
        echo "  T+12s  Dashboard shows 1 critical vulnerability!"
        echo ""

        print_info "Step 1: Open Grafana dashboard"
        print_url "http://localhost:3000/d/sca-overview"
        echo ""
        print_info "Press Enter when ready to publish SBOM..."
        read -r

        print_info "Publishing SBOM with vulnerable package..."
        echo -e "${YELLOW}  $ python3 producers/sbom_producer.py --mock --env=web-app-v1 --inject-hit --kafka${NC}"
        python3 producers/sbom_producer.py --mock --env=web-app-v1 --inject-hit --kafka
        echo ""
        print_info "SBOM published! Check Grafana - Critical count should still be 0"
        print_info "Press Enter to publish the CVE..."
        read -r

        print_info "Publishing CVE for vulnerable-lib..."
        echo -e "${YELLOW}  $ python3 producers/cve_producer.py --publish-new-cve --target=vulnerable-lib --severity=critical${NC}"
        python3 producers/cve_producer.py --publish-new-cve --target=vulnerable-lib --severity=critical
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  Watch Grafana! Critical count should jump to 1!${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        print_url "http://localhost:3000/d/sca-overview"
        ;;

    sem)
        print_step "SEM Demo - Real-time Vulnerability Detection"
        echo ""
        echo -e "${CYAN}Demo Flow:${NC}"
        echo "  Step 1: Baseline - Grafana shows 0 vulnerabilities"
        echo "  Step 2: CVE feed arrives - watch messages flow in Kafka UI"
        echo "  Step 3: Enhanced SBOM arrives - vulnerabilities detected!"
        echo ""

        # Reset database state
        print_info "Clearing vulnerability state..."
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "TRUNCATE vulnerability_matches, detection_audit_log, sbom_inventory CASCADE;" >/dev/null 2>&1
        docker-compose restart stream-processor >/dev/null 2>&1
        sleep 2
        echo -e "${GREEN}  ✓ Ready${NC}"
        echo ""

        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}  STEP 1: BASELINE${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "  Open these URLs:"
        print_url "Grafana:  http://localhost:3000/d/sca-overview"
        print_url "Kafka UI: http://localhost:8080"
        echo ""
        echo "  Grafana shows 0 vulnerabilities detected"
        echo ""
        print_info "Press Enter to publish CVE feed..."
        read -r

        echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}  STEP 2: CVE FEED ARRIVES${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        print_info "Publishing 35 CVEs to Kafka..."
        print_info "Watch the cve_feed topic in Kafka UI!"
        echo ""
        python3 producers/cve_producer.py --seed-flox 2>&1 | grep -E "^  [🔴🟠🟡🔵]|Seeded"
        echo ""
        echo "  Kafka UI:  35 new messages in cve_feed topic"
        echo "  Grafana:   Still 0 - no environments to match against!"
        echo ""
        print_info "Press Enter to publish enhanced SBOM..."
        read -r

        echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  STEP 3: ENHANCED SBOM WITH PURL ENRICHMENT${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        print_info "Publishing Flox environment SBOM with PURL enrichment..."
        print_info "Watch sbom_events and vulnerability_matches topics!"
        echo ""
        python3 producers/sbom_producer.py --sbom=emacs-30.2.spdx.json --format=enhanced --inject-hit --kafka 2>&1 | grep -E "Environment:|Packages:|INJECT|Published"
        echo ""
        echo -e "${GREEN}  ✓ Vulnerabilities detected!${NC}"
        echo ""
        echo "  Kafka UI:  sbom_events + vulnerability_matches flowing"
        echo "  Grafana:   Dashboard shows 1 critical, 4 high, 10 medium, 20 low"
        echo ""
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}  KEY INSIGHT: Same packages, now with PURLs for CVE matching${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        ;;

    sbom)
        print_step "Generate SBOM"
        shift
        python3 producers/sbom_producer.py "$@"
        ;;

    cve)
        print_step "CVE Operations"
        shift
        python3 producers/cve_producer.py "$@"
        ;;

    watch)
        print_step "Watching Stream Processor"
        docker-compose logs -f stream-processor
        ;;

    topics)
        print_step "Kafka Topic Contents"
        echo ""
        echo "=== cve_feed (CVEs) ==="
        docker-compose exec -T kafka kafka-console-consumer \
            --bootstrap-server localhost:9092 \
            --topic cve_feed \
            --from-beginning \
            --timeout-ms 3000 \
            --property print.key=true \
            --property key.separator=" => " 2>/dev/null || true
        echo ""
        echo "=== vulnerability_matches ==="
        docker-compose exec -T kafka kafka-console-consumer \
            --bootstrap-server localhost:9092 \
            --topic vulnerability_matches \
            --from-beginning \
            --timeout-ms 3000 \
            --property print.key=true \
            --property key.separator=" => " 2>/dev/null || true
        ;;

    psql)
        print_step "PostgreSQL Shell"
        docker-compose exec postgres psql -U sca -d sca_demo
        ;;

    query)
        print_step "Current Vulnerabilities"
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "SELECT environment_id, cve_id, severity, detected_at FROM vulnerability_matches WHERE status = 'active' ORDER BY detected_at DESC;"
        ;;

    reset)
        print_step "Resetting Demo Data"
        print_info "Clearing PostgreSQL tables..."
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "TRUNCATE vulnerability_matches, detection_audit_log, sbom_inventory, sca_scan_results, sca_tool_vulnerabilities CASCADE;" 2>/dev/null || true

        print_info "Stopping stream processor..."
        docker-compose stop stream-processor >/dev/null 2>&1

        print_info "Resetting Kafka consumer offsets..."
        docker-compose exec -T kafka kafka-consumer-groups \
            --bootstrap-server localhost:9092 \
            --group stream-processor \
            --reset-offsets --to-earliest --all-topics --execute 2>/dev/null || true

        print_info "Restarting stream processor..."
        docker-compose start stream-processor >/dev/null 2>&1

        print_info "Done! Run './demo.sh sca' to run the full demo"
        ;;

    live)
        print_step "Live CVE Feed Demo (OSV + NVD)"
        echo ""
        echo -e "${CYAN}This demo fetches REAL vulnerabilities from:${NC}"
        echo "  - OSV (Open Source Vulnerabilities) - PURL-based"
        echo "  - NVD (National Vulnerability Database) - CPE-based"
        echo ""
        print_info "Querying and publishing live CVE data to Kafka..."
        python3 producers/live_cve_producer.py --demo --kafka
        echo ""
        print_info "CVEs published to cve_feed topic"
        ;;

    sca)
        # Full SCA demo: CVEs + SBOM with vulnerable packages + Snyk/FOSSA
        SBOM_FILE="${2:-emacs-30.2.spdx.json}"
        SCA_TOOLS="${3:-snyk,fossa}"
        print_step "Full SCA Demo: CVEs + SBOM + External Tools"
        echo ""
        echo -e "${CYAN}This demo:${NC}"
        echo "  1. Fetches live CVEs from OSV/NVD → Kafka"
        echo "  2. Produces SBOM with vulnerable log4j → Kafka"
        echo "  3. Stream processor matches CVEs → Grafana alerts"
        echo "  4. Sends to Snyk/FOSSA APIs → SCA comparison dashboard"
        echo ""

        # Step 1: Seed CVE data
        print_info "Step 1: Seeding live CVE data..."
        python3 producers/live_cve_producer.py --demo --kafka
        echo ""

        # Step 2: Seed log4j CVE for guaranteed match
        print_info "Step 2: Seeding Log4Shell CVE for demo..."
        python3 producers/cve_producer.py --seed-flox 2>&1 | grep -E "^  [🔴🟠🟡🔵]|Seeded|CVE Producer"
        echo ""

        # Step 3: Produce SBOM with vulnerable package + trigger SCA
        print_info "Step 3: Producing SBOM with vulnerable log4j + triggering $SCA_TOOLS..."
        python3 producers/sbom_producer.py \
            --sbom="$SBOM_FILE" \
            --format=enhanced \
            --inject-hit \
            --kafka \
            --trigger-sca \
            --sca-tools="$SCA_TOOLS"
        echo ""

        # Wait for processing
        print_info "Step 4: Waiting for stream processor and SCA orchestrator..."
        sleep 5

        # Show results
        echo ""
        print_info "Check results:"
        print_url "Grafana Overview:    http://localhost:3000/d/sca-overview"
        print_url "SCA Comparison:      http://localhost:3000/d/sca-comparison"
        print_url "Kibana:              http://localhost:5601"
        print_url "Kafka UI:            http://localhost:8080"
        echo ""
        print_info "Query PostgreSQL for matches:"
        echo "  ./demo.sh query"
        ;;

    live-sbom)
        SBOM_FILE="${2:-emacs-30.2.spdx.json}"
        print_step "Live CVE Query for SBOM: $SBOM_FILE"
        echo ""
        print_info "Querying OSV + NVD for packages in SBOM..."
        python3 producers/live_cve_producer.py --sbom="$SBOM_FILE" --kafka
        echo ""
        print_info "Check Grafana for real vulnerability data!"
        print_url "http://localhost:3000/d/sca-overview"
        ;;

    vex)
        print_step "VEX Auto-Detection Demo"
        echo ""
        echo -e "${CYAN}VEX (Vulnerability Exploitability eXchange) Status:${NC}"
        echo "  - affected: Vulnerability affects this environment"
        echo "  - not_affected: Patched in nixpkgs (auto-detected)"
        echo "  - fixed: Remediation applied"
        echo ""

        # Reset state
        print_info "Clearing vulnerability state..."
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "TRUNCATE vulnerability_matches, detection_audit_log CASCADE;" >/dev/null 2>&1
        docker-compose restart stream-processor >/dev/null 2>&1
        sleep 2
        echo -e "${GREEN}  ✓ Ready${NC}"
        echo ""

        print_info "Step 1: Seeding CVEs..."
        python3 producers/cve_producer.py --seed-flox 2>&1 | grep -E "^  [🔴🟠🟡🔵]|Seeded"
        echo ""

        print_info "Step 2: Publishing SBOM with VEX annotations..."
        echo -e "${YELLOW}  Simulating: One CVE has been patched in nixpkgs${NC}"

        # Create a mock SBOM with VEX status
        python3 -c "
import json
import sys
sys.path.insert(0, '.')
from kafka import KafkaProducer
from datetime import datetime

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

sbom = {
    'environment_id': 'vex-demo-env',
    'scan_timestamp': datetime.utcnow().isoformat(),
    'packages': [
        {
            'name': 'ncurses6',
            'version': '6.5',
            'purl': 'pkg:nix/ncurses6@6.5',
            'vex_status': 'not_affected',
            'vex_justification': 'Patched in nixpkgs via CVE-2023-29491.patch'
        },
        {
            'name': 'readline',
            'version': '8.2',
            'purl': 'pkg:nix/readline@8.2',
            'vex_status': 'affected'
        },
        {
            'name': 'openssl',
            'version': '3.0.13',
            'purl': 'pkg:nix/openssl@3.0.13',
            'cpe': 'cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*',
            'vex_status': 'affected'
        },
        {
            'name': 'curl',
            'version': '8.5.0',
            'purl': 'pkg:nix/curlhttp3@8.5.0',
            'vex_status': 'affected'
        },
        {
            'name': 'log4j',
            'version': '2.14.1',
            'purl': 'pkg:nix/log4j@2.14.1',
            'vex_status': 'affected'
        }
    ]
}

producer.send('sbom_events', value=sbom)
producer.flush()
print('  Published SBOM with VEX annotations')
"
        echo ""

        sleep 2
        print_info "Step 3: Check results..."
        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "SELECT cve_id, severity, vex_status, COALESCE(package_purl, package_cpe) as package FROM vulnerability_matches WHERE status = 'active' ORDER BY severity DESC, vex_status;"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${CYAN}Key insight: CVE-2023-29491 (ncurses) shows 'not_affected'${NC}"
        echo -e "${CYAN}because nixpkgs includes the security patch!${NC}"
        echo ""
        print_info "Check Grafana - 'Auto-VEX Filtered' should show 1"
        print_url "http://localhost:3000/d/sca-overview"
        ;;

    kev)
        print_step "CISA KEV Demo - Actively Exploited Vulnerabilities"
        echo ""
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}  KEV = Known Exploited Vulnerabilities (CISA)${NC}"
        echo -e "${RED}  These CVEs are being actively exploited in the wild!${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "The stream processor enriches matches with KEV status:"
        echo "  - Fetches CISA KEV catalog (1200+ CVEs)"
        echo "  - Flags matches that are actively exploited"
        echo "  - Dashboard shows KEV count + table highlights"
        echo ""

        # Reset state
        print_info "Clearing vulnerability state..."
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "TRUNCATE vulnerability_matches, detection_audit_log CASCADE;" >/dev/null 2>&1
        docker-compose restart stream-processor >/dev/null 2>&1
        sleep 2
        echo -e "${GREEN}  ✓ Ready${NC}"
        echo ""

        print_info "Step 1: Fetching CISA KEV catalog..."
        python3 -c "
import sys
sys.path.insert(0, '.')
from clients.kev_client import KEVClient

client = KEVClient()
entries = client.fetch_kev_list()
ransomware = client.get_ransomware_cves()
recent = client.get_recent_additions(days=30)

print(f'  Total KEV entries: {len(entries)}')
print(f'  Ransomware-associated: {len(ransomware)}')
print(f'  Added in last 30 days: {len(recent)}')
print()
print('  Sample KEV CVEs:')
for cve_id in ['CVE-2021-44228', 'CVE-2024-3400', 'CVE-2023-29491']:
    if client.is_actively_exploited(cve_id):
        entry = client.get_kev_details(cve_id)
        print(f'    🔴 {cve_id}: {entry.vulnerability_name[:50]}...')
    else:
        print(f'    ⚪ {cve_id}: Not on KEV list')
"
        echo ""

        print_info "Step 2: Seeding CVEs (including KEV CVEs)..."
        python3 producers/cve_producer.py --seed-flox 2>&1 | grep -E "^  [🔴🟠🟡🔵]|Seeded"
        echo ""

        print_info "Step 3: Publishing SBOM with vulnerable packages..."
        python3 -c "
import json
import sys
sys.path.insert(0, '.')
from kafka import KafkaProducer
from datetime import datetime

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# SBOM with packages that have KEV CVEs
sbom = {
    'environment_id': 'kev-demo-env',
    'scan_timestamp': datetime.utcnow().isoformat(),
    'packages': [
        {
            'name': 'log4j',
            'version': '2.14.1',
            'purl': 'pkg:nix/log4j@2.14.1',
            'vex_status': 'affected'
        },
        {
            'name': 'ncurses6',
            'version': '6.4',
            'purl': 'pkg:nix/ncurses6@6.4',
            'vex_status': 'affected'
        },
        {
            'name': 'openssl',
            'version': '3.0.13',
            'purl': 'pkg:nix/openssl@3.0.13',
            'cpe': 'cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*',
            'vex_status': 'affected'
        },
        {
            'name': 'curl',
            'version': '8.5.0',
            'purl': 'pkg:nix/curlhttp3@8.5.0',
            'vex_status': 'affected'
        }
    ]
}

producer.send('sbom_events', value=sbom)
producer.flush()
print('  Published SBOM with KEV-relevant packages')
"
        echo ""

        sleep 3
        print_info "Step 4: Check results..."
        echo ""
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "SELECT cve_id, severity, CASE WHEN cisa_kev THEN '🔴 KEV' ELSE '' END as kev, vex_status, COALESCE(package_purl, package_cpe) as package FROM vulnerability_matches WHERE status = 'active' ORDER BY cisa_kev DESC, severity DESC;"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${RED}⚠️  KEV CVEs require IMMEDIATE attention!${NC}"
        echo ""
        print_info "Check Grafana - 'Actively Exploited (KEV)' panel shows count"
        print_url "http://localhost:3000/d/sca-overview"
        ;;

    demo-hits)
        print_step "Real CVE Hits Demo - Live Vulnerability Data"
        echo ""
        echo -e "${CYAN}This demo:${NC}"
        echo "  1. Queries OSV for REAL vulnerabilities"
        echo "  2. Generates SBOMs with packages that WILL trigger matches"
        echo "  3. Publishes to Kafka for real-time detection"
        echo ""
        echo "Severity distribution:"
        echo "  - Critical: 1-2 hits (catastrophic, e.g., Log4Shell)"
        echo "  - High:     ~12 hits (serious, needs attention)"
        echo "  - Medium:   ~50 hits (should fix eventually)"
        echo "  - Low:      ~100 hits (informational)"
        echo ""

        # Reset state
        print_info "Clearing vulnerability state..."
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "TRUNCATE vulnerability_matches, detection_audit_log CASCADE;" >/dev/null 2>&1
        docker-compose restart stream-processor >/dev/null 2>&1
        sleep 2
        echo -e "${GREEN}  ✓ Ready${NC}"
        echo ""

        print_info "Generating SBOM with real vulnerable packages..."
        python3 producers/demo_sbom_producer.py --kafka \
            --critical=2 --high=12 --medium=50 --low=100 \
            --env="real-cve-demo"

        echo ""
        sleep 2

        print_info "Vulnerability summary:"
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "SELECT severity, COUNT(*) as count, COUNT(*) FILTER (WHERE cisa_kev) as kev_count FROM vulnerability_matches WHERE status = 'active' GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END;"
        echo ""
        print_info "Check Grafana for the full dashboard!"
        print_url "http://localhost:3000/d/sca-overview"
        ;;

    demo-continuous)
        print_step "Continuous Demo - Real-time Vulnerability Stream"
        echo ""
        echo "Continuously generates SBOMs with real CVE matches."
        echo "New environment every 30 seconds with varying severity."
        echo ""
        print_info "Press Ctrl+C to stop"
        echo ""
        python3 producers/demo_sbom_producer.py --continuous --interval=30
        ;;

    elk)
        print_step "Starting ELK Stack (Elasticsearch + Kibana)"
        echo ""
        echo -e "${CYAN}ELK provides:${NC}"
        echo "  - Full-text search across all CVE descriptions"
        echo "  - Investigation workflows (drill-down, filtering)"
        echo "  - Detection latency analysis"
        echo "  - Compliance reporting via Kibana Canvas"
        echo ""

        print_info "Starting Elasticsearch..."
        docker-compose up -d elasticsearch
        echo -n "  Waiting for Elasticsearch: "
        for i in {1..60}; do
            if curl -s http://localhost:9200/_cluster/health?wait_for_status=yellow\&timeout=1s >/dev/null 2>&1; then
                echo -e "${GREEN}ready${NC}"
                break
            fi
            echo -n "."
            sleep 2
        done

        print_info "Starting Kibana..."
        docker-compose up -d kibana
        echo -n "  Waiting for Kibana: "
        for i in {1..60}; do
            if curl -s http://localhost:5601/api/status 2>/dev/null | grep -q '"status":"green"'; then
                echo -e "${GREEN}ready${NC}"
                break
            fi
            echo -n "."
            sleep 3
        done

        print_info "Starting ES Consumer (Kafka → Elasticsearch)..."
        docker-compose up -d es-consumer
        sleep 2
        echo -e "  ${GREEN}✓ ES Consumer started${NC}"

        echo ""
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  ELK Stack Ready!${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        print_url "Elasticsearch: http://localhost:9200"
        print_url "Kibana:        http://localhost:5601"
        echo ""
        echo "Import dashboard:"
        echo "  1. Go to Kibana → Stack Management → Saved Objects"
        echo "  2. Import: kibana/dashboards/sca_investigation.ndjson"
        echo ""
        print_info "Run a demo to populate Elasticsearch:"
        echo "  ./demo.sh demo-hits"
        echo ""
        ;;

    elk-stop)
        print_step "Stopping ELK Stack"
        docker-compose stop elasticsearch kibana es-consumer
        print_info "ELK services stopped (data preserved)"
        ;;

    elk-reset)
        print_step "Resetting ELK Stack"
        print_info "Stopping services..."
        docker-compose stop elasticsearch kibana es-consumer
        print_info "Removing Elasticsearch data..."
        docker-compose rm -f elasticsearch
        docker volume rm flox_sca_es_data 2>/dev/null || true
        print_info "ELK reset complete. Run './demo.sh elk' to start fresh."
        ;;

    grype-scan)
        SBOM_FILE="${2:-sbom.json}"
        print_step "Grype Scan with EPSS/Risk Filtering"
        echo ""
        echo -e "${CYAN}Tier-based filtering:${NC}"
        echo "  Tier 1 (Break Glass): KEV + Critical → Immediate action"
        echo "  Tier 2 (Immediate):   EPSS > 40% or Risk > 80 → Auto-ticket"
        echo "  Tier 3 (Standard):    Weekly review"
        echo ""

        if [ ! -f "$SBOM_FILE" ]; then
            echo -e "${RED}Error: SBOM file not found: $SBOM_FILE${NC}"
            echo "Usage: ./demo.sh grype-scan [sbom-file]"
            exit 1
        fi

        if ! command -v grype &> /dev/null; then
            echo -e "${RED}Error: grype not found. Install with: flox install grype${NC}"
            exit 1
        fi

        print_info "Scanning $SBOM_FILE with Grype..."
        echo ""

        # Cache grype JSON output for filtering
        GRYPE_JSON=$(grype "$SBOM_FILE" -o json 2>/dev/null)

        # Tier 1: Break Glass - KEV + Critical
        echo -e "${RED}━━━ TIER 1: BREAK GLASS (KEV + Critical) ━━━${NC}"
        echo "$GRYPE_JSON" | jq -r '
            [.matches[] | select(
                .vulnerability.severity == "Critical" and
                (.vulnerability.knownExploited | length) > 0
            )] | .[] | "\(.vulnerability.id) | \(.artifact.name)@\(.artifact.version) | Risk: \(.vulnerability.risk | floor) | EPSS: \((.vulnerability.epss[0].epss // 0) * 100 | floor)% | KEV!"
        ' 2>/dev/null | head -10 || echo "  No Tier 1 vulnerabilities"

        echo ""
        echo -e "${YELLOW}━━━ TIER 2: IMMEDIATE (Risk>80 or EPSS>40%) ━━━${NC}"
        echo "$GRYPE_JSON" | jq -r '
            [.matches[] | select(
                (.vulnerability.severity == "Critical" or .vulnerability.severity == "High") and
                ((.vulnerability.risk // 0) > 80 or (.vulnerability.epss[0].epss // 0) > 0.4)
            )] | .[] | "\(.vulnerability.id) | \(.artifact.name)@\(.artifact.version) | Risk: \(.vulnerability.risk | floor) | EPSS: \((.vulnerability.epss[0].epss // 0) * 100 | floor)%"
        ' 2>/dev/null | head -20 || echo "  No Tier 2 vulnerabilities"

        echo ""
        echo -e "${BLUE}━━━ TIER 3: STANDARD (Weekly Review) ━━━${NC}"
        TIER3_COUNT=$(echo "$GRYPE_JSON" | jq '
            [.matches[] | select(
                ((.vulnerability.risk // 0) <= 80 and (.vulnerability.epss[0].epss // 0) <= 0.4) or
                (.vulnerability.severity != "Critical" and .vulnerability.severity != "High")
            )] | length
        ' 2>/dev/null)
        echo "  ${TIER3_COUNT:-0} vulnerabilities for weekly review"
        echo ""
        print_info "Filter: cat sbom.json | grype -o json | jq '[.matches[] | select((.vulnerability.severity == \"Critical\") and ((.vulnerability.risk // 0) > 80 or (.vulnerability.epss[0].epss // 0) > 0.4))]'"
        ;;

    tiers)
        print_step "Current Alert Tier Summary"
        echo ""
        echo -e "${RED}━━━ TIER 1: BREAK GLASS ━━━${NC}"
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "SELECT environment_id, cve_id, ROUND(risk_score, 0) as risk, tier_reason FROM vulnerability_matches WHERE status = 'active' AND vex_status != 'not_affected' AND alert_tier = 1 ORDER BY risk_score DESC LIMIT 10;" 2>/dev/null || echo "  No Tier 1 vulnerabilities"
        echo ""
        echo -e "${YELLOW}━━━ TIER 2: IMMEDIATE ━━━${NC}"
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "SELECT cve_id, ROUND(risk_score, 0) as risk, ROUND(epss_score * 100, 1) as epss_pct, tier_reason FROM vulnerability_matches WHERE status = 'active' AND vex_status != 'not_affected' AND alert_tier = 2 ORDER BY risk_score DESC LIMIT 10;" 2>/dev/null || echo "  No Tier 2 vulnerabilities"
        echo ""
        echo -e "${BLUE}━━━ TIER 3: STANDARD ━━━${NC}"
        docker-compose exec -T postgres psql -U sca -d sca_demo -c \
            "SELECT COUNT(*) as count FROM vulnerability_matches WHERE status = 'active' AND vex_status != 'not_affected' AND alert_tier = 3;" 2>/dev/null || echo "  No data"
        echo ""
        print_info "Check Grafana for full dashboard:"
        print_url "http://localhost:3000/d/sca-overview"
        ;;

    help|*)
        echo "SCA Demo - Real-time Vulnerability Detection"
        echo ""
        echo "Usage: ./demo.sh <command> [options]"
        echo ""
        echo "Stack Management:"
        echo "  up              Start all services (builds containers)"
        echo "  down            Stop all services"
        echo "  status          Show service status"
        echo "  logs [service]  Follow logs (optionally for specific service)"
        echo "  reset           Clear all demo data"
        echo ""
        echo "Demo Scenarios:"
        echo "  demo-hits       Real CVE Hits - queries OSV, generates matching SBOMs"
        echo "  demo-continuous Continuous stream of SBOMs with real CVE matches"
        echo "  sem             SEM Demo - Legacy vs Enhanced SBOM"
        echo "  hit             Original demo - The Hit (vulnerable-lib)"
        echo "  vex             VEX Auto-Detection Demo (version range + patch filtering)"
        echo "  kev             CISA KEV Demo (actively exploited vulnerabilities)"
        echo "  seed            Seed CVE feed with mock npm CVEs"
        echo "  seed-flox       Seed CVE feed with Flox-specific CVEs"
        echo ""
        echo "Live Vulnerability Feeds (v2):"
        echo "  live            Query OSV + NVD with demo packages"
        echo "  live-sbom [f]   Query live CVEs for SBOM file"
        echo "  sca [sbom] [tools]  Full SCA demo: CVEs + SBOM + Snyk/FOSSA"
        echo ""
        echo "Manual Operations:"
        echo "  sbom [opts]     Generate SBOM (--env=X, --inject-hit, --continuous)"
        echo "  cve [opts]      CVE operations (--publish-new-cve, --list-cves, --seed)"
        echo ""
        echo "ELK Stack (Investigation & Compliance):"
        echo "  elk             Start ELK stack (Elasticsearch + Kibana)"
        echo "  elk-stop        Stop ELK stack (preserves data)"
        echo "  elk-reset       Stop and reset ELK stack (clears data)"
        echo ""
        echo "Risk Tiering:"
        echo "  tiers           Show current tier summary (T1/T2/T3)"
        echo "  grype-scan [f]  Grype scan with EPSS/Risk tier filtering"
        echo ""
        echo "Debugging:"
        echo "  watch           Watch stream processor logs"
        echo "  topics          Show Kafka topic contents"
        echo "  query           Query current vulnerabilities in PostgreSQL"
        echo "  psql            Open PostgreSQL shell"
        echo ""
        echo "Quick Start (Real CVE Data):"
        echo "  1. ./demo.sh up         # Start the stack (~30s)"
        echo "  2. ./demo.sh demo-hits  # Real CVEs with matching SBOMs"
        echo ""
        echo "Full SCA Pipeline (with Snyk/FOSSA):"
        echo "  1. ./demo.sh up         # Start the stack"
        echo "  2. ./demo.sh sca        # Live CVEs + SBOM + Snyk/FOSSA APIs"
        echo ""
        echo "Alternative Demos:"
        echo "  ./demo.sh kev           # Focus on actively exploited CVEs"
        echo "  ./demo.sh vex           # Focus on version range filtering"
        echo "  ./demo.sh demo-continuous  # Continuous stream for live dashboards"
        echo ""
        ;;
esac
