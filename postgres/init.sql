-- SCA Demo PostgreSQL Schema
-- This is a MATERIALIZED VIEW cache, not source of truth (Kafka is source of truth)

-- Current vulnerability state (Flink sink target)
-- Hash-based joins: uses environment hash as primary key for instant CVE-to-pod correlation
CREATE TABLE IF NOT EXISTS vulnerability_matches (
    environment_id VARCHAR(255) NOT NULL,
    cve_id VARCHAR(50) NOT NULL,
    hash VARCHAR(64),                           -- Environment hash (content-addressable)
    match_id VARCHAR(100),                      -- Compound key: {hash}:{cve_id}
    nix_hash VARCHAR(64),                       -- Package derivation hash
    package_purl VARCHAR(500),
    package_cpe VARCHAR(500),
    severity VARCHAR(20) NOT NULL,
    cvss_score DECIMAL(3,1),                    -- Numeric CVSS score (e.g., 9.8)
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    vex_status VARCHAR(20) DEFAULT 'affected',  -- affected, not_affected, fixed, under_investigation
    vex_reason VARCHAR(50),                     -- version_not_in_range, patch_detected, etc.
    vex_justification TEXT,
    source VARCHAR(20) DEFAULT 'mock',          -- mock, osv, nvd
    cwe_ids TEXT[],                             -- Array of CWE IDs (e.g., {CWE-787, CWE-125})
    cisa_kev BOOLEAN DEFAULT FALSE,             -- Is on CISA KEV list?
    kev_date_added DATE,                        -- When added to KEV
    kev_ransomware BOOLEAN DEFAULT FALSE,       -- Known ransomware use?
    cve_published_at TIMESTAMP,                 -- CVE publication date for detection latency
    epss_score DECIMAL(5,4),                    -- EPSS probability (0.0000 to 1.0000)
    epss_percentile DECIMAL(5,2),               -- EPSS percentile ranking (0.00 to 100.00)
    risk_score DECIMAL(5,2),                    -- Composite risk score (0-100)
    alert_tier INTEGER DEFAULT 3,               -- 1=break_glass, 2=immediate, 3=standard
    tier_reason VARCHAR(100),                   -- Why this tier was assigned
    PRIMARY KEY (environment_id, cve_id)
);

-- Indexes for Grafana queries
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerability_matches(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_detected_at ON vulnerability_matches(detected_at);
CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerability_matches(status);
CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerability_matches(cisa_kev);
CREATE INDEX IF NOT EXISTS idx_vuln_vex_reason ON vulnerability_matches(vex_reason);
CREATE INDEX IF NOT EXISTS idx_vuln_alert_tier ON vulnerability_matches(alert_tier);
CREATE INDEX IF NOT EXISTS idx_vuln_risk_score ON vulnerability_matches(risk_score DESC);
-- Hash-based indexes for blast radius queries
CREATE INDEX IF NOT EXISTS idx_vuln_hash ON vulnerability_matches(hash);
CREATE INDEX IF NOT EXISTS idx_vuln_match_id ON vulnerability_matches(match_id);
CREATE INDEX IF NOT EXISTS idx_vuln_nix_hash ON vulnerability_matches(nix_hash);

-- Audit log for dwell time calculations (append-only)
CREATE TABLE IF NOT EXISTS detection_audit_log (
    id SERIAL PRIMARY KEY,
    environment_id VARCHAR(255) NOT NULL,
    cve_id VARCHAR(50) NOT NULL,
    package_purl VARCHAR(500),
    severity VARCHAR(20),
    event_type VARCHAR(20) NOT NULL,  -- 'detected', 'resolved', 'updated'
    event_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cve_published_at TIMESTAMP  -- For dwell time calculation
);

CREATE INDEX IF NOT EXISTS idx_audit_event_type ON detection_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON detection_audit_log(event_timestamp);

-- SBOM inventory (for drill-down queries and blast radius)
-- Maps environments to their derivations with Nix-style hashes
CREATE TABLE IF NOT EXISTS sbom_inventory (
    id SERIAL PRIMARY KEY,
    environment_id VARCHAR(255) NOT NULL,
    environment_hash VARCHAR(64),              -- Environment hash (content-addressable)
    package_purl VARCHAR(500),
    purl_base VARCHAR(500),                    -- Version-agnostic PURL for CVE matching
    package_cpe VARCHAR(500),
    package_name VARCHAR(255),
    package_version VARCHAR(100),
    nix_hash VARCHAR(64),                      -- Package derivation hash
    vex_status VARCHAR(20) DEFAULT 'affected',
    vex_justification TEXT,
    scan_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (environment_id, package_purl),
    UNIQUE (environment_id, package_cpe)
);

CREATE INDEX IF NOT EXISTS idx_sbom_environment ON sbom_inventory(environment_id);
CREATE INDEX IF NOT EXISTS idx_sbom_env_hash ON sbom_inventory(environment_hash);
CREATE INDEX IF NOT EXISTS idx_sbom_package ON sbom_inventory(package_name);
CREATE INDEX IF NOT EXISTS idx_sbom_purl_base ON sbom_inventory(purl_base);
CREATE INDEX IF NOT EXISTS idx_sbom_nix_hash ON sbom_inventory(nix_hash);
CREATE INDEX IF NOT EXISTS idx_sbom_cpe ON sbom_inventory(package_cpe);
CREATE INDEX IF NOT EXISTS idx_sbom_vex ON sbom_inventory(vex_status);

-- View for Grafana: vulnerability summary by severity
CREATE OR REPLACE VIEW vulnerability_summary AS
SELECT
    severity,
    COUNT(*) as count,
    COUNT(DISTINCT environment_id) as affected_environments
FROM vulnerability_matches
WHERE status = 'active'
GROUP BY severity;

-- View for Grafana: affected environments with vulnerability counts
CREATE OR REPLACE VIEW affected_environments AS
SELECT
    environment_id,
    COUNT(*) as total_vulnerabilities,
    COUNT(*) FILTER (WHERE severity = 'critical') as critical_count,
    COUNT(*) FILTER (WHERE severity = 'high') as high_count,
    COUNT(*) FILTER (WHERE severity = 'medium') as medium_count,
    COUNT(*) FILTER (WHERE severity = 'low') as low_count,
    MIN(detected_at) as first_detected,
    MAX(detected_at) as last_detected
FROM vulnerability_matches
WHERE status = 'active'
GROUP BY environment_id
ORDER BY critical_count DESC, high_count DESC;

-- View for dwell time metrics
CREATE OR REPLACE VIEW dwell_time_metrics AS
SELECT
    AVG(EXTRACT(EPOCH FROM (event_timestamp - cve_published_at))) as mean_dwell_seconds,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (event_timestamp - cve_published_at))) as median_dwell_seconds,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (event_timestamp - cve_published_at))) as p95_dwell_seconds,
    COUNT(*) as total_detections
FROM detection_audit_log
WHERE event_type = 'detected'
  AND cve_published_at IS NOT NULL;

-- View for actionable vulnerabilities (excludes not_affected by VEX)
CREATE OR REPLACE VIEW actionable_vulnerabilities AS
SELECT
    environment_id,
    cve_id,
    COALESCE(package_purl, package_cpe) as package_identifier,
    severity,
    detected_at,
    status,
    vex_status,
    source
FROM vulnerability_matches
WHERE status = 'active'
  AND vex_status != 'not_affected';

-- View for VEX summary
CREATE OR REPLACE VIEW vex_summary AS
SELECT
    vex_status,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE severity = 'critical') as critical_count,
    COUNT(*) FILTER (WHERE severity = 'high') as high_count
FROM vulnerability_matches
WHERE status = 'active'
GROUP BY vex_status;

-- View for alert tier summary
CREATE OR REPLACE VIEW tier_summary AS
SELECT
    alert_tier,
    CASE alert_tier
        WHEN 1 THEN 'Break Glass'
        WHEN 2 THEN 'Immediate'
        ELSE 'Standard'
    END as tier_name,
    COUNT(*) as count,
    COUNT(DISTINCT environment_id) as affected_environments
FROM vulnerability_matches
WHERE status = 'active' AND vex_status != 'not_affected'
GROUP BY alert_tier
ORDER BY alert_tier;

-- View for Tier 1 (Break Glass) vulnerabilities - BLOCK LIST
CREATE OR REPLACE VIEW break_glass_vulnerabilities AS
SELECT
    hash,
    environment_id,
    cve_id,
    COALESCE(package_purl, package_cpe) as package_identifier,
    nix_hash,
    severity,
    cvss_score,
    epss_score,
    risk_score,
    tier_reason,
    cisa_kev,
    detected_at
FROM vulnerability_matches
WHERE status = 'active'
  AND vex_status != 'not_affected'
  AND alert_tier = 1
ORDER BY risk_score DESC, detected_at DESC;

-- View for high-risk vulnerabilities sorted by tier and risk
CREATE OR REPLACE VIEW prioritized_vulnerabilities AS
SELECT
    hash,
    environment_id,
    cve_id,
    COALESCE(package_purl, package_cpe) as package_identifier,
    nix_hash,
    severity,
    cvss_score,
    epss_score,
    risk_score,
    alert_tier,
    tier_reason,
    cisa_kev,
    detected_at
FROM vulnerability_matches
WHERE status = 'active'
  AND vex_status != 'not_affected'
ORDER BY alert_tier ASC, risk_score DESC;

-- View for detection latency metrics
CREATE OR REPLACE VIEW detection_latency_metrics AS
SELECT
    AVG(EXTRACT(EPOCH FROM (detected_at - cve_published_at)) / 3600) as avg_latency_hours,
    PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (detected_at - cve_published_at)) / 3600) as median_latency_hours,
    MIN(EXTRACT(EPOCH FROM (detected_at - cve_published_at)) / 3600) as min_latency_hours,
    MAX(EXTRACT(EPOCH FROM (detected_at - cve_published_at)) / 3600) as max_latency_hours,
    COUNT(*) as total_with_latency
FROM vulnerability_matches
WHERE status = 'active'
  AND cve_published_at IS NOT NULL
  AND detected_at > cve_published_at;

-- =============================================================================
-- Hash-Based Blast Radius Tables and Views
-- =============================================================================

-- Package index table (purl_base -> environment hashes containing it)
-- Enables: "Which environments contain this vulnerable package?"
CREATE TABLE IF NOT EXISTS package_index (
    purl_base VARCHAR(500) PRIMARY KEY,
    hashes TEXT[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pkg_idx_hashes ON package_index USING GIN (hashes);

-- Fleet registry (for future k8s integration)
-- Maps environment hashes to running pods for instant blast radius
CREATE TABLE IF NOT EXISTS fleet_registry (
    hash VARCHAR(64) NOT NULL,
    pod_id VARCHAR(255) NOT NULL,
    cluster_id VARCHAR(100) NOT NULL,
    namespace VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'running',
    started_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (hash, pod_id)
);
CREATE INDEX IF NOT EXISTS idx_fleet_hash ON fleet_registry(hash);
CREATE INDEX IF NOT EXISTS idx_fleet_status ON fleet_registry(status);
CREATE INDEX IF NOT EXISTS idx_fleet_cluster ON fleet_registry(cluster_id);

-- View: Blast radius by CVE (which environments/pods are affected)
CREATE OR REPLACE VIEW blast_radius_by_cve AS
SELECT
    vm.cve_id,
    vm.hash,
    vm.environment_id,
    vm.severity,
    vm.risk_score,
    vm.alert_tier,
    COALESCE(
        (SELECT COUNT(*) FROM fleet_registry f WHERE f.hash = vm.hash AND f.status = 'running'),
        0
    ) as running_pods
FROM vulnerability_matches vm
WHERE vm.status = 'active' AND vm.vex_status != 'not_affected';

-- View: Blast radius summary by hash (aggregate pod counts)
CREATE OR REPLACE VIEW blast_radius_by_hash AS
SELECT
    vm.hash,
    vm.environment_id,
    COUNT(DISTINCT vm.cve_id) as cve_count,
    COUNT(DISTINCT vm.cve_id) FILTER (WHERE vm.severity = 'critical') as critical_count,
    COUNT(DISTINCT vm.cve_id) FILTER (WHERE vm.severity = 'high') as high_count,
    MAX(vm.risk_score) as max_risk_score,
    COALESCE(
        (SELECT COUNT(*) FROM fleet_registry f WHERE f.hash = vm.hash AND f.status = 'running'),
        0
    ) as running_pods
FROM vulnerability_matches vm
WHERE vm.status = 'active'
  AND vm.vex_status != 'not_affected'
  AND vm.hash IS NOT NULL
GROUP BY vm.hash, vm.environment_id
ORDER BY critical_count DESC, high_count DESC, max_risk_score DESC;

-- View: Environment-to-packages (derivations) relationship
CREATE OR REPLACE VIEW environment_derivations AS
SELECT
    environment_hash as hash,
    environment_id,
    package_name,
    package_version,
    nix_hash,
    package_purl as purl,
    purl_base
FROM sbom_inventory
WHERE environment_hash IS NOT NULL;

-- View: Which environments contain a specific package (by purl_base)
CREATE OR REPLACE VIEW package_to_environments AS
SELECT
    purl_base,
    array_agg(DISTINCT environment_hash) as environment_hashes,
    array_agg(DISTINCT environment_id) as environment_names,
    COUNT(DISTINCT environment_hash) as env_count
FROM sbom_inventory
WHERE purl_base IS NOT NULL AND environment_hash IS NOT NULL
GROUP BY purl_base;

-- Function to upsert vulnerability matches (for Flink JDBC sink)
CREATE OR REPLACE FUNCTION upsert_vulnerability(
    p_environment_id VARCHAR(255),
    p_cve_id VARCHAR(50),
    p_package_purl VARCHAR(500),
    p_package_cpe VARCHAR(500),
    p_severity VARCHAR(20),
    p_detected_at TIMESTAMP,
    p_status VARCHAR(20),
    p_vex_status VARCHAR(20),
    p_vex_justification TEXT,
    p_source VARCHAR(20)
) RETURNS VOID AS $$
BEGIN
    INSERT INTO vulnerability_matches (environment_id, cve_id, package_purl, package_cpe, severity, detected_at, status, vex_status, vex_justification, source)
    VALUES (p_environment_id, p_cve_id, p_package_purl, p_package_cpe, p_severity, p_detected_at, p_status, p_vex_status, p_vex_justification, p_source)
    ON CONFLICT (environment_id, cve_id)
    DO UPDATE SET
        package_purl = COALESCE(EXCLUDED.package_purl, vulnerability_matches.package_purl),
        package_cpe = COALESCE(EXCLUDED.package_cpe, vulnerability_matches.package_cpe),
        severity = EXCLUDED.severity,
        detected_at = EXCLUDED.detected_at,
        status = EXCLUDED.status,
        vex_status = EXCLUDED.vex_status,
        vex_justification = EXCLUDED.vex_justification,
        source = EXCLUDED.source;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- SCA Tool Scan Results (for multi-tool comparison)
-- =============================================================================

-- Scan results from external SCA tools (Snyk, BlackDuck, Sonar, Sonatype)
CREATE TABLE IF NOT EXISTS sca_scan_results (
    id SERIAL PRIMARY KEY,
    sbom_key VARCHAR(255) NOT NULL,
    environment_id VARCHAR(255) NOT NULL,
    source VARCHAR(50) NOT NULL,  -- snyk, blackduck, sonar, sonatype
    scan_id VARCHAR(255),
    status VARCHAR(50) NOT NULL,  -- completed, failed
    submitted_at TIMESTAMP,
    completed_at TIMESTAMP,
    latency_ms INTEGER,
    total_packages INTEGER,
    packages_with_issues INTEGER,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    error_message TEXT,
    raw_response JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sca_results_sbom_key ON sca_scan_results(sbom_key);
CREATE INDEX IF NOT EXISTS idx_sca_results_source ON sca_scan_results(source);
CREATE INDEX IF NOT EXISTS idx_sca_results_env ON sca_scan_results(environment_id);
CREATE INDEX IF NOT EXISTS idx_sca_results_created ON sca_scan_results(created_at);
CREATE INDEX IF NOT EXISTS idx_sca_results_status ON sca_scan_results(status);

-- Detailed vulnerability findings per SCA tool
CREATE TABLE IF NOT EXISTS sca_tool_vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_result_id INTEGER REFERENCES sca_scan_results(id) ON DELETE CASCADE,
    sbom_key VARCHAR(255) NOT NULL,
    source VARCHAR(50) NOT NULL,
    cve_id VARCHAR(50),
    source_vuln_id VARCHAR(255),  -- Tool-specific ID (e.g., SNYK-JAVA-...)
    package_name VARCHAR(255),
    package_version VARCHAR(100),
    purl VARCHAR(500),
    severity VARCHAR(20),
    cvss_score FLOAT,
    epss_score FLOAT,
    remediation TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sca_vulns_sbom ON sca_tool_vulnerabilities(sbom_key);
CREATE INDEX IF NOT EXISTS idx_sca_vulns_cve ON sca_tool_vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_sca_vulns_source ON sca_tool_vulnerabilities(source);
CREATE INDEX IF NOT EXISTS idx_sca_vulns_severity ON sca_tool_vulnerabilities(severity);

-- =============================================================================
-- Views for SCA Tool Comparison Dashboard
-- =============================================================================

-- Summary by tool for latest scans
CREATE OR REPLACE VIEW sca_tool_summary AS
SELECT
    source,
    COUNT(*) as total_scans,
    COUNT(*) FILTER (WHERE status = 'completed') as successful_scans,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_scans,
    AVG(latency_ms) as avg_latency_ms,
    SUM(critical_count) as total_critical,
    SUM(high_count) as total_high,
    SUM(medium_count) as total_medium,
    SUM(low_count) as total_low
FROM sca_scan_results
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY source;

-- Tool agreement analysis (which CVEs are found by multiple tools)
CREATE OR REPLACE VIEW sca_tool_agreement AS
SELECT
    cve_id,
    COUNT(DISTINCT source) as tool_count,
    array_agg(DISTINCT source) as found_by_tools,
    MAX(severity) as max_severity,
    MAX(cvss_score) as max_cvss
FROM sca_tool_vulnerabilities
WHERE cve_id IS NOT NULL
GROUP BY cve_id
ORDER BY tool_count DESC, max_cvss DESC NULLS LAST;

-- Unique findings per tool (found by only one tool)
CREATE OR REPLACE VIEW sca_unique_findings AS
SELECT
    v.source,
    v.cve_id,
    v.package_name,
    v.severity,
    v.cvss_score
FROM sca_tool_vulnerabilities v
WHERE v.cve_id IN (
    SELECT cve_id
    FROM sca_tool_vulnerabilities
    WHERE cve_id IS NOT NULL
    GROUP BY cve_id
    HAVING COUNT(DISTINCT source) = 1
)
ORDER BY v.source, v.cvss_score DESC NULLS LAST;

-- EPSS coverage by tool
CREATE OR REPLACE VIEW sca_epss_coverage AS
SELECT
    source,
    COUNT(*) as total_vulns,
    COUNT(epss_score) as vulns_with_epss,
    ROUND(100.0 * COUNT(epss_score) / NULLIF(COUNT(*), 0), 2) as epss_coverage_pct
FROM sca_tool_vulnerabilities
GROUP BY source;

-- Latest scan status per environment and tool
CREATE OR REPLACE VIEW sca_latest_scans AS
SELECT DISTINCT ON (environment_id, source)
    environment_id,
    source,
    sbom_key,
    status,
    latency_ms,
    critical_count,
    high_count,
    medium_count,
    low_count,
    created_at
FROM sca_scan_results
ORDER BY environment_id, source, created_at DESC;

-- =============================================================================
-- VEX Statements from Vendor Feeds
-- =============================================================================

-- VEX statements from vendor feeds (Red Hat CSAF, Ubuntu VEX, Chainguard, etc.)
-- Key: {cve_id}:{product_purl}:{source} - allows multiple vendor opinions per CVE+product
CREATE TABLE IF NOT EXISTS vex_statements (
    vex_id VARCHAR(200) PRIMARY KEY,
    cve_id VARCHAR(50) NOT NULL,
    product_purl VARCHAR(500),
    product_cpe VARCHAR(500),
    vex_status VARCHAR(30) NOT NULL,  -- affected, not_affected, fixed, under_investigation
    vex_justification VARCHAR(100),    -- CISA justification codes
    action_statement TEXT,
    impact_statement TEXT,
    source VARCHAR(50) NOT NULL,       -- redhat-csaf, ubuntu-vex, chainguard, internal
    source_url TEXT,
    published_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vex_cve ON vex_statements(cve_id);
CREATE INDEX IF NOT EXISTS idx_vex_purl ON vex_statements(product_purl);
CREATE INDEX IF NOT EXISTS idx_vex_source ON vex_statements(source);
CREATE INDEX IF NOT EXISTS idx_vex_status ON vex_statements(vex_status);

-- View: VEX coverage by source
CREATE OR REPLACE VIEW vex_coverage AS
SELECT
    source,
    vex_status,
    COUNT(*) as count
FROM vex_statements
GROUP BY source, vex_status
ORDER BY source, vex_status;

-- View: CVEs with vendor VEX overrides (not_affected status)
CREATE OR REPLACE VIEW cve_vex_overrides AS
SELECT
    v.cve_id,
    v.product_purl,
    v.vex_status,
    v.vex_justification,
    v.source,
    v.updated_at
FROM vex_statements v
WHERE v.vex_status = 'not_affected'
ORDER BY v.updated_at DESC;

-- View: VEX statements by justification reason
CREATE OR REPLACE VIEW vex_by_justification AS
SELECT
    vex_justification,
    COUNT(*) as count,
    array_agg(DISTINCT source) as sources
FROM vex_statements
WHERE vex_status = 'not_affected'
  AND vex_justification IS NOT NULL
GROUP BY vex_justification
ORDER BY count DESC;
