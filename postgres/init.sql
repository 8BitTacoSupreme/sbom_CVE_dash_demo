-- SCA Demo PostgreSQL Schema
-- This is a MATERIALIZED VIEW cache, not source of truth (Kafka is source of truth)

-- Current vulnerability state (Flink sink target)
CREATE TABLE IF NOT EXISTS vulnerability_matches (
    environment_id VARCHAR(255) NOT NULL,
    cve_id VARCHAR(50) NOT NULL,
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

-- SBOM inventory (optional: for drill-down queries)
CREATE TABLE IF NOT EXISTS sbom_inventory (
    id SERIAL PRIMARY KEY,
    environment_id VARCHAR(255) NOT NULL,
    environment_hash VARCHAR(100),
    package_purl VARCHAR(500),
    package_cpe VARCHAR(500),
    package_name VARCHAR(255),
    package_version VARCHAR(100),
    vex_status VARCHAR(20) DEFAULT 'affected',
    vex_justification TEXT,
    scan_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (environment_id, package_purl),
    UNIQUE (environment_id, package_cpe)
);

CREATE INDEX IF NOT EXISTS idx_sbom_environment ON sbom_inventory(environment_id);
CREATE INDEX IF NOT EXISTS idx_sbom_package ON sbom_inventory(package_name);
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
    environment_id,
    cve_id,
    COALESCE(package_purl, package_cpe) as package_identifier,
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
    environment_id,
    cve_id,
    COALESCE(package_purl, package_cpe) as package_identifier,
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
