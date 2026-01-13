# SBOM API Response Examples: Snyk, Black Duck, SonarQube, Sonatype

## Overview
Each tool returns vulnerability and license data in slightly different formats. Here's what you can expect from each:

---

## 1. Snyk API

### Workflow
1. **POST** SBOM → Get job_id
2. **Poll** job status → Check if "finished"
3. **GET** results → Receive vulnerability data

### Response Format (Summary)
Snyk returns vulnerability data in a structured JSON format:

```json
{
  "data": {
    "type": "sbom_test_results",
    "attributes": {
      "summary": {
        "total_packages": 45,
        "packages_with_issues": 12,
        "total_issues": 23,
        "critical": 2,
        "high": 8,
        "medium": 10,
        "low": 3
      },
      "packages": [
        {
          "name": "log4j-core",
          "version": "2.14.1",
          "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
          "vulnerabilities": [
            {
              "id": "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720",
              "title": "Arbitrary Code Execution",
              "severity": "critical",
              "cvss_score": 10.0,
              "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
              "cve": ["CVE-2021-44228"],
              "cwe": ["CWE-502"],
              "description": "Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker controlled LDAP...",
              "exploit_maturity": "proof-of-concept",
              "publication_date": "2021-12-10T00:00:00Z",
              "disclosure_date": "2021-12-09T00:00:00Z",
              "remediation": {
                "type": "upgrade",
                "description": "Upgrade to version 2.17.1 or higher",
                "upgrade_path": ["log4j-core@2.17.1"]
              },
              "is_patchable": false,
              "is_upgradable": true,
              "references": [
                {
                  "title": "GitHub Commit",
                  "url": "https://github.com/apache/logging-log4j2/commit/..."
                },
                {
                  "title": "NVD",
                  "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                }
              ]
            }
          ],
          "licenses": [
            {
              "id": "Apache-2.0",
              "name": "Apache License 2.0",
              "url": "https://opensource.org/licenses/Apache-2.0"
            }
          ]
        }
      ]
    }
  }
}
```

### Key Fields:
- **CVE/Snyk ID**: Vulnerability identifiers
- **CVSS Score & Vector**: Severity metrics (v3.1)
- **Exploit Maturity**: Whether exploits exist (PoC, mature, etc.)
- **Reachability**: Whether vulnerable code is actually called (if enabled)
- **Remediation Guidance**: Upgrade paths, patches
- **License Information**: SPDX identifiers

---

## 2. Black Duck API

### Workflow
Black Duck can ingest SPDX/CycloneDX SBOMs via their scanner or REST API. Results are typically retrieved through their Hub API.

### Response Format (CycloneDX Export with Vulnerabilities)

```xml
<bom serialNumber="urn:uuid:..." version="1" xmlns="http://cyclonedx.org/schema/bom/1.5">
  <metadata>
    <timestamp>2025-01-13T10:30:00Z</timestamp>
    <tools>
      <tool>
        <vendor>Black Duck Software</vendor>
        <name>Black Duck Hub</name>
        <version>2024.10.0</version>
      </tool>
    </tools>
  </metadata>
  
  <components>
    <component type="library" bom-ref="pkg:maven/log4j/log4j@1.2.17">
      <name>log4j</name>
      <version>1.2.17</version>
      <purl>pkg:maven/log4j/log4j@1.2.17</purl>
      <licenses>
        <license>
          <id>Apache-2.0</id>
          <name>Apache License 2.0</name>
        </license>
      </licenses>
    </component>
  </components>
  
  <vulnerabilities>
    <vulnerability bom-ref="CVE-2021-44228">
      <id>CVE-2021-44228</id>
      <source>
        <name>NVD</name>
        <url>https://nvd.nist.gov/vuln/detail/CVE-2021-44228</url>
      </source>
      <ratings>
        <rating>
          <source>
            <name>Black Duck</name>
          </source>
          <score>10.0</score>
          <severity>critical</severity>
          <method>CVSSv31</method>
          <vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</vector>
        </rating>
        <rating>
          <source>
            <name>EPSS</name>
          </source>
          <score>0.97</score>
          <method>EPSS</method>
        </rating>
      </ratings>
      <cwes>
        <cwe>502</cwe>
        <cwe>400</cwe>
      </cwes>
      <description>Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.</description>
      <detail>This vulnerability allows remote attackers to execute arbitrary code...</detail>
      <recommendation>Upgrade to version 2.17.1 or later</recommendation>
      <advisories>
        <advisory>
          <title>Black Duck Security Advisory</title>
          <url>https://www.blackducksoftware.com/security-advisories/BDSA-2021-3897</url>
        </advisory>
        <advisory>
          <title>Apache Security</title>
          <url>https://logging.apache.org/log4j/2.x/security.html</url>
        </advisory>
      </advisories>
      <created>2021-12-10T10:00:00Z</created>
      <published>2021-12-10T10:00:00Z</published>
      <updated>2024-01-10T08:15:00Z</updated>
      <affects>
        <target>
          <ref>pkg:maven/log4j/log4j@1.2.17</ref>
        </target>
      </affects>
    </vulnerability>
  </vulnerabilities>
</bom>
```

### JSON Format (for SPDX)
```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "MyApplication",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-log4j-1.2.17",
      "name": "log4j",
      "versionInfo": "1.2.17",
      "licenseConcluded": "Apache-2.0",
      "externalRefs": [
        {
          "referenceCategory": "SECURITY",
          "referenceType": "cpe23Type",
          "referenceLocator": "cpe:2.3:a:apache:log4j:1.2.17:*:*:*:*:*:*:*"
        },
        {
          "referenceCategory": "SECURITY",
          "referenceType": "advisory",
          "referenceLocator": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        }
      ],
      "annotations": [
        {
          "annotationDate": "2025-01-13T10:30:00Z",
          "annotationType": "REVIEW",
          "annotator": "Tool: Black Duck",
          "comment": "CRITICAL: CVE-2021-44228 - CVSS 10.0 - Remote Code Execution"
        }
      ]
    }
  ]
}
```

### Key Features:
- **BDSA (Black Duck Security Advisories)**: Expert-curated vulnerability data, often 23 days before NVD
- **EPSS Scoring**: Exploit Prediction Scoring System
- **CVSS v2/v3/v4**: Multiple scoring versions
- **License Obligations**: Detailed compliance requirements
- **Component Matching**: Multiple identification methods (hash, binary analysis)

---

## 3. SonarQube Advanced Security

### Workflow
SonarQube's SBOM analysis is newer (beta as of Dec 2025). It integrates with their existing SCA platform.

### Response Format (via UI/API)

```json
{
  "project": {
    "key": "my-app",
    "name": "My Application",
    "qualifier": "TRK"
  },
  "dependencies": {
    "total": 45,
    "withIssues": 12,
    "components": [
      {
        "key": "maven:org.apache.logging.log4j:log4j-core:2.14.1",
        "name": "log4j-core",
        "version": "2.14.1",
        "scope": "compile",
        "transitive": false,
        "vulnerabilities": [
          {
            "key": "CVE-2021-44228",
            "message": "Remote Code Execution in Log4j",
            "severity": "CRITICAL",
            "type": "VULNERABILITY",
            "status": "OPEN",
            "cvssScore": 10.0,
            "cwe": ["CWE-502"],
            "creationDate": "2021-12-10T10:00:00+0000",
            "updateDate": "2024-01-13T08:00:00+0000",
            "effort": "15min",
            "remediation": {
              "type": "UPGRADE",
              "fixedVersion": "2.17.1",
              "description": "Upgrade to Log4j 2.17.1 or later"
            }
          }
        ],
        "licenses": [
          {
            "key": "Apache-2.0",
            "name": "Apache License 2.0",
            "category": "PERMISSIVE",
            "compliant": true
          }
        ]
      }
    ]
  },
  "metrics": {
    "security_rating": "E",
    "vulnerabilities": 23,
    "security_hotspots": 5,
    "security_review_rating": "C"
  }
}
```

### Key Features:
- **Integrated with Code Analysis**: Security issues alongside code quality metrics
- **Quality Gates**: Can block deployments based on vulnerability thresholds
- **Developer-First**: Designed to show in PRs, IDEs, CI/CD
- **License Compliance**: Policy-based license checking
- **SBOM Export**: Can export CycloneDX/SPDX with vulnerability data

---

## 4. Sonatype (Nexus Lifecycle / SBOM Manager)

### Workflow
Sonatype accepts SPDX/CycloneDX input and can export enriched SBOMs via REST API

### Response Format (CycloneDX with Sonatype Enrichment)

```xml
<bom serialNumber="urn:uuid:..." version="1" xmlns="http://cyclonedx.org/schema/bom/1.5">
  <metadata>
    <timestamp>2025-01-13T10:30:00Z</timestamp>
    <tools>
      <tool>
        <vendor>Sonatype Inc.</vendor>
        <name>Nexus IQ Server</name>
        <version>193.0</version>
      </tool>
    </tools>
    <component type="application">
      <name>iq_application_sample-app</name>
      <version>1.0.0</version>
      <purl>pkg:generic/sonatype/iq_application_sample-app@1.0.0</purl>
    </component>
  </metadata>
  
  <components>
    <component type="library" bom-ref="pkg:maven/log4j/log4j@1.2.17">
      <name>log4j</name>
      <version>1.2.17</version>
      <purl>pkg:maven/log4j/log4j@1.2.17</purl>
      <properties>
        <property name="Sonatype Component ID">12345-abcde</property>
        <property name="Match State">exact</property>
        <property name="Identification Source">Sonatype</property>
        <property name="Policy Violations">2</property>
        <property name="Security Issues">High</property>
      </properties>
      <licenses>
        <license>
          <id>Apache-2.0</id>
        </license>
      </licenses>
    </component>
  </components>
  
  <vulnerabilities>
    <vulnerability bom-ref="sonatype-2021-5422">
      <id>sonatype-2021-5422</id>
      <source>
        <name>SONATYPE</name>
        <url>https://ossindex.sonatype.org/vulnerability/sonatype-2021-5422</url>
      </source>
      <references>
        <reference>
          <id>CVE-2021-44228</id>
          <source>
            <name>NVD</name>
          </source>
        </reference>
      </references>
      <ratings>
        <rating>
          <source>
            <name>Sonatype</name>
          </source>
          <score>10.0</score>
          <severity>critical</severity>
          <method>CVSSv31</method>
          <vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</vector>
        </rating>
      </ratings>
      <cwes>
        <cwe>502</cwe>
      </cwes>
      <description>Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.</description>
      <recommendation>Upgrade to 2.17.1 or later. If upgrading is not possible, remove the JndiLookup class from the classpath.</recommendation>
      <advisories>
        <advisory>
          <title>Sonatype Security Advisory</title>
          <url>https://ossindex.sonatype.org/vulnerability/sonatype-2021-5422</url>
        </advisory>
      </advisories>
      <created>2021-12-10T02:15:00Z</created>
      <published>2021-12-10T02:15:00Z</published>
      <updated>2025-01-10T14:30:00Z</updated>
      <analysis>
        <state>not_affected</state>
        <justification>code_not_reachable</justification>
        <response>will_not_fix</response>
        <detail>Analysis shows the vulnerable JNDI lookup is not enabled in our configuration</detail>
      </analysis>
      <affects>
        <target>
          <ref>pkg:maven/log4j/log4j@1.2.17</ref>
          <versions>
            <version>1.2.17</version>
          </versions>
        </target>
      </affects>
    </vulnerability>
  </vulnerabilities>
  
  <externalReferences>
    <reference type="bom">
      <url>http://nexus-iq.company.com/ui/links/application/app/report/abc123</url>
      <comment>IQ Report</comment>
    </reference>
  </externalReferences>
</bom>
```

### JSON Response (Programmatic Access)
```json
{
  "applicationId": "app-12345",
  "reportTime": "2025-01-13T10:30:00.000Z",
  "components": [
    {
      "componentIdentifier": {
        "format": "maven",
        "coordinates": {
          "groupId": "log4j",
          "artifactId": "log4j",
          "version": "1.2.17"
        }
      },
      "hash": "5dbd3be3e56b9c1a0c7b87d9f4e3a2f1",
      "pathnames": ["/WEB-INF/lib/log4j-1.2.17.jar"],
      "securityIssues": [
        {
          "reference": "sonatype-2021-5422",
          "severity": 10.0,
          "status": "OPEN",
          "url": "https://ossindex.sonatype.org/vulnerability/sonatype-2021-5422",
          "threatCategory": "critical",
          "cwe": "CWE-502",
          "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
          "cvssScore": 10.0
        }
      ],
      "licenseData": {
        "declaredLicenses": [
          {
            "licenseId": "Apache-2.0",
            "licenseName": "Apache License 2.0"
          }
        ],
        "observedLicenses": [
          {
            "licenseId": "Apache-2.0",
            "licenseName": "Apache License 2.0"
          }
        ]
      },
      "policyData": {
        "policyViolations": [
          {
            "policyName": "Security-Critical",
            "policyThreatLevel": 10,
            "constraintViolations": [
              {
                "constraintName": "Critical Security Issue",
                "reasons": [
                  {
                    "reason": "CVE-2021-44228 with CVSS 10.0",
                    "reference": {
                      "id": "CVE-2021-44228",
                      "source": "NVD"
                    }
                  }
                ]
              }
            ]
          }
        ]
      }
    }
  ]
}
```

### Key Features:
- **Sonatype Intelligence**: Proprietary vulnerability data (often faster than NVD)
- **VEX Support**: Can add vulnerability exploitability exchange data
- **Policy Engine**: Custom policies beyond just vulnerabilities
- **CPE Matching**: Can use CPE identifiers from SBOM for vulnerability mapping
- **Continuous Monitoring**: Alerts when new vulnerabilities discovered
- **Waiver Support**: Document why certain vulnerabilities are acceptable

---

## Comparison Summary

| Feature | Snyk | Black Duck | SonarQube | Sonatype |
|---------|------|------------|-----------|----------|
| **Response Format** | JSON (proprietary) | CycloneDX/SPDX | JSON (proprietary) | CycloneDX/SPDX |
| **CVSS Scoring** | v3.1 | v2/v3/v4 | v3.1 | v3.1 |
| **Reachability** | ✅ (preview) | ❌ | ✅ (planned) | ❌ |
| **EPSS** | ❌ | ✅ | ❌ | ❌ |
| **License Details** | SPDX IDs | Full obligations | Policy-based | Full obligations |
| **Custom Policies** | ✅ | ✅ | ✅ (Quality Gates) | ✅ (most flexible) |
| **VEX Support** | ❌ | ✅ | ❌ | ✅ |
| **Time to Update** | Real-time | ~23 days before NVD | Real-time | Fast Track (hours) |

---

## API Integration Examples

### Snyk
```bash
# Submit SBOM
curl -X POST \
  -H "Authorization: token $SNYK_TOKEN" \
  -H "Content-Type: application/vnd.api+json" \
  --data @sbom.json \
  "https://api.snyk.io/rest/orgs/$ORG_ID/sbom_tests?version=2024-09-03~beta"

# Get results
curl -X GET \
  -H "Authorization: token $SNYK_TOKEN" \
  "https://api.snyk.io/rest/orgs/$ORG_ID/sbom_tests/$JOB_ID/results?version=2024-09-03~beta"
```

### Black Duck
```bash
# Upload via scanner (typical workflow)
bash <(curl -s -L https://detect.synopsys.com/detect.sh) \
  --blackduck.url=$BD_URL \
  --blackduck.api.token=$BD_TOKEN \
  --detect.project.name="MyProject" \
  --detect.project.version.name="1.0.0"

# Export SBOM
curl -X GET \
  -H "Authorization: Bearer $BD_TOKEN" \
  "$BD_URL/api/projects/$PROJECT_ID/versions/$VERSION_ID/sbom?format=cyclonedx"
```

### SonarQube
```bash
# Analyze with SBOM (passes SBOM file to scanner)
sonar-scanner \
  -Dsonar.projectKey=myproject \
  -Dsonar.sources=. \
  -Dsonar.host.url=$SONAR_URL \
  -Dsonar.login=$SONAR_TOKEN \
  -Dsonar.sbom.path=sbom.json

# Get results
curl -X GET \
  -H "Authorization: Bearer $SONAR_TOKEN" \
  "$SONAR_URL/api/dependencies/list?ps=100&project=myproject"
```

### Sonatype
```bash
# Submit SBOM for analysis
curl -X POST \
  -H "Authorization: Bearer $IQ_TOKEN" \
  -H "Content-Type: application/xml" \
  --data-binary @sbom.xml \
  "$IQ_URL/api/v2/scan/applications/$APP_ID"

# Get CycloneDX export with vulnerabilities
curl -X GET \
  -H "Authorization: Bearer $IQ_TOKEN" \
  "$IQ_URL/api/v2/cycloneDx/1.5/$APP_INTERNAL_ID/stages/build"
```

---

## Recommendations for Flox Integration

Given Flox's use case:

1. **For Enterprise Sales**: Sonatype or Black Duck
   - Most comprehensive for regulated industries
   - Best policy engines
   - VEX support for false positive management

2. **For Developer Workflows**: Snyk
   - Best developer experience
   - Fast feedback
   - Reachability analysis (preview)

3. **For Integrated Platforms**: SonarQube
   - If already using SonarQube for code quality
   - Unified security + quality metrics

4. **For Flexibility**: Support multiple
   - Many enterprises use 2-3 tools
   - Different teams prefer different tools
   - API compatibility is straightforward

All four accept standard SPDX SBOMs, so Flox could generate once and submit to multiple platforms.
