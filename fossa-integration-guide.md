# FOSSA API Integration Guide
## Complete Guide to SBOM Import & License Compliance Analysis

**Version:** 1.0  
**Last Updated:** January 2026  
**API Version:** v2

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Authentication Setup](#authentication-setup)
3. [SBOM Import Workflow](#sbom-import-workflow)
4. [License Compliance Checking](#license-compliance-checking)
5. [Complete Python Integration](#complete-python-integration)
6. [Bash Automation Scripts](#bash-automation-scripts)
7. [API Reference](#api-reference)
8. [Error Handling](#error-handling)
9. [Best Practices](#best-practices)

---

## Quick Start

### Prerequisites
```bash
# Required
- FOSSA account (free tier: https://fossa.com)
- API token with Full Access permissions
- SBOM file (SPDX or CycloneDX format)

# Optional but recommended
- jq (for JSON parsing)
- Python 3.8+ (for Python examples)
```

### 3-Minute Test

```bash
# 1. Set your API token
export FOSSA_TOKEN="your-api-token-here"

# 2. Test authentication
curl -s -H "Authorization: Bearer $FOSSA_TOKEN" \
  "https://app.fossa.com/api/v2/organizations" | jq .

# 3. Check for license issues
curl -s -G "https://app.fossa.com/api/v2/issues" \
  -d "category=licensing" \
  -d "scope[type]=global" \
  -H "Authorization: Bearer $FOSSA_TOKEN" | jq '.issues[] | {dependency: .dependency.name, license: .dependency.license, severity: .severity}'

# Success! You're ready to integrate.
```

---

## Authentication Setup

### Getting Your API Token

#### Step 1: Sign Up for FOSSA
1. Go to https://app.fossa.com
2. Sign up (free tier available)
3. Verify your email

#### Step 2: Generate API Token
1. Click profile icon (top right) → **Account Settings**
2. Go to **Integrations** tab → **API** section
3. Click **Create New Token**
4. Configuration:
   - **Name**: `SBOM-Integration` (descriptive)
   - **Push Only**: ❌ UNCHECK (need read access)
   - **Full Access**: ✅ Required for reading issues
5. Click **Create**
6. **Copy token immediately** (shown only once)

#### Step 3: Store Token Securely

```bash
# Linux/Mac - Add to ~/.bashrc or ~/.zshrc
export FOSSA_TOKEN="your-token-here"

# Or use a .env file (recommended)
cat > .env << EOF
FOSSA_TOKEN=your-token-here
EOF

# Load when needed
source .env
```

### Test Authentication

```bash
#!/bin/bash
# test-fossa-auth.sh

FOSSA_TOKEN="${FOSSA_TOKEN}"

if [ -z "$FOSSA_TOKEN" ]; then
  echo "Error: FOSSA_TOKEN not set"
  exit 1
fi

echo "Testing FOSSA authentication..."

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer $FOSSA_TOKEN" \
  "https://app.fossa.com/api/v2/organizations")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ Authentication successful!"
  echo "$BODY" | jq -r '.[] | "Organization: \(.name)"'
else
  echo "✗ Authentication failed (HTTP $HTTP_CODE)"
  echo "$BODY" | jq .
  exit 1
fi
```

---

## SBOM Import Workflow

FOSSA uses a **two-step upload process**:
1. Get a pre-signed upload URL (valid 5 minutes)
2. Upload SBOM file to that URL

### Step-by-Step Process

#### Step 1: Get Signed Upload URL

```bash
#!/bin/bash
# get-signed-url.sh

FOSSA_TOKEN="your-token"
PROJECT_NAME="my-application"
VERSION="v1.2.3"

# Get signed URL
RESPONSE=$(curl -s -G "https://app.fossa.com/api/components/signed_url" \
  --data-urlencode "packageSpec=custom+${PROJECT_NAME}" \
  --data-urlencode "revision=${VERSION}" \
  --data-urlencode "fetcherType=user_defined" \
  -H "Authorization: Bearer $FOSSA_TOKEN")

# Extract signed URL
SIGNED_URL=$(echo "$RESPONSE" | jq -r '.signedURL')
EXPIRES=$(echo "$RESPONSE" | jq -r '.expiresAt')

if [ "$SIGNED_URL" = "null" ] || [ -z "$SIGNED_URL" ]; then
  echo "Error getting signed URL:"
  echo "$RESPONSE" | jq .
  exit 1
fi

echo "Signed URL obtained (expires: $EXPIRES)"
echo "$SIGNED_URL"
```

**Parameters:**
- `packageSpec`: Project identifier in format `custom+project-name`
- `revision`: Version identifier (git SHA, version number, or branch)
- `fetcherType`: Always `user_defined` for SBOM imports

#### Step 2: Upload SBOM File

```bash
#!/bin/bash
# upload-sbom.sh

SIGNED_URL="$1"  # From step 1
SBOM_FILE="$2"   # Path to your SBOM file

if [ -z "$SIGNED_URL" ] || [ -z "$SBOM_FILE" ]; then
  echo "Usage: $0 <signed_url> <sbom_file>"
  exit 1
fi

# Detect content type
if [[ "$SBOM_FILE" == *.json ]]; then
  CONTENT_TYPE="application/json"
elif [[ "$SBOM_FILE" == *.xml ]]; then
  CONTENT_TYPE="application/xml"
elif [[ "$SBOM_FILE" == *.spdx ]]; then
  CONTENT_TYPE="text/plain"
else
  CONTENT_TYPE="application/json"  # default
fi

echo "Uploading $SBOM_FILE..."

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PUT \
  -H "Content-Type: $CONTENT_TYPE" \
  --data-binary "@${SBOM_FILE}" \
  "$SIGNED_URL")

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ SBOM uploaded successfully!"
else
  echo "✗ Upload failed (HTTP $HTTP_CODE)"
  exit 1
fi
```

### Complete Import Script

```bash
#!/bin/bash
# fossa-import-sbom.sh
# Complete SBOM import workflow

set -e

# Configuration
FOSSA_TOKEN="${FOSSA_TOKEN}"
PROJECT_NAME="${1}"
VERSION="${2}"
SBOM_FILE="${3}"

# Validate inputs
if [ -z "$FOSSA_TOKEN" ]; then
  echo "Error: FOSSA_TOKEN environment variable not set"
  exit 1
fi

if [ -z "$PROJECT_NAME" ] || [ -z "$VERSION" ] || [ -z "$SBOM_FILE" ]; then
  echo "Usage: $0 <project_name> <version> <sbom_file>"
  echo "Example: $0 my-app v1.0.0 ./sbom.json"
  exit 1
fi

if [ ! -f "$SBOM_FILE" ]; then
  echo "Error: SBOM file not found: $SBOM_FILE"
  exit 1
fi

echo "======================================"
echo "FOSSA SBOM Import"
echo "======================================"
echo "Project: $PROJECT_NAME"
echo "Version: $VERSION"
echo "SBOM File: $SBOM_FILE"
echo "======================================"

# Step 1: Get signed URL
echo
echo "[1/3] Getting signed upload URL..."
RESPONSE=$(curl -s -G "https://app.fossa.com/api/components/signed_url" \
  --data-urlencode "packageSpec=custom+${PROJECT_NAME}" \
  --data-urlencode "revision=${VERSION}" \
  --data-urlencode "fetcherType=user_defined" \
  -H "Authorization: Bearer $FOSSA_TOKEN")

SIGNED_URL=$(echo "$RESPONSE" | jq -r '.signedURL')

if [ "$SIGNED_URL" = "null" ] || [ -z "$SIGNED_URL" ]; then
  echo "✗ Failed to get signed URL"
  echo "$RESPONSE" | jq .
  exit 1
fi

echo "✓ Signed URL obtained (valid for 5 minutes)"

# Step 2: Upload SBOM
echo
echo "[2/3] Uploading SBOM..."

# Detect content type
CONTENT_TYPE="application/json"
if [[ "$SBOM_FILE" == *.xml ]]; then
  CONTENT_TYPE="application/xml"
elif [[ "$SBOM_FILE" == *.spdx ]]; then
  CONTENT_TYPE="text/plain"
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PUT \
  -H "Content-Type: $CONTENT_TYPE" \
  --data-binary "@${SBOM_FILE}" \
  "$SIGNED_URL")

if [ "$HTTP_CODE" != "200" ]; then
  echo "✗ Upload failed (HTTP $HTTP_CODE)"
  exit 1
fi

echo "✓ SBOM uploaded successfully"

# Step 3: Generate project URL
echo
echo "[3/3] Processing complete!"
PROJECT_ID=$(echo "custom+${PROJECT_NAME}" | jq -sRr @uri)
VERSION_ENCODED=$(echo "${VERSION}" | jq -sRr @uri)
PROJECT_URL="https://app.fossa.com/projects/${PROJECT_ID}/refs/branch/${VERSION_ENCODED}"

echo
echo "======================================"
echo "✓ SBOM Import Complete!"
echo "======================================"
echo "View project at:"
echo "$PROJECT_URL"
echo
echo "FOSSA will now:"
echo "  • Parse SBOM components"
echo "  • Detect licenses"
echo "  • Scan for vulnerabilities"
echo "  • Check policy compliance"
echo
echo "Processing typically takes 1-5 minutes."
echo "======================================"
```

**Usage:**
```bash
chmod +x fossa-import-sbom.sh
./fossa-import-sbom.sh my-app v1.0.0 ./sbom.json
```

---

## License Compliance Checking

### Issues API Overview

**Base URL:** `https://app.fossa.com/api/v2/issues`

**Issue Categories:**
- `licensing` - License policy violations (compliance, indemnity risk)
- `vulnerability` - Security vulnerabilities (CVEs)
- `quality` - Outdated or deprecated dependencies
- `risk` - Unlicensed or unknown components

### Get All License Issues

```bash
#!/bin/bash
# get-license-issues.sh

FOSSA_TOKEN="$FOSSA_TOKEN"

curl -s -G "https://app.fossa.com/api/v2/issues" \
  -d "category=licensing" \
  -d "scope[type]=global" \
  -H "Authorization: Bearer $FOSSA_TOKEN" | \
  jq '.issues[] | {
    dependency: .dependency.name,
    version: .dependency.version,
    license: .dependency.license,
    issue: .title,
    severity: .severity,
    project: .project.name
  }'
```

### Get Issues for Specific Project

```bash
#!/bin/bash
# get-project-issues.sh

FOSSA_TOKEN="$FOSSA_TOKEN"
PROJECT_NAME="my-application"
VERSION="v1.0.0"

# URL encode the project ID
PROJECT_ID=$(echo "custom+${PROJECT_NAME}" | python3 -c "import sys; from urllib.parse import quote; print(quote(sys.stdin.read().strip()))")

curl -s -G "https://app.fossa.com/api/v2/issues" \
  -d "category=licensing" \
  -d "scope[type]=project" \
  -d "scope[id]=${PROJECT_ID}" \
  -d "scope[revision]=${VERSION}" \
  -H "Authorization: Bearer $FOSSA_TOKEN" | \
  jq '.issues'
```

### Filter High-Severity Issues

```bash
#!/bin/bash
# get-high-severity-issues.sh

FOSSA_TOKEN="$FOSSA_TOKEN"

curl -s -G "https://app.fossa.com/api/v2/issues" \
  -d "category=licensing" \
  -d "scope[type]=global" \
  -d "filter[resolution]=active" \
  -H "Authorization: Bearer $FOSSA_TOKEN" | \
  jq '[.issues[] | select(.severity == "high" or .severity == "critical")] | 
      map({
        dependency: .dependency.name,
        license: .dependency.license,
        issue: .title,
        severity: .severity
      })'
```

### Export Issues to CSV

```bash
#!/bin/bash
# export-issues-csv.sh

FOSSA_TOKEN="$FOSSA_TOKEN"
OUTPUT_FILE="license-issues.csv"

curl -s -G "https://app.fossa.com/api/v2/issues" \
  -d "category=licensing" \
  -d "scope[type]=global" \
  -d "csv=true" \
  -H "Authorization: Bearer $FOSSA_TOKEN" \
  -o "$OUTPUT_FILE"

echo "✓ Exported to $OUTPUT_FILE"
echo "$(wc -l < $OUTPUT_FILE) issues found"
```

### Check for Copyleft Licenses

```bash
#!/bin/bash
# check-copyleft.sh

FOSSA_TOKEN="$FOSSA_TOKEN"

COPYLEFT_LICENSES=("GPL" "LGPL" "AGPL" "MPL" "EPL")

echo "Checking for copyleft licenses..."
echo

for LICENSE in "${COPYLEFT_LICENSES[@]}"; do
  COUNT=$(curl -s -G "https://app.fossa.com/api/v2/issues" \
    -d "category=licensing" \
    -d "scope[type]=global" \
    -d "filter[search]=${LICENSE}" \
    -H "Authorization: Bearer $FOSSA_TOKEN" | \
    jq '.issues | length')
  
  if [ "$COUNT" -gt 0 ]; then
    echo "⚠️  Found $COUNT dependencies with $LICENSE licenses"
  fi
done
```

### Get Issue Counts Summary

```bash
#!/bin/bash
# get-issue-summary.sh

FOSSA_TOKEN="$FOSSA_TOKEN"

echo "FOSSA Issue Summary"
echo "===================="

for CATEGORY in licensing vulnerability quality risk; do
  COUNT=$(curl -s -G "https://app.fossa.com/api/v2/issues/counts" \
    -d "scope[type]=global" \
    -H "Authorization: Bearer $FOSSA_TOKEN" | \
    jq -r ".${CATEGORY} // 0")
  
  printf "%-15s: %3d\n" "${CATEGORY^}" "$COUNT"
done
```

---

## Complete Python Integration

### Full-Featured Python Client

```python
#!/usr/bin/env python3
"""
FOSSA API Client
Complete integration for SBOM import and license compliance checking
"""

import os
import sys
import json
import time
import argparse
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import quote, urlencode
import requests


class FOSSAError(Exception):
    """Base exception for FOSSA API errors"""
    pass


class FOSSAClient:
    """
    FOSSA API Client
    
    Handles authentication, SBOM imports, and license compliance checks.
    """
    
    def __init__(self, api_token: str, base_url: str = "https://app.fossa.com"):
        """
        Initialize FOSSA client
        
        Args:
            api_token: FOSSA API token (Full Access)
            base_url: FOSSA instance URL
        """
        self.api_token = api_token
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "User-Agent": "FOSSA-API-Client/1.0"
        })
    
    def test_connection(self) -> bool:
        """
        Test API authentication
        
        Returns:
            bool: True if authentication successful
        
        Raises:
            FOSSAError: If authentication fails
        """
        try:
            response = self.session.get(f"{self.base_url}/api/v2/organizations")
            response.raise_for_status()
            orgs = response.json()
            print(f"✓ Authentication successful")
            print(f"  Organizations: {len(orgs)}")
            return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise FOSSAError("Authentication failed: Invalid API token")
            raise FOSSAError(f"HTTP {e.response.status_code}: {e.response.text}")
        except requests.exceptions.RequestException as e:
            raise FOSSAError(f"Connection error: {str(e)}")
    
    def get_signed_upload_url(
        self, 
        project_name: str, 
        revision: str,
        fetcher_type: str = "user_defined"
    ) -> Dict[str, str]:
        """
        Get pre-signed URL for SBOM upload
        
        Args:
            project_name: Project identifier (e.g., "my-app")
            revision: Version/revision (e.g., "v1.0.0", git SHA)
            fetcher_type: Always "user_defined" for SBOM imports
        
        Returns:
            dict: {'signedURL': str, 'expiresAt': str}
        
        Raises:
            FOSSAError: If request fails
        """
        params = {
            "packageSpec": f"custom+{project_name}",
            "revision": revision,
            "fetcherType": fetcher_type
        }
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/components/signed_url",
                params=params
            )
            response.raise_for_status()
            data = response.json()
            
            if 'signedURL' not in data:
                raise FOSSAError(f"No signed URL in response: {data}")
            
            return data
        except requests.exceptions.RequestException as e:
            raise FOSSAError(f"Failed to get signed URL: {str(e)}")
    
    def upload_sbom(
        self,
        signed_url: str,
        sbom_file_path: str
    ) -> bool:
        """
        Upload SBOM file to pre-signed URL
        
        Args:
            signed_url: Pre-signed upload URL from get_signed_upload_url()
            sbom_file_path: Path to SBOM file
        
        Returns:
            bool: True if upload successful
        
        Raises:
            FOSSAError: If upload fails
        """
        file_path = Path(sbom_file_path)
        
        if not file_path.exists():
            raise FOSSAError(f"SBOM file not found: {sbom_file_path}")
        
        # Determine content type
        suffix = file_path.suffix.lower()
        content_type_map = {
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.spdx': 'text/plain'
        }
        content_type = content_type_map.get(suffix, 'application/json')
        
        try:
            with open(file_path, 'rb') as f:
                response = requests.put(
                    signed_url,
                    data=f,
                    headers={'Content-Type': content_type}
                )
            
            if response.status_code != 200:
                raise FOSSAError(
                    f"Upload failed: HTTP {response.status_code}"
                )
            
            return True
        except requests.exceptions.RequestException as e:
            raise FOSSAError(f"Upload error: {str(e)}")
    
    def import_sbom(
        self,
        project_name: str,
        revision: str,
        sbom_file_path: str
    ) -> str:
        """
        Complete SBOM import workflow (get URL + upload)
        
        Args:
            project_name: Project identifier
            revision: Version/revision
            sbom_file_path: Path to SBOM file
        
        Returns:
            str: Project URL in FOSSA
        
        Raises:
            FOSSAError: If import fails
        """
        print(f"Importing SBOM for {project_name} @ {revision}")
        
        # Step 1: Get signed URL
        print("  [1/2] Getting signed upload URL...")
        url_data = self.get_signed_upload_url(project_name, revision)
        print(f"  ✓ Signed URL obtained (expires: {url_data['expiresAt']})")
        
        # Step 2: Upload SBOM
        print("  [2/2] Uploading SBOM...")
        self.upload_sbom(url_data['signedURL'], sbom_file_path)
        print("  ✓ Upload complete")
        
        # Generate project URL
        project_id = quote(f"custom+{project_name}")
        revision_encoded = quote(revision)
        project_url = f"{self.base_url}/projects/{project_id}/refs/branch/{revision_encoded}"
        
        print(f"\n✓ SBOM imported successfully!")
        print(f"  View at: {project_url}")
        
        return project_url
    
    def get_issues(
        self,
        category: str = "licensing",
        scope_type: str = "global",
        project_id: Optional[str] = None,
        revision: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get issues from FOSSA
        
        Args:
            category: Issue category (licensing, vulnerability, quality, risk)
            scope_type: Scope type (global, project)
            project_id: Project ID (required if scope_type=project)
            revision: Project revision (required if scope_type=project)
            filters: Additional filters (resolution, severity, search, etc.)
        
        Returns:
            list: List of issue dictionaries
        
        Raises:
            FOSSAError: If request fails
        """
        params = {
            "category": category,
            "scope[type]": scope_type
        }
        
        if scope_type == "project":
            if not project_id or not revision:
                raise FOSSAError("project_id and revision required for project scope")
            params["scope[id]"] = project_id
            params["scope[revision]"] = revision
        
        if filters:
            for key, value in filters.items():
                if isinstance(value, list):
                    for i, v in enumerate(value):
                        params[f"filter[{key}][{i}]"] = v
                else:
                    params[f"filter[{key}]"] = value
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/v2/issues",
                params=params
            )
            response.raise_for_status()
            data = response.json()
            return data.get('issues', [])
        except requests.exceptions.RequestException as e:
            raise FOSSAError(f"Failed to get issues: {str(e)}")
    
    def get_license_issues(
        self,
        project_name: Optional[str] = None,
        revision: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get license compliance issues
        
        Args:
            project_name: Optional project name (if None, gets global issues)
            revision: Optional revision (required if project_name provided)
        
        Returns:
            list: License issues
        """
        if project_name:
            project_id = f"custom+{project_name}"
            return self.get_issues(
                category="licensing",
                scope_type="project",
                project_id=project_id,
                revision=revision
            )
        else:
            return self.get_issues(category="licensing", scope_type="global")
    
    def get_issue_summary(self) -> Dict[str, int]:
        """
        Get issue count summary
        
        Returns:
            dict: Issue counts by category
        """
        try:
            response = self.session.get(
                f"{self.base_url}/api/v2/issues/counts",
                params={"scope[type]": "global"}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise FOSSAError(f"Failed to get issue summary: {str(e)}")
    
    def export_issues_csv(
        self,
        output_path: str,
        category: str = "licensing"
    ) -> int:
        """
        Export issues to CSV
        
        Args:
            output_path: Path to output CSV file
            category: Issue category
        
        Returns:
            int: Number of issues exported
        """
        params = {
            "category": category,
            "scope[type]": "global",
            "csv": "true"
        }
        
        try:
            response = self.session.get(
                f"{self.base_url}/api/v2/issues",
                params=params
            )
            response.raise_for_status()
            
            with open(output_path, 'w') as f:
                f.write(response.text)
            
            # Count lines (excluding header)
            with open(output_path, 'r') as f:
                count = sum(1 for line in f) - 1
            
            return count
        except requests.exceptions.RequestException as e:
            raise FOSSAError(f"Failed to export CSV: {str(e)}")


def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description="FOSSA API Client - Import SBOMs and check license compliance"
    )
    parser.add_argument(
        '--token',
        default=os.getenv('FOSSA_TOKEN'),
        help='FOSSA API token (or set FOSSA_TOKEN env var)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Test command
    subparsers.add_parser('test', help='Test API authentication')
    
    # Import command
    import_parser = subparsers.add_parser('import', help='Import SBOM')
    import_parser.add_argument('project', help='Project name')
    import_parser.add_argument('version', help='Version/revision')
    import_parser.add_argument('sbom_file', help='Path to SBOM file')
    
    # Issues command
    issues_parser = subparsers.add_parser('issues', help='Get license issues')
    issues_parser.add_argument('--project', help='Project name (optional)')
    issues_parser.add_argument('--version', help='Version (required if --project set)')
    issues_parser.add_argument('--csv', help='Export to CSV file')
    
    # Summary command
    subparsers.add_parser('summary', help='Get issue summary')
    
    args = parser.parse_args()
    
    if not args.token:
        print("Error: FOSSA_TOKEN not set", file=sys.stderr)
        print("Set via: export FOSSA_TOKEN=your-token", file=sys.stderr)
        sys.exit(1)
    
    try:
        client = FOSSAClient(args.token)
        
        if args.command == 'test':
            client.test_connection()
        
        elif args.command == 'import':
            client.import_sbom(
                args.project,
                args.version,
                args.sbom_file
            )
        
        elif args.command == 'issues':
            if args.csv:
                count = client.export_issues_csv(args.csv)
                print(f"✓ Exported {count} issues to {args.csv}")
            else:
                issues = client.get_license_issues(
                    args.project,
                    args.version
                )
                print(f"\nFound {len(issues)} license issues:\n")
                for issue in issues:
                    dep = issue.get('dependency', {})
                    print(f"  • {dep.get('name')} ({dep.get('version')})")
                    print(f"    License: {dep.get('license')}")
                    print(f"    Issue: {issue.get('title')}")
                    print(f"    Severity: {issue.get('severity')}")
                    print()
        
        elif args.command == 'summary':
            summary = client.get_issue_summary()
            print("\nIssue Summary:")
            print("=" * 40)
            for category, count in summary.items():
                print(f"  {category.capitalize():<15}: {count:>3}")
        
        else:
            parser.print_help()
    
    except FOSSAError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == '__main__':
    main()
```

**Usage Examples:**

```bash
# Test authentication
python3 fossa_client.py test

# Import SBOM
python3 fossa_client.py import my-app v1.0.0 ./sbom.json

# Get license issues (global)
python3 fossa_client.py issues

# Get issues for specific project
python3 fossa_client.py issues --project my-app --version v1.0.0

# Export issues to CSV
python3 fossa_client.py issues --csv license-issues.csv

# Get summary
python3 fossa_client.py summary
```

---

## Bash Automation Scripts

### CI/CD Integration Script

```bash
#!/bin/bash
# fossa-ci-check.sh
# CI/CD pipeline integration for FOSSA license compliance

set -e

# Configuration
FOSSA_TOKEN="${FOSSA_TOKEN}"
PROJECT_NAME="${CI_PROJECT_NAME:-$(basename $(pwd))}"
VERSION="${CI_COMMIT_SHA:-$(git rev-parse HEAD)}"
SBOM_FILE="${1:-./sbom.json}"
FAIL_ON_ISSUES="${FAIL_ON_ISSUES:-true}"

echo "========================================"
echo "FOSSA License Compliance Check"
echo "========================================"
echo "Project: $PROJECT_NAME"
echo "Version: $VERSION"
echo "SBOM: $SBOM_FILE"
echo "========================================"

# Check prerequisites
if [ -z "$FOSSA_TOKEN" ]; then
  echo "✗ Error: FOSSA_TOKEN not set"
  exit 1
fi

if [ ! -f "$SBOM_FILE" ]; then
  echo "✗ Error: SBOM file not found: $SBOM_FILE"
  exit 1
fi

# Import SBOM
echo
echo "[1/3] Importing SBOM to FOSSA..."

# Get signed URL
SIGNED_URL_RESPONSE=$(curl -s -G "https://app.fossa.com/api/components/signed_url" \
  --data-urlencode "packageSpec=custom+${PROJECT_NAME}" \
  --data-urlencode "revision=${VERSION}" \
  --data-urlencode "fetcherType=user_defined" \
  -H "Authorization: Bearer $FOSSA_TOKEN")

SIGNED_URL=$(echo "$SIGNED_URL_RESPONSE" | jq -r '.signedURL')

if [ "$SIGNED_URL" = "null" ]; then
  echo "✗ Failed to get signed URL"
  exit 1
fi

# Upload SBOM
curl -s -X PUT \
  -H "Content-Type: application/json" \
  --data-binary "@${SBOM_FILE}" \
  "$SIGNED_URL" > /dev/null

echo "✓ SBOM uploaded"

# Wait for processing
echo
echo "[2/3] Waiting for FOSSA to process SBOM (30 seconds)..."
sleep 30

# Check for license issues
echo
echo "[3/3] Checking for license compliance issues..."

PROJECT_ID=$(echo "custom+${PROJECT_NAME}" | python3 -c "import sys; from urllib.parse import quote; print(quote(sys.stdin.read().strip()))")

ISSUES=$(curl -s -G "https://app.fossa.com/api/v2/issues" \
  -d "category=licensing" \
  -d "scope[type]=project" \
  -d "scope[id]=${PROJECT_ID}" \
  -d "scope[revision]=${VERSION}" \
  -H "Authorization: Bearer $FOSSA_TOKEN")

ISSUE_COUNT=$(echo "$ISSUES" | jq '.issues | length')

echo
echo "========================================"
echo "Results:"
echo "========================================"
echo "License Issues Found: $ISSUE_COUNT"

if [ "$ISSUE_COUNT" -gt 0 ]; then
  echo
  echo "Issues:"
  echo "$ISSUES" | jq -r '.issues[] | "  • \(.dependency.name) (\(.dependency.license)) - \(.title)"'
  
  if [ "$FAIL_ON_ISSUES" = "true" ]; then
    echo
    echo "✗ License compliance check FAILED"
    echo "Fix issues at: https://app.fossa.com/projects/${PROJECT_ID}/refs/branch/$(echo $VERSION | python3 -c "import sys; from urllib.parse import quote; print(quote(sys.stdin.read().strip()))")"
    exit 1
  fi
else
  echo "✓ No license compliance issues found"
fi

echo "========================================"
```

### Monitoring Script

```bash
#!/bin/bash
# fossa-monitor.sh
# Monitor FOSSA for new license issues

FOSSA_TOKEN="${FOSSA_TOKEN}"
CHECK_INTERVAL="${CHECK_INTERVAL:-3600}"  # 1 hour
ALERT_EMAIL="${ALERT_EMAIL}"

while true; do
  echo "[$(date)] Checking FOSSA for issues..."
  
  SUMMARY=$(curl -s -G "https://app.fossa.com/api/v2/issues/counts" \
    -d "scope[type]=global" \
    -H "Authorization: Bearer $FOSSA_TOKEN")
  
  LICENSE_ISSUES=$(echo "$SUMMARY" | jq -r '.licensing // 0')
  VULN_ISSUES=$(echo "$SUMMARY" | jq -r '.vulnerability // 0')
  
  echo "  License issues: $LICENSE_ISSUES"
  echo "  Vulnerabilities: $VULN_ISSUES"
  
  if [ "$LICENSE_ISSUES" -gt 0 ] && [ -n "$ALERT_EMAIL" ]; then
    echo "⚠️  Sending alert email..."
    echo "License compliance issues detected: $LICENSE_ISSUES issues found" | \
      mail -s "FOSSA Alert: License Issues Detected" "$ALERT_EMAIL"
  fi
  
  echo "  Next check in ${CHECK_INTERVAL}s"
  sleep "$CHECK_INTERVAL"
done
```

---

## API Reference

### Base URLs
- **Production:** `https://app.fossa.com`
- **On-Premise:** `https://fossa.your-company.com`

### Authentication
All requests require Bearer token:
```http
Authorization: Bearer YOUR_API_TOKEN
```

### Key Endpoints

#### 1. Get Signed Upload URL
```http
GET /api/components/signed_url
```

**Query Parameters:**
- `packageSpec` (required): `custom+project-name`
- `revision` (required): Version identifier
- `fetcherType` (required): `user_defined`

**Response:**
```json
{
  "signedURL": "https://storage.googleapis.com/...",
  "expiresAt": "2026-01-13T17:30:00Z"
}
```

#### 2. Upload SBOM
```http
PUT <signed_url>
Content-Type: application/json

<SBOM file contents>
```

#### 3. Get Issues
```http
GET /api/v2/issues
```

**Query Parameters:**
- `category`: `licensing`, `vulnerability`, `quality`, `risk`
- `scope[type]`: `global`, `project`
- `scope[id]`: Project ID (if scope=project)
- `scope[revision]`: Revision (if scope=project)
- `filter[resolution]`: `active`, `resolved`, `ignored`
- `filter[search]`: Search term
- `csv`: `true` for CSV export

**Response:**
```json
{
  "issues": [
    {
      "id": "issue-id",
      "type": "license_policy_violation",
      "severity": "high",
      "title": "GPL-3.0 license not allowed",
      "dependency": {
        "name": "library-name",
        "version": "1.0.0",
        "license": "GPL-3.0-only"
      },
      "resolved": false,
      "ignored": false,
      "createdAt": "2026-01-10T15:30:00Z",
      "project": {
        "name": "my-app",
        "url": "https://app.fossa.com/projects/..."
      }
    }
  ],
  "pagination": {
    "page": 1,
    "count": 50,
    "total": 125
  }
}
```

#### 4. Get Issue Counts
```http
GET /api/v2/issues/counts
```

**Query Parameters:**
- `scope[type]`: `global`, `project`

**Response:**
```json
{
  "licensing": 15,
  "vulnerability": 42,
  "quality": 8,
  "risk": 3
}
```

---

## Error Handling

### Common Errors

| HTTP Code | Error | Solution |
|-----------|-------|----------|
| 401 | Unauthorized | Check API token, ensure Full Access |
| 403 | Forbidden | Token lacks required permissions |
| 404 | Not Found | Check project ID, revision exists |
| 429 | Rate Limited | Implement exponential backoff |
| 500 | Server Error | Retry with exponential backoff |

### Retry Logic Example

```python
import time
from typing import Callable, Any

def retry_with_backoff(
    func: Callable,
    max_retries: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0
) -> Any:
    """
    Retry function with exponential backoff
    
    Args:
        func: Function to retry
        max_retries: Maximum number of retries
        initial_delay: Initial delay in seconds
        backoff_factor: Multiplier for each retry
    
    Returns:
        Function result
    
    Raises:
        Last exception if all retries fail
    """
    delay = initial_delay
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            return func()
        except requests.exceptions.HTTPError as e:
            last_exception = e
            
            # Don't retry on 4xx errors (except 429)
            if 400 <= e.response.status_code < 500:
                if e.response.status_code != 429:
                    raise
            
            if attempt < max_retries:
                print(f"Retry {attempt + 1}/{max_retries} after {delay}s...")
                time.sleep(delay)
                delay *= backoff_factor
            else:
                raise last_exception
    
    raise last_exception

# Usage
result = retry_with_backoff(lambda: client.get_issues())
```

---

## Best Practices

### 1. API Token Security

✅ **DO:**
- Store tokens in environment variables or secrets managers
- Use separate tokens for dev/staging/prod
- Rotate tokens periodically
- Use Full Access only when needed (Push Only for CI/CD scans)

❌ **DON'T:**
- Commit tokens to git
- Share tokens in Slack/email
- Use personal tokens for production systems
- Log tokens in application logs

### 2. SBOM Import Best Practices

✅ **DO:**
- Use semantic versioning for revisions
- Include complete dependency graph
- Validate SBOM before upload
- Wait 1-5 minutes for processing before querying issues
- Use descriptive project names

❌ **DON'T:**
- Use random strings for revisions
- Upload partial SBOMs
- Query issues immediately after upload
- Reuse the same revision for different builds

### 3. Rate Limiting

FOSSA API rate limits (typical):
- **Read operations:** 100 requests/minute
- **Write operations:** 20 requests/minute

Implement rate limiting:
```python
import time
from collections import deque

class RateLimiter:
    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self.calls = deque()
    
    def __call__(self, func):
        def wrapper(*args, **kwargs):
            now = time.time()
            
            # Remove old calls
            while self.calls and self.calls[0] < now - self.period:
                self.calls.popleft()
            
            # Wait if at limit
            if len(self.calls) >= self.max_calls:
                sleep_time = self.period - (now - self.calls[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                self.calls.popleft()
            
            self.calls.append(time.time())
            return func(*args, **kwargs)
        
        return wrapper

# Usage
@RateLimiter(max_calls=100, period=60)
def get_issues():
    return client.get_issues()
```

### 4. CI/CD Integration

**Recommended workflow:**

1. **Build** → Generate SBOM (e.g., with Syft, cdxgen)
2. **Upload** → Import SBOM to FOSSA
3. **Wait** → 30-60 seconds for processing
4. **Check** → Query for license/security issues
5. **Gate** → Fail build if high-severity issues found

```yaml
# GitHub Actions example
- name: Generate SBOM
  run: syft . -o cyclonedx-json > sbom.json

- name: Import to FOSSA
  run: |
    python3 fossa_client.py import \
      my-app ${{ github.sha }} sbom.json
  env:
    FOSSA_TOKEN: ${{ secrets.FOSSA_TOKEN }}

- name: Check compliance
  run: |
    python3 fossa_client.py issues \
      --project my-app \
      --version ${{ github.sha }}
```

### 5. Monitoring

Set up automated monitoring:
- Daily compliance checks
- Alert on new high-severity issues
- Track issue trends over time
- Export weekly CSV reports

---

## Troubleshooting

### SBOM Upload Fails

**Symptom:** HTTP 400/500 on upload

**Solutions:**
1. Validate SBOM format (use SPDX/CycloneDX validators)
2. Check file size (< 100MB recommended)
3. Ensure correct Content-Type header
4. Upload within 5 minutes of getting signed URL

### No Issues Found

**Symptom:** Empty issues array after import

**Solutions:**
1. Wait longer (processing takes 1-5 minutes)
2. Check project policies are configured
3. Verify SBOM contains valid license data
4. Check FOSSA UI manually for project

### Authentication Errors

**Symptom:** 401 Unauthorized

**Solutions:**
1. Verify token is Full Access (not Push Only)
2. Check token hasn't expired
3. Ensure correct token format (`Bearer TOKEN`)
4. Try regenerating token

---

## Additional Resources

### FOSSA Documentation
- **Main Docs:** https://docs.fossa.com
- **API Reference:** https://docs.fossa.com/docs/api-reference
- **CLI Docs:** https://github.com/fossas/fossa-cli

### SBOM Standards
- **SPDX:** https://spdx.dev
- **CycloneDX:** https://cyclonedx.org

### Support
- **Email:** [email protected]
- **Slack:** FOSSA Community Slack
- **GitHub Issues:** https://github.com/fossas/fossa-cli/issues

---

## Appendix: Complete Example Workflow

```bash
#!/bin/bash
# complete-fossa-workflow.sh
# End-to-end SBOM → License Compliance workflow

set -e

PROJECT="my-application"
VERSION="v1.0.0"
SBOM_FILE="./sbom.json"

echo "============================================"
echo "Complete FOSSA License Compliance Workflow"
echo "============================================"

# 1. Generate SBOM (example with Syft)
echo
echo "[1/5] Generating SBOM with Syft..."
syft . -o cyclonedx-json > "$SBOM_FILE"
echo "✓ SBOM generated: $SBOM_FILE"

# 2. Import to FOSSA
echo
echo "[2/5] Importing SBOM to FOSSA..."
python3 fossa_client.py import "$PROJECT" "$VERSION" "$SBOM_FILE"

# 3. Wait for processing
echo
echo "[3/5] Waiting for FOSSA to process SBOM..."
sleep 60

# 4. Check for issues
echo
echo "[4/5] Checking for license compliance issues..."
python3 fossa_client.py issues --project "$PROJECT" --version "$VERSION"

# 5. Export report
echo
echo "[5/5] Exporting compliance report..."
python3 fossa_client.py issues --csv "license-report-${VERSION}.csv"

echo
echo "============================================"
echo "✓ Workflow Complete!"
echo "============================================"
echo "Review results:"
echo "  • CSV Report: license-report-${VERSION}.csv"
echo "  • FOSSA Dashboard: https://app.fossa.com/projects/custom%2B${PROJECT}"
echo "============================================"
```

---

**End of Guide**

For questions or issues, contact [email protected] or visit https://docs.fossa.com
