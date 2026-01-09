"""
Patch Detector for Auto-VEX

Detects CVE patches in Nix derivations to automatically determine VEX status.
When a CVE patch is found, the package can be marked as "not_affected" since
the vulnerability has been backported/fixed in nixpkgs.
"""

import re
import os
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class PatchEvidence:
    """Evidence that a CVE has been patched."""
    cve_id: str
    source: str  # 'filename', 'content', 'commit_message'
    patch_file: str
    confidence: float = 1.0  # 0.0-1.0
    line_match: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            'cve_id': self.cve_id,
            'source': self.source,
            'patch_file': self.patch_file,
            'confidence': self.confidence,
            'line_match': self.line_match,
        }


@dataclass
class VEXStatus:
    """VEX status for a package."""
    status: str  # 'not_affected', 'affected', 'fixed', 'under_investigation'
    justification: Optional[str] = None
    impact_statement: Optional[str] = None
    patched_cves: Set[str] = field(default_factory=set)
    evidence: List[PatchEvidence] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'status': self.status,
            'justification': self.justification,
            'impact_statement': self.impact_statement,
            'patched_cves': list(self.patched_cves),
            'evidence': [e.to_dict() for e in self.evidence],
        }


class PatchDetector:
    """
    Detects CVE patches in Nix derivations for auto-VEX status.

    Searches for CVE references in:
    1. Patch filenames (e.g., CVE-2024-1234.patch)
    2. Patch file content (e.g., "Fixes CVE-2024-1234")
    3. Commit messages in fetchpatch URLs
    """

    # CVE ID pattern
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

    # Common patch filename patterns
    PATCH_FILE_PATTERNS = [
        r'CVE-\d{4}-\d+\.patch',
        r'fix-CVE-\d{4}-\d+\.patch',
        r'security-CVE-\d{4}-\d+\.patch',
    ]

    def __init__(self):
        """Initialize patch detector."""
        self._cache: Dict[str, Set[str]] = {}

    def detect_patched_cves(self, drv_path: Optional[str] = None,
                           drv_content: Optional[str] = None,
                           patch_paths: Optional[List[str]] = None) -> Dict[str, PatchEvidence]:
        """
        Detect CVEs that have been patched.

        Args:
            drv_path: Path to derivation file
            drv_content: Content of derivation (if already read)
            patch_paths: List of patch file paths to examine

        Returns:
            Dict mapping CVE ID to patch evidence
        """
        results: Dict[str, PatchEvidence] = {}

        # Read derivation content if needed
        if drv_content is None and drv_path:
            try:
                with open(drv_path, 'r', encoding='utf-8', errors='replace') as f:
                    drv_content = f.read()
            except (IOError, OSError) as e:
                logger.error(f"Failed to read {drv_path}: {e}")
                drv_content = ""

        # Extract patch paths from derivation
        if patch_paths is None:
            patch_paths = self._extract_patch_paths(drv_content or "")

        # Check each patch
        for patch_path in patch_paths:
            patch_cves = self._check_patch(patch_path)
            results.update(patch_cves)

        # Also check derivation content directly for CVE references
        if drv_content:
            content_cves = self._check_content_for_cves(drv_content, "derivation")
            # Only add if not already found in patches (lower confidence)
            for cve_id, evidence in content_cves.items():
                if cve_id not in results:
                    evidence.confidence = 0.5  # Lower confidence for inline refs
                    results[cve_id] = evidence

        return results

    def get_vex_status(self, cve_id: str, patched_cves: Dict[str, PatchEvidence]) -> VEXStatus:
        """
        Determine VEX status for a specific CVE.

        Args:
            cve_id: CVE identifier to check
            patched_cves: Dict of patched CVE evidence

        Returns:
            VEXStatus indicating if CVE is patched
        """
        if cve_id.upper() in {c.upper() for c in patched_cves}:
            evidence = patched_cves.get(cve_id.upper()) or patched_cves.get(cve_id)
            return VEXStatus(
                status='not_affected',
                justification='vulnerability_not_present',
                impact_statement=f"Patched in nixpkgs via {evidence.patch_file if evidence else 'backport'}",
                patched_cves={cve_id},
                evidence=[evidence] if evidence else [],
            )

        return VEXStatus(
            status='affected',
            justification=None,
            impact_statement=None,
        )

    def _extract_patch_paths(self, content: str) -> List[str]:
        """Extract patch file paths from derivation content."""
        patches = []

        # Find Nix store paths ending in .patch
        store_pattern = re.compile(r'/nix/store/[a-z0-9]{32}-[^"\']+\.patch')
        patches.extend(store_pattern.findall(content))

        # Find relative patch paths
        rel_pattern = re.compile(r'["\']([./a-zA-Z0-9_-]+\.patch)["\']')
        patches.extend(m.group(1) for m in rel_pattern.finditer(content))

        # Find fetchpatch URLs
        fetchpatch_pattern = re.compile(r'fetchpatch\s*\{[^}]*url\s*=\s*["\']([^"\']+)["\']')
        for m in fetchpatch_pattern.finditer(content):
            patches.append(m.group(1))

        return list(set(patches))

    def _check_patch(self, patch_path: str) -> Dict[str, PatchEvidence]:
        """Check a patch file/URL for CVE references."""
        results: Dict[str, PatchEvidence] = {}

        # Check filename
        filename = Path(patch_path).name if '/' in patch_path else patch_path
        filename_cves = self.CVE_PATTERN.findall(filename)
        for cve in filename_cves:
            cve_upper = cve.upper()
            results[cve_upper] = PatchEvidence(
                cve_id=cve_upper,
                source='filename',
                patch_file=patch_path,
                confidence=1.0,
                line_match=filename,
            )

        # Try to read patch content if it's a local file
        if patch_path.startswith('/nix/store/') and os.path.exists(patch_path):
            try:
                with open(patch_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                content_results = self._check_content_for_cves(content, patch_path)
                # Merge, preferring filename matches
                for cve_id, evidence in content_results.items():
                    if cve_id not in results:
                        results[cve_id] = evidence
            except (IOError, OSError):
                pass

        return results

    def _check_content_for_cves(self, content: str, source_file: str) -> Dict[str, PatchEvidence]:
        """Check text content for CVE references."""
        results: Dict[str, PatchEvidence] = {}

        # Common patterns indicating a CVE fix
        fix_patterns = [
            (r'(?:fix(?:es)?|patch(?:es)?|resolv(?:es)?|address(?:es)?)\s+(CVE-\d{4}-\d+)', 0.9),
            (r'(CVE-\d{4}-\d+)\s*:', 0.8),
            (r'security:\s*(CVE-\d{4}-\d+)', 0.85),
            (r'(CVE-\d{4}-\d+)', 0.6),  # Bare mention, lower confidence
        ]

        for pattern, confidence in fix_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                cve = match.group(1).upper()
                if cve not in results or results[cve].confidence < confidence:
                    results[cve] = PatchEvidence(
                        cve_id=cve,
                        source='content',
                        patch_file=source_file,
                        confidence=confidence,
                        line_match=match.group(0)[:100],
                    )

        return results

    def scan_nixpkgs_patches(self, nixpkgs_path: str, package: Optional[str] = None) -> Dict[str, List[PatchEvidence]]:
        """
        Scan nixpkgs source tree for CVE patches.

        Args:
            nixpkgs_path: Path to nixpkgs checkout
            package: Optional package name to limit search

        Returns:
            Dict mapping CVE ID to list of patch evidence
        """
        results: Dict[str, List[PatchEvidence]] = {}

        # Search paths
        search_paths = []
        if package:
            # Search in specific package directory
            for category in ['development', 'tools', 'applications', 'servers', 'misc']:
                pkg_path = Path(nixpkgs_path) / 'pkgs' / category / package
                if pkg_path.exists():
                    search_paths.append(pkg_path)
        else:
            # Search all pkgs
            search_paths.append(Path(nixpkgs_path) / 'pkgs')

        for search_path in search_paths:
            if not search_path.exists():
                continue

            for patch_file in search_path.rglob('*.patch'):
                evidence_dict = self._check_patch(str(patch_file))
                for cve_id, evidence in evidence_dict.items():
                    if cve_id not in results:
                        results[cve_id] = []
                    results[cve_id].append(evidence)

        return results


def demo():
    """Demonstrate patch detector."""
    detector = PatchDetector()

    print("=== Patch Detector Demo ===\n")

    # Test with sample patch filenames
    test_paths = [
        "/nix/store/abc123-CVE-2024-1234.patch",
        "/nix/store/def456-fix-security-issue.patch",
        "./patches/CVE-2023-45678-buffer-overflow.patch",
        "https://github.com/foo/bar/commit/abc123.patch",
    ]

    print("Testing patch filename detection:")
    for path in test_paths:
        results = detector._check_patch(path)
        if results:
            for cve, evidence in results.items():
                print(f"  {path}")
                print(f"    -> {cve} (confidence: {evidence.confidence})")
        else:
            print(f"  {path}: No CVEs found")
    print()

    # Test content detection
    sample_content = """
    This patch fixes CVE-2024-1234 which allows remote code execution.
    Also addresses CVE-2024-5678: buffer overflow in parser.

    The vulnerability was reported by security researcher.

    Fixes: CVE-2024-9012
    """

    print("Testing content detection:")
    results = detector._check_content_for_cves(sample_content, "sample.patch")
    for cve, evidence in results.items():
        print(f"  {cve}: confidence={evidence.confidence:.1f}, match='{evidence.line_match}'")
    print()

    # Test VEX status
    print("Testing VEX status determination:")
    patched = {"CVE-2024-1234": PatchEvidence("CVE-2024-1234", "filename", "test.patch")}
    for cve in ["CVE-2024-1234", "CVE-2024-9999"]:
        status = detector.get_vex_status(cve, patched)
        print(f"  {cve}: {status.status}")
        if status.justification:
            print(f"    Justification: {status.justification}")


if __name__ == "__main__":
    demo()
