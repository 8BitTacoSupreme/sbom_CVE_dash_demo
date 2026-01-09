"""
Nix Derivation Analyzer

Parses .drv files to extract package metadata and infer PURL/CPE identifiers.
Nix derivations contain the complete build recipe including source URLs and patches.
"""

import re
import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Known vendor mappings for CPE inference
# Maps package name patterns to (vendor, product) tuples
VENDOR_MAPPINGS = {
    'openssl': ('openssl', 'openssl'),
    'curl': ('haxx', 'curl'),
    'libcurl': ('haxx', 'curl'),
    'curlHTTP3': ('haxx', 'curl'),
    'curlhttp3': ('haxx', 'curl'),
    'zlib': ('zlib', 'zlib'),
    'sqlite': ('sqlite', 'sqlite'),
    'sqlite3': ('sqlite', 'sqlite'),
    'postgresql': ('postgresql', 'postgresql'),
    'postgres': ('postgresql', 'postgresql'),
    'libpq': ('postgresql', 'postgresql'),
    'ncurses': ('gnu', 'ncurses'),
    'ncurses6': ('gnu', 'ncurses'),
    'readline': ('gnu', 'readline'),
    'bash': ('gnu', 'bash'),
    'glibc': ('gnu', 'glibc'),
    'gcc': ('gnu', 'gcc'),
    'binutils': ('gnu', 'binutils'),
    'expat': ('libexpat', 'expat'),
    'libxml2': ('xmlsoft', 'libxml2'),
    'libxslt': ('xmlsoft', 'libxslt'),
    'openldap': ('openldap', 'openldap'),
    'nginx': ('nginx', 'nginx'),
    'apache': ('apache', 'http_server'),
    'httpd': ('apache', 'http_server'),
    'openssh': ('openbsd', 'openssh'),
    'libtiff': ('libtiff', 'libtiff'),
    'libpng': ('libpng', 'libpng'),
    'libjpeg': ('ijg', 'libjpeg'),
    'giflib': ('giflib', 'giflib'),
    'freetype': ('freetype', 'freetype'),
    'fontconfig': ('fontconfig', 'fontconfig'),
    'cairo': ('cairographics', 'cairo'),
    'glib': ('gnome', 'glib'),
    'gtk': ('gnome', 'gtk'),
    'perl': ('perl', 'perl'),
    'python': ('python', 'python'),
    'ruby': ('ruby-lang', 'ruby'),
    'node': ('nodejs', 'node.js'),
    'nodejs': ('nodejs', 'node.js'),
    'php': ('php', 'php'),
    'lua': ('lua', 'lua'),
    'go': ('golang', 'go'),
    'rust': ('rust-lang', 'rust'),
}

# URL patterns for inferring vendor from source URLs
URL_VENDOR_PATTERNS = [
    (r'github\.com/([^/]+)/', lambda m: (m.group(1).lower(), None)),
    (r'gitlab\.com/([^/]+)/', lambda m: (m.group(1).lower(), None)),
    (r'ftp\.gnu\.org/', lambda m: ('gnu', None)),
    (r'download\.gnome\.org/', lambda m: ('gnome', None)),
    (r'www\.openssl\.org/', lambda m: ('openssl', 'openssl')),
    (r'curl\.se/', lambda m: ('haxx', 'curl')),
    (r'www\.sqlite\.org/', lambda m: ('sqlite', 'sqlite')),
]


@dataclass
class PackageInfo:
    """Package metadata extracted from a derivation."""
    name: str
    version: str
    drv_path: Optional[str] = None
    src_url: Optional[str] = None
    src_hash: Optional[str] = None
    patches: List[str] = field(default_factory=list)
    purl: Optional[str] = None
    cpe: Optional[str] = None
    ecosystem: str = "nix"  # nix, npm, pypi, etc.

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'version': self.version,
            'drv_path': self.drv_path,
            'src_url': self.src_url,
            'purl': self.purl,
            'cpe': self.cpe,
            'patches': self.patches,
            'ecosystem': self.ecosystem,
        }


class DrvAnalyzer:
    """
    Analyzer for Nix derivation files.

    Extracts package metadata and infers PURL/CPE identifiers for
    vulnerability matching against OSV and NVD databases.
    """

    # Regex patterns for parsing derivation content
    NAME_VERSION_PATTERN = re.compile(r'^([a-zA-Z][a-zA-Z0-9_-]*?)-([0-9][0-9a-zA-Z._-]*)$')
    URL_PATTERN = re.compile(r'https?://[^\s"\']+')
    HASH_PATTERN = re.compile(r'sha256-[A-Za-z0-9+/=]+|sha256:[a-f0-9]{64}')

    def __init__(self, vendor_mappings: Optional[Dict] = None):
        """
        Initialize analyzer.

        Args:
            vendor_mappings: Custom package name to (vendor, product) mappings
        """
        self.vendor_mappings = {**VENDOR_MAPPINGS}
        if vendor_mappings:
            self.vendor_mappings.update(vendor_mappings)

    def analyze(self, drv_path: str) -> Optional[PackageInfo]:
        """
        Analyze a derivation file.

        Args:
            drv_path: Path to .drv file

        Returns:
            PackageInfo with extracted metadata, or None if parsing fails
        """
        try:
            with open(drv_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except (IOError, OSError) as e:
            logger.error(f"Failed to read {drv_path}: {e}")
            return None

        # Extract derivation name from path
        drv_name = Path(drv_path).stem
        if drv_name.startswith('nixpkgs-'):
            drv_name = drv_name[8:]  # Strip nixpkgs- prefix

        # Parse name and version
        name, version = self._parse_name_version(drv_name)
        if not name:
            logger.warning(f"Could not parse name/version from {drv_path}")
            return None

        # Extract source URL
        src_url = self._extract_src_url(content)

        # Extract patches
        patches = self._extract_patches(content)

        # Detect ecosystem from content hints
        ecosystem = self._detect_ecosystem(content, name)

        # Create base package info
        info = PackageInfo(
            name=name,
            version=version,
            drv_path=drv_path,
            src_url=src_url,
            patches=patches,
            ecosystem=ecosystem,
        )

        # Infer PURL
        info.purl = self.infer_purl(name, version, ecosystem)

        # Infer CPE
        info.cpe = self.infer_cpe(name, version, src_url)

        return info

    def analyze_store_path(self, store_path: str) -> Optional[PackageInfo]:
        """
        Analyze a package by its Nix store path.

        Args:
            store_path: Nix store path (e.g., /nix/store/xxx-package-1.2.3)

        Returns:
            PackageInfo with inferred metadata
        """
        # Extract name from store path
        path = Path(store_path)
        hash_name = path.name

        # Strip hash prefix (first 32 chars + dash)
        if len(hash_name) > 33 and hash_name[32] == '-':
            pkg_name = hash_name[33:]
        else:
            pkg_name = hash_name

        # Strip output suffix (-out, -dev, -lib, etc.)
        for suffix in ['-out', '-dev', '-lib', '-bin', '-doc', '-man', '-info']:
            if pkg_name.endswith(suffix):
                pkg_name = pkg_name[:-len(suffix)]
                break

        name, version = self._parse_name_version(pkg_name)
        if not name:
            # Fallback: use entire string as name
            name = pkg_name
            version = "0"

        info = PackageInfo(
            name=name,
            version=version,
            ecosystem="nix",
        )

        info.purl = self.infer_purl(name, version, "nix")
        info.cpe = self.infer_cpe(name, version, None)

        return info

    def _parse_name_version(self, drv_name: str) -> Tuple[Optional[str], str]:
        """Parse name and version from derivation name."""
        # Try standard name-version pattern
        match = self.NAME_VERSION_PATTERN.match(drv_name)
        if match:
            return match.group(1), match.group(2)

        # Try splitting on last dash followed by digit
        for i in range(len(drv_name) - 1, 0, -1):
            if drv_name[i - 1] == '-' and drv_name[i].isdigit():
                return drv_name[:i - 1], drv_name[i:]

        # Fallback: entire string is name, version is 0
        return drv_name, "0"

    def _extract_src_url(self, content: str) -> Optional[str]:
        """Extract source URL from derivation content."""
        urls = self.URL_PATTERN.findall(content)
        for url in urls:
            # Prefer tarball/archive URLs
            if any(ext in url for ext in ['.tar.', '.tgz', '.zip', '/archive/']):
                return url.rstrip('",\\')
        return urls[0].rstrip('",\\') if urls else None

    def _extract_patches(self, content: str) -> List[str]:
        """Extract patch file paths from derivation."""
        patches = []
        # Look for patch file references
        patch_pattern = re.compile(r'/nix/store/[^"\']+\.patch')
        patches.extend(patch_pattern.findall(content))

        # Also look for patches array
        patches_array = re.search(r'"patches"\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if patches_array:
            patches.extend(patch_pattern.findall(patches_array.group(1)))

        return list(set(patches))

    def _detect_ecosystem(self, content: str, name: str) -> str:
        """Detect package ecosystem from derivation content."""
        # Check for language-specific build systems
        if 'buildPythonPackage' in content or 'pythonPackages' in content:
            return 'pypi'
        if 'buildNpmPackage' in content or 'nodePackages' in content:
            return 'npm'
        if 'buildGoModule' in content or 'goPackages' in content:
            return 'go'
        if 'buildRustPackage' in content or 'cargoPackages' in content:
            return 'crates.io'
        if 'bundlerEnv' in content or 'rubyPackages' in content:
            return 'rubygems'

        return 'nix'

    def infer_purl(self, name: str, version: str, ecosystem: str = "nix") -> str:
        """
        Infer PURL from package metadata.

        Args:
            name: Package name
            version: Package version
            ecosystem: Package ecosystem (nix, npm, pypi, etc.)

        Returns:
            PURL string (e.g., "pkg:nix/openssl@3.0.0")
        """
        # Map ecosystem to PURL type
        purl_type = {
            'nix': 'nix',
            'npm': 'npm',
            'pypi': 'pypi',
            'go': 'golang',
            'crates.io': 'cargo',
            'rubygems': 'gem',
        }.get(ecosystem, 'nix')

        # Clean name (remove output suffixes common in nix)
        clean_name = name
        for suffix in ['-out', '-dev', '-lib', '-bin']:
            if clean_name.endswith(suffix):
                clean_name = clean_name[:-len(suffix)]
                break

        return f"pkg:{purl_type}/{clean_name}@{version}"

    def infer_cpe(self, name: str, version: str,
                  src_url: Optional[str] = None) -> Optional[str]:
        """
        Infer CPE from package metadata.

        Args:
            name: Package name
            version: Package version
            src_url: Optional source URL for vendor hints

        Returns:
            CPE 2.3 string or None if cannot infer
        """
        # Clean name
        clean_name = name.lower()
        for suffix in ['-out', '-dev', '-lib', '-bin', '6', '8']:
            if clean_name.endswith(suffix):
                clean_name = clean_name[:-len(suffix)]

        # Check known mappings
        for pattern, (vendor, product) in self.vendor_mappings.items():
            if clean_name.startswith(pattern.lower()):
                return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

        # Try URL-based inference
        if src_url:
            for pattern, extractor in URL_VENDOR_PATTERNS:
                match = re.search(pattern, src_url)
                if match:
                    vendor, product = extractor(match)
                    product = product or clean_name
                    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

        # Fallback: use name as both vendor and product
        return f"cpe:2.3:a:{clean_name}:{clean_name}:{version}:*:*:*:*:*:*:*"


def demo():
    """Demonstrate derivation analyzer."""
    analyzer = DrvAnalyzer()

    print("=== Derivation Analyzer Demo ===\n")

    # Test store path analysis
    test_paths = [
        "/nix/store/abc123-openssl-3.0.0-out",
        "/nix/store/def456-curl-8.5.0",
        "/nix/store/ghi789-ncurses6-6.5-dev",
        "/nix/store/jkl012-python3-3.11.0",
    ]

    for path in test_paths:
        info = analyzer.analyze_store_path(path)
        if info:
            print(f"Store path: {path}")
            print(f"  Name: {info.name}")
            print(f"  Version: {info.version}")
            print(f"  PURL: {info.purl}")
            print(f"  CPE: {info.cpe}")
            print()


if __name__ == "__main__":
    demo()
