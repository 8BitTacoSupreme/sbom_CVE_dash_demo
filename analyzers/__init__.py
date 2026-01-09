"""
SCA v2 Analyzers

Analyzers for extracting vulnerability-relevant metadata from Nix derivations:
- DrvAnalyzer: Extract package metadata, infer PURL/CPE
- PatchDetector: Detect CVE patches in derivations for auto-VEX
- VersionMatcher: Check package versions against affected ranges
"""

from .drv_analyzer import DrvAnalyzer, PackageInfo
from .patch_detector import PatchDetector, PatchEvidence
from .version_matcher import VersionMatcher, VersionRange

__all__ = ['DrvAnalyzer', 'PackageInfo', 'PatchDetector', 'PatchEvidence', 'VersionMatcher', 'VersionRange']
