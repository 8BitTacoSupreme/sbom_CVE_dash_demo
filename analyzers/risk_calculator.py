"""
Risk Calculator for Vulnerability Triage

Calculates composite risk scores and assigns alert tiers for
intelligent prioritization of vulnerability remediation.

Tier Definitions:
  - Tier 1 (Break Glass): KEV + Critical → Block build / PagerDuty
  - Tier 2 (Immediate): Risk > 80 OR EPSS > 0.4 → Auto-ticket
  - Tier 3 (Standard): Everything else → Weekly review dashboard
"""

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class RiskAssessment:
    """Result of risk calculation for a vulnerability."""
    risk_score: float       # 0-100 composite score
    tier: int               # 1, 2, or 3
    tier_name: str          # "break_glass", "immediate", "standard"
    trigger_reason: str     # Why this tier was assigned


class RiskCalculator:
    """
    Calculate composite risk score and assign alert tier.

    Risk Score Formula:
      - CVSS normalized (0-10 → 0-100): 25%
      - EPSS (0-1 → 0-100): 35%
      - KEV bonus: 30% if actively exploited
      - Scorecard penalty (0-10 → 0-100 inverted): 10% (low maintenance = higher risk)

    Tier Assignment:
      - Tier 1: KEV=True AND severity='critical'
      - Tier 2: risk_score > 80 OR epss_score > 0.4
      - Tier 3: Everything else
    """

    # Weight configuration (sum to 1.0)
    CVSS_WEIGHT = 0.25
    EPSS_WEIGHT = 0.35
    KEV_WEIGHT = 0.30
    SCORECARD_WEIGHT = 0.10

    # Tier thresholds
    TIER2_RISK_THRESHOLD = 80
    TIER2_EPSS_THRESHOLD = 0.4

    # KEV bonus value (when actively exploited)
    KEV_BONUS = 90

    def calculate(
        self,
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        cisa_kev: bool = False,
        severity: Optional[str] = None,
        scorecard_score: Optional[float] = None,
    ) -> RiskAssessment:
        """
        Calculate risk score and assign tier.

        Args:
            cvss_score: CVSS score (0-10 scale)
            epss_score: EPSS probability (0-1 scale)
            cisa_kev: Whether CVE is on CISA KEV list
            severity: Severity string ("critical", "high", etc.)
            scorecard_score: OpenSSF Scorecard aggregate score (0-10, higher = better maintained)

        Returns:
            RiskAssessment with score, tier, and reasoning
        """
        # Normalize scores to 0-100 scale
        cvss_normalized = (cvss_score or 0) * 10  # 0-10 → 0-100
        epss_normalized = (epss_score or 0) * 100  # 0-1 → 0-100
        kev_bonus = self.KEV_BONUS if cisa_kev else 0

        # Scorecard: invert so low maintenance = high risk
        # Score of 2/10 → penalty of 80, score of 9/10 → penalty of 10
        # If no scorecard data, use neutral value (50) to avoid penalizing unknowns
        if scorecard_score is not None:
            scorecard_penalty = (10 - scorecard_score) * 10  # 0-100 inverted
        else:
            scorecard_penalty = 50  # Neutral when unknown

        # Calculate composite risk score
        risk_score = (
            cvss_normalized * self.CVSS_WEIGHT +
            epss_normalized * self.EPSS_WEIGHT +
            kev_bonus * self.KEV_WEIGHT +
            scorecard_penalty * self.SCORECARD_WEIGHT
        )

        # Cap at 100
        risk_score = min(risk_score, 100)

        # Normalize severity for comparison
        severity_lower = (severity or "").lower()

        # Tier 1: Break Glass - KEV + Critical
        if cisa_kev and severity_lower == "critical":
            return RiskAssessment(
                risk_score=round(risk_score, 2),
                tier=1,
                tier_name="break_glass",
                trigger_reason="KEV + Critical"
            )

        # Tier 2: Immediate - High risk or high EPSS
        tier2_reasons = []
        if risk_score > self.TIER2_RISK_THRESHOLD:
            tier2_reasons.append(f"Risk={risk_score:.0f}")
        if (epss_score or 0) > self.TIER2_EPSS_THRESHOLD:
            tier2_reasons.append(f"EPSS={epss_score:.1%}")

        if tier2_reasons:
            return RiskAssessment(
                risk_score=round(risk_score, 2),
                tier=2,
                tier_name="immediate",
                trigger_reason=" + ".join(tier2_reasons)
            )

        # Tier 3: Standard review
        return RiskAssessment(
            risk_score=round(risk_score, 2),
            tier=3,
            tier_name="standard",
            trigger_reason="Standard review"
        )

    def calculate_batch(
        self,
        vulnerabilities: list
    ) -> list:
        """
        Calculate risk for multiple vulnerabilities.

        Args:
            vulnerabilities: List of dicts with cvss_score, epss_score, cisa_kev, severity

        Returns:
            List of RiskAssessment objects
        """
        return [
            self.calculate(
                cvss_score=v.get("cvss_score"),
                epss_score=v.get("epss_score"),
                cisa_kev=v.get("cisa_kev", False),
                severity=v.get("severity")
            )
            for v in vulnerabilities
        ]


def demo():
    """Demonstrate risk calculation with sample vulnerabilities."""
    calc = RiskCalculator()

    print("=== Risk Calculator Demo ===\n")

    test_cases = [
        {
            "name": "Log4Shell (KEV + Critical)",
            "cvss_score": 10.0,
            "epss_score": 0.975,
            "cisa_kev": True,
            "severity": "critical"
        },
        {
            "name": "High EPSS (>0.4)",
            "cvss_score": 7.5,
            "epss_score": 0.67,
            "cisa_kev": False,
            "severity": "high"
        },
        {
            "name": "High Risk Score (>80)",
            "cvss_score": 9.8,
            "epss_score": 0.35,
            "cisa_kev": True,
            "severity": "high"
        },
        {
            "name": "Standard Critical (low EPSS)",
            "cvss_score": 9.0,
            "epss_score": 0.05,
            "cisa_kev": False,
            "severity": "critical"
        },
        {
            "name": "Medium severity",
            "cvss_score": 5.5,
            "epss_score": 0.02,
            "cisa_kev": False,
            "severity": "medium"
        },
    ]

    for case in test_cases:
        result = calc.calculate(
            cvss_score=case["cvss_score"],
            epss_score=case["epss_score"],
            cisa_kev=case["cisa_kev"],
            severity=case["severity"]
        )

        tier_emoji = {1: "🚨", 2: "⚠️ ", 3: "📋"}[result.tier]
        print(f"{tier_emoji} {case['name']}")
        print(f"   CVSS={case['cvss_score']}, EPSS={case['epss_score']:.1%}, KEV={case['cisa_kev']}")
        print(f"   → Tier {result.tier} ({result.tier_name}): Risk={result.risk_score:.0f}")
        print(f"   → Reason: {result.trigger_reason}")
        print()


if __name__ == "__main__":
    demo()
