from typing import List, Dict, Any, Tuple

class RiskEngine:
    """
    Central Risk Engine.
    Aggregates multi-layer signals and calculates an application-defined risk score (0-100)
    and risk classification band.
    """

    @staticmethod
    def calculate_risk(
        indicators: List[Dict[str, Any]],
        stored_intel: Dict[str, Any] = None
    ) -> Tuple[int, str, str]:
        """
        Combines indicator weights and stored intelligence signal.
        Returns: (risk_score, risk_level, threat_category)
        """
        total_score = 0
        category_counts: Dict[str, int] = {}

        # 1. Sum indicator weights
        for ind in indicators:
            weight = ind.get("weight", 10)
            total_score += weight

        # 2. Factor in Stored Intelligence signal if present
        if stored_intel:
            prior_score = stored_intel.get("risk_score", 0)
            scan_count = stored_intel.get("scan_count", 1)
            # Add up to +25 score depending on prior intelligence severity & frequency
            intel_weight = min(25, int(prior_score * 0.25) + min(10, scan_count * 2))
            total_score += intel_weight
            
            # Inject stored intelligence indicator for transparent evidence
            indicators.append({
                "code": "CYBERSHIELD_STORED_MEMORY_MATCH",
                "label": "CyberShield Intelligence Memory Match",
                "severity": "medium" if prior_score < 60 else "high",
                "description": f"Content signature was previously recorded in persistent threat memory ({scan_count} prior observation(s)).",
                "weight": intel_weight
            })

        # Cap score between 0 and 100
        risk_score = min(100, max(0, total_score))

        # 3. Determine Risk Band
        if risk_score <= 25:
            risk_level = "SAFE"
        elif risk_score <= 65:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "SCAM"

        # 4. Determine Threat Category
        threat_category = RiskEngine._determine_threat_category(indicators, risk_score)

        return risk_score, risk_level, threat_category

    @staticmethod
    def _determine_threat_category(indicators: List[Dict[str, Any]], score: int) -> str:
        if score <= 25:
            return "Safe Digital Content"
            
        codes = [ind.get("code", "") for ind in indicators]

        if "MSG_CREDENTIAL_HARVESTING" in codes:
            return "OTP & Banking Credential Theft"
        if "MSG_FINANCIAL_COERCION" in codes and ("MSG_ORGANIZATION_IMPERSONATION" in codes or "URL_PHISHING_KEYWORDS" in codes):
            return "UPI / Bank Impersonation Fraud"
        if "MSG_FAKE_JOB_SCHEME" in codes:
            return "Work-From-Home Task Scam"
        if "URL_PHISHING_KEYWORDS" in codes or "URL_IP_HOST" in codes or "THREAT_INTEL_VIRUSTOTAL_FLAGGED" in codes:
            return "Phishing Website / Credential Harvest"
        if "MSG_URGENCY_PRESSURE" in codes:
            return "Social Engineering Panic Scam"
        if "URL_NO_HTTPS" in codes or "URL_SUSPICIOUS_TLD" in codes:
            return "Low Security Digital Destination"

        return "Suspicious Digital Content"

risk_engine = RiskEngine()
