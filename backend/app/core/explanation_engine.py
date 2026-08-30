from typing import List, Dict, Any, Tuple

class ExplanationEngine:
    """
    Translates technical risk signals into human-understandable evidence, explanations,
    and actionable recommendations. Follows the principle: EVIDENCE -> EXPLANATION -> ACTION.
    """

    @staticmethod
    def generate_explanation(
        risk_score: int,
        risk_level: str,
        threat_category: str,
        indicators: List[Dict[str, Any]],
        input_type: str
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Returns: (explanation_dict, recommendations_list)
        """
        if risk_level == "SAFE":
            summary = f"No known risk indicators detected in this {input_type}."
            why_risky = "The analyzed content displays normal patterns without recognized phishing or social engineering threat markers."
            possible_impact = ["Low risk of fraud or compromise based on current automated checks."]
            recommendations = [
                "Always verify sender identity before entering personal details.",
                "Ensure your browser and security software remain up to date."
            ]
            evidence = ["Analyzed structural patterns yielded zero high-risk threat flags."]
        else:
            indicator_labels = [ind["label"] for ind in indicators if "label" in ind]
            matched_text = ", ".join(indicator_labels[:3])
            
            summary = f"This {input_type} displays {risk_level} security risk ({risk_score}/100) consistent with {threat_category}."
            why_risky = (
                f"CyberShield detected key suspicious indicators ({matched_text}). "
                f"Scammers frequently use these exact techniques to trick users into revealing confidential information or transferring money."
            )
            
            # Impact mapping based on severity
            possible_impact = []
            if any("CREDENTIAL" in ind.get("code", "") for ind in indicators):
                possible_impact.append("Unauthorized account access and credential theft")
                possible_impact.append("Loss of funds via fraudulent OTP or PIN verification")
            if any("FINANCIAL" in ind.get("code", "") for ind in indicators):
                possible_impact.append("Direct monetary loss through fraudulent payment portals")
            if any("URL" in ind.get("code", "") for ind in indicators):
                possible_impact.append("Exposure to spoofed phishing web interfaces")
                possible_impact.append("Potential malware or spyware payload delivery")
            if not possible_impact:
                possible_impact.append("Potential social engineering deception or identity harvesting")

            # Recommendations mapping
            recommendations = []
            if "qr" in input_type.lower():
                recommendations.append("⛔ Do NOT enter your UPI PIN or transfer money to 'receive' payments. UPI PIN is required ONLY to send money.")
                recommendations.append("🔍 Verify the destination URL displayed on your screen before interacting with any opened page.")
            else:
                recommendations.append("🚫 Do NOT click any links contained in this message or email.")
                recommendations.append("🔒 Never share OTPs, UPI PINs, passwords, or bank details over SMS, phone, or unverified websites.")
                recommendations.append("🏛️ Verify account status directly by visiting the organization's official website or official mobile app.")
                recommendations.append("🚨 Report this suspicious message to CyberShield and official cybercrime channels (e.g., 1930 Helpline in India).")

            evidence = [
                f"{ind.get('label')}: {ind.get('description')}" for ind in indicators
            ]

        explanation_dict = {
            "summary": summary,
            "why_risky": why_risky,
            "possible_impact": possible_impact,
            "evidence_breakdown": evidence
        }

        return explanation_dict, recommendations

explanation_engine = ExplanationEngine()
