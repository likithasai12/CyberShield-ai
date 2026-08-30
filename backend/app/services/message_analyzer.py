import re
from typing import List, Dict, Any, Tuple
from app.services.url_analyzer import url_analyzer

COERCIVE_PANIC_PATTERNS = [
    r"\b(account (will be )?blocked (today|within \d+ hours?)|sim (deactivated|blocked) today|electricity (cutoff|disconnected) today|legal action will be taken|police complaint registered)\b",
    r"\b(immediate (deactivation|suspension|cutoff|penalty)|final notice before blocking)\b"
]

PREDATORY_FINANCIAL_PATTERNS = [
    r"\b(won \d+ (lakh|crore|dollars?|rs)|lottery winner|unsolicited cash reward|claim \d+ bonus|deposit money to withdraw|pay processing fee to claim|task earnings deposit)\b"
]

CREDENTIAL_PATTERNS = [
    r"\b(otp|one time password|upi pin|pin|cvv|banking password|credentials|card number)\b",
    r"\b(share otp|enter pin|verify password|send otp|provide details|share pin)\b"
]

KNOWN_BRAND_KEYWORDS = [
    "sbi", "hdfc", "icici", "axis", "kotak", "paytm", "gpay", "phonepe", "yono",
    "electricity board", "tneb", "bescom", "mseb", "bses", "speedpost", "courier",
    "fedex", "delhivery", "customs", "income tax", "kyc", "sim block", "jio", "airtel", "vi", "amazon", "flipkart"
]

FAKE_JOB_PATTERNS = [
    r"\b(work from home|part time job|earn \d+ (per|a) day|google review|youtube like|telegram task job|daily payout deposit)\b"
]

class MessageAnalyzer:
    """
    NLP and Heuristic analyzer for SMS, Chat, and Email contents.
    Identifies social engineering markers and parses embedded URLs.
    Combines multiple independent signals before classifying content as suspicious.
    """

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        url_pattern = r"(https?://[^\s>\"']+|www\.[^\s>\"']+)"
        found = re.findall(url_pattern, text)
        return list(set(found))

    @staticmethod
    def mask_sensitive_data(text: str) -> str:
        """
        Scrubs potential raw OTPs, PINs, and credit card numbers prior to database storage.
        """
        text = re.sub(r"(otp\s*(?:is|:)?\s*)\d{4,8}", r"\1******", text, flags=re.IGNORECASE)
        text = re.sub(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "****-****-****-****", text)
        return text

    def analyze(self, text: str, subject: str = "") -> Tuple[List[Dict[str, Any]], List[str]]:
        indicators = []
        combined_text = f"{subject} {text}".lower()
        extracted_urls = self.extract_urls(text + " " + subject)

        # 1. Severe Panic & Coercion Threat
        for pattern in COERCIVE_PANIC_PATTERNS:
            if re.search(pattern, combined_text):
                indicators.append({
                    "code": "MSG_URGENCY_PRESSURE",
                    "label": "Coercive Threats & Panic Urgency",
                    "severity": "high",
                    "description": "Message threatens immediate account/service deactivation to bypass logical evaluation.",
                    "weight": 16
                })
                break

        # 2. Predatory Financial Claim / Fee Demand
        for pattern in PREDATORY_FINANCIAL_PATTERNS:
            if re.search(pattern, combined_text):
                indicators.append({
                    "code": "MSG_FINANCIAL_COERCION",
                    "label": "Predatory Financial Gain or Advance-Fee Demand",
                    "severity": "high",
                    "description": "Promises unsolicited lottery/prize payouts or demands prepaid fees.",
                    "weight": 18
                })
                break

        # 3. Credential & OTP Request (Always Critical Signal)
        for pattern in CREDENTIAL_PATTERNS:
            if re.search(pattern, combined_text):
                indicators.append({
                    "code": "MSG_CREDENTIAL_HARVESTING",
                    "label": "Sensitive Credential / OTP Request",
                    "severity": "critical",
                    "description": "Requests secret authentication tokens (OTP, UPI PIN, Passwords, CVV) which legitimate organizations never ask via chat/SMS.",
                    "weight": 25
                })
                break

        # 4. Fake Job / Task Scam
        for pattern in FAKE_JOB_PATTERNS:
            if re.search(pattern, combined_text):
                indicators.append({
                    "code": "MSG_FAKE_JOB_SCHEME",
                    "label": "Task Scam / Advance-Fee Job Fraud",
                    "severity": "high",
                    "description": "Promotes high daily payouts for simple online tasks (Telegram reviews, YouTube likes), a common advance-fee scam format.",
                    "weight": 20
                })
                break

        # 5. Embedded URL Extraction & Cross-Analysis
        url_has_suspicious_features = False
        if extracted_urls:
            for u in extracted_urls:
                url_indicators = url_analyzer.analyze(u)
                for ind in url_indicators:
                    if not any(existing["code"] == ind["code"] for existing in indicators):
                        indicators.append(ind)
                    if ind.get("weight", 0) >= 12:
                        url_has_suspicious_features = True

            if url_has_suspicious_features:
                indicators.append({
                    "code": "MSG_EMBEDDED_LINK",
                    "label": "Suspicious Embedded Hyperlink",
                    "severity": "medium",
                    "description": f"Contains embedded link(s) with suspicious structural characteristics.",
                    "weight": 10
                })

        # 6. Contextual Brand Impersonation Signal
        # Only flag brand impersonation if combined with a suspicious URL or a credential/panic request
        mentioned_brands = [b for b in KNOWN_BRAND_KEYWORDS if re.search(r"\b" + re.escape(b) + r"\b", combined_text)]
        if mentioned_brands:
            has_panic_or_credential = any(ind["code"] in ["MSG_URGENCY_PRESSURE", "MSG_CREDENTIAL_HARVESTING", "MSG_FINANCIAL_COERCION"] for ind in indicators)
            if url_has_suspicious_features or has_panic_or_credential:
                matched_brand_str = ", ".join(mentioned_brands[:2]).upper()
                indicators.append({
                    "code": "MSG_ORGANIZATION_IMPERSONATION",
                    "label": "Deceptive Brand Reference",
                    "severity": "medium",
                    "description": f"References organization ({matched_brand_str}) alongside suspicious links or urgent credential requests.",
                    "weight": 14
                })

        return indicators, extracted_urls

message_analyzer = MessageAnalyzer()

