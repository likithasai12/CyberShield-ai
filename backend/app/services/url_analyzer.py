import re
from urllib.parse import urlparse
from typing import List, Dict, Any

SUSPICIOUS_TLDS = {
    "xyz", "top", "online", "site", "club", "buzz", "tech", "vip", "work", "icu",
    "gq", "cf", "ml", "ga", "tk", "support", "verify", "link", "click", "download",
    "info", "live", "rest", "fit", "monster", "fun", "space", "website"
}

HIGH_RISK_KEYWORDS = [
    "login", "verify", "verification", "update", "account", "secure", "security",
    "banking", "netbanking", "kyc", "upi", "paytm", "gpay", "phonepe", "sbi", "hdfc",
    "icici", "axis", "kotak", "claim", "reward", "lottery", "prize", "refund",
    "customer-care", "helpline", "support-desk", "free-gift", "telegram", "whatsapp",
    "work-from-home", "job-offer", "speedpost", "courier-update"
]

class URLAnalyzer:
    """
    Multi-layer structural and heuristic URL analyzer.
    Extracts risk indicators without navigating to or executing the target URL.
    Combines independent signals to avoid false positives on legitimate domains.
    """
    
    @staticmethod
    def normalize_url(url_str: str) -> str:
        url_str = url_str.strip()
        if not url_str.startswith(("http://", "https://")):
            url_str = "http://" + url_str
        return url_str

    def analyze(self, raw_url: str) -> List[Dict[str, Any]]:
        indicators = []
        normalized_url = self.normalize_url(raw_url)
        
        try:
            parsed = urlparse(normalized_url)
            hostname = parsed.hostname or ""
            path = parsed.path or ""
            query = parsed.query or ""
            full_target = (hostname + path + query).lower()
        except Exception:
            indicators.append({
                "code": "URL_MALFORMED",
                "label": "Malformed URL Structure",
                "severity": "high",
                "description": "The submitted URL structure is invalid or deliberately obfuscated.",
                "weight": 25
            })
            return indicators

        domain_parts = hostname.split(".")
        tld = domain_parts[-1].lower() if len(domain_parts) > 1 else ""
        has_suspicious_tld = tld in SUSPICIOUS_TLDS
        is_ip_host = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))

        # 1. Check IP address hostname
        if is_ip_host:
            indicators.append({
                "code": "URL_IP_HOST",
                "label": "Raw IP Address Hostname",
                "severity": "high",
                "description": "URL uses a raw IP address instead of a domain name to mask server identity.",
                "weight": 25
            })

        # 2. Check HTTP vs HTTPS
        if parsed.scheme == "http":
            indicators.append({
                "code": "URL_NO_HTTPS",
                "label": "Unencrypted HTTP Protocol",
                "severity": "medium",
                "description": "Connection lacks SSL/TLS encryption.",
                "weight": 10
            })

        # 3. Check Suspicious TLD
        if has_suspicious_tld:
            indicators.append({
                "code": "URL_SUSPICIOUS_TLD",
                "label": f"High-Risk Top-Level Domain (.{tld})",
                "severity": "medium",
                "description": f"Domain uses '.{tld}', a TLD frequently associated with low-cost disposable phishing sites.",
                "weight": 18
            })

        # 4. Check Subdomain depth
        if len(domain_parts) > 3:
            indicators.append({
                "code": "URL_DEEP_SUBDOMAIN",
                "label": "Excessive Subdomains",
                "severity": "medium",
                "description": f"Domain contains {len(domain_parts)-2} subdomain levels, often used to mimic brand hostnames.",
                "weight": 15
            })

        # 5. Check URL Obfuscation (@ symbol, excessive hyphens)
        if "@" in raw_url:
            indicators.append({
                "code": "URL_AT_OBFUSCATION",
                "label": "URL Redirect Obfuscation (@ Symbol)",
                "severity": "high",
                "description": "Contains an '@' symbol, which ignores preceding text and redirects users to a secondary destination.",
                "weight": 25
            })
            
        if hostname.count("-") >= 3:
            indicators.append({
                "code": "URL_HYPHEN_OBFUSCATION",
                "label": "Excessive Hyphen Obfuscation",
                "severity": "medium",
                "description": "Hostname relies heavily on hyphens to imitate genuine organizational domain names.",
                "weight": 15
            })

        # 6. Check URL Length
        if len(raw_url) > 120:
            indicators.append({
                "code": "URL_EXCESS_LENGTH",
                "label": "Unusually Long URL",
                "severity": "low",
                "description": f"URL length ({len(raw_url)} characters) is exceptionally long.",
                "weight": 5
            })

        # 7. Check Sensitive / Phishing Keywords
        # Only assign higher weight if combined with structural risk factors (IP host, suspicious TLD, hyphens, deep subdomains)
        found_keywords = [kw for kw in HIGH_RISK_KEYWORDS if kw in full_target]
        if found_keywords:
            matched_str = ", ".join(found_keywords[:3])
            has_structural_risk = (has_suspicious_tld or is_ip_host or len(domain_parts) > 3 or hostname.count("-") >= 3 or "@" in raw_url or parsed.scheme == "http")
            kw_weight = 20 if has_structural_risk else 5
            indicators.append({
                "code": "URL_PHISHING_KEYWORDS",
                "label": "Sensitive Security & Brand Keywords",
                "severity": "medium" if has_structural_risk else "low",
                "description": f"Target contains security/brand keywords ({matched_str})." + (" High risk when combined with suspicious domain structure." if has_structural_risk else " Normal in standard transactional links."),
                "weight": kw_weight
            })

        return indicators

url_analyzer = URLAnalyzer()

