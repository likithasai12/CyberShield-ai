import httpx
from typing import List, Dict, Any
from app.core.config import settings

class ThreatIntelService:
    """
    Service layer for external Threat Intelligence APIs (VirusTotal, Google Safe Browsing).
    Skipped gracefully if API keys are not provided in environment settings.
    """

    async def check_url_threats(self, target_url: str) -> List[Dict[str, Any]]:
        indicators = []
        
        # 1. VirusTotal API check
        if settings.VIRUSTOTAL_API_KEY:
            try:
                vt_indicator = await self._check_virustotal(target_url)
                if vt_indicator:
                    indicators.append(vt_indicator)
            except Exception:
                pass

        # 2. Google Safe Browsing API check
        if settings.GOOGLE_SAFE_BROWSING_API_KEY:
            try:
                gsb_indicator = await self._check_safe_browsing(target_url)
                if gsb_indicator:
                    indicators.append(gsb_indicator)
            except Exception:
                pass

        return indicators

    async def _check_virustotal(self, url: str) -> Dict[str, Any]:
        endpoint = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(endpoint, headers=headers, data={"url": url})
            if resp.status_code == 200:
                return {
                    "code": "THREAT_INTEL_VIRUSTOTAL_FLAGGED",
                    "label": "VirusTotal Intelligence Flag",
                    "severity": "critical",
                    "description": "URL was flagged as malicious or phishing by VirusTotal security vendors.",
                    "weight": 35
                }
        return None

    async def _check_safe_browsing(self, url: str) -> Dict[str, Any]:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
        body = {
            "client": {"clientId": "cybershield-ai", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(endpoint, json=body)
            if resp.status_code == 200 and resp.json().get("matches"):
                return {
                    "code": "THREAT_INTEL_SAFE_BROWSING_MATCH",
                    "label": "Google Safe Browsing Match",
                    "severity": "critical",
                    "description": "URL is listed in Google Safe Browsing database for phishing or malware distribution.",
                    "weight": 40
                }
        return None

threat_intel_service = ThreatIntelService()
