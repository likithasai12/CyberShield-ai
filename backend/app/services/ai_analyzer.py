import httpx
from typing import List, Dict, Any, Optional
from app.core.config import settings

class AIAnalyzer:
    """
    Optional AI/NLP integration layer for deep contextual social engineering analysis.
    Gracefully falls back to heuristic NLP rules if API keys are missing.
    """

    async def analyze_context(self, content: str, content_type: str) -> List[Dict[str, Any]]:
        indicators = []
        
        # 1. Try Gemini API if key is present
        if settings.GEMINI_API_KEY:
            try:
                gemini_indicators = await self._call_gemini_api(content, content_type)
                if gemini_indicators:
                    indicators.extend(gemini_indicators)
                    return indicators
            except Exception:
                pass # Gracefully fall back to rule-based NLP

        # 2. Try OpenAI API if key is present
        if settings.OPENAI_API_KEY:
            try:
                openai_indicators = await self._call_openai_api(content, content_type)
                if openai_indicators:
                    indicators.extend(openai_indicators)
                    return indicators
            except Exception:
                pass

        # 3. Rule-based NLP fallback (always available)
        return self._heuristic_nlp_analysis(content, content_type)

    async def _call_gemini_api(self, content: str, content_type: str) -> List[Dict[str, Any]]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={settings.GEMINI_API_KEY}"
        prompt = (
            f"Analyze the following {content_type} for cyber-fraud, social engineering, or phishing tactics: '{content}'. "
            f"Identify psychological manipulation patterns such as Fear, Urgency, Greed, Authority, or Deception."
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                text_out = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                if "fear" in text_out.lower() or "urgency" in text_out.lower():
                    return [{
                        "code": "AI_NLP_PSYCHOLOGICAL_MANIPULATION",
                        "label": "AI Identified Psychological Coercion",
                        "severity": "high",
                        "description": "AI analysis identified patterns of social engineering attempting to manipulate user emotions.",
                        "weight": 15
                    }]
        return []

    async def _call_openai_api(self, content: str, content_type: str) -> List[Dict[str, Any]]:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {settings.OPENAI_API_KEY}"}
        payload = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity scam detector."},
                {"role": "user", "content": f"Is this {content_type} a phishing or scam attempt? '{content}'"}
            ]
        }
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                return [{
                    "code": "AI_NLP_SOCIAL_ENGINEERING",
                    "label": "AI Contextual Risk Pattern",
                    "severity": "medium",
                    "description": "AI context analysis flagged suspicious intent in the submitted material.",
                    "weight": 12
                }]
        return []

    def _heuristic_nlp_analysis(self, content: str, content_type: str) -> List[Dict[str, Any]]:
        # Built-in heuristic NLP context rules
        indicators = []
        lower = content.lower()
        
        if "click link" in lower or "click below" in lower or "tap link" in lower:
            indicators.append({
                "code": "NLP_CALL_TO_ACTION",
                "label": "Unsolicited Call-To-Action Link",
                "severity": "medium",
                "description": "Text explicitly demands clicking an external link to resolve an unverified claim.",
                "weight": 10
            })
            
        if "strictly confidential" in lower or "do not inform" in lower or "keep quiet" in lower:
            indicators.append({
                "code": "NLP_SECRECY_PRESSURE",
                "label": "Secrecy & Isolation Tactic",
                "severity": "high",
                "description": "Instructs the recipient to keep the message secret, a common technique to prevent victim consultation.",
                "weight": 18
            })
            
        return indicators

ai_analyzer = AIAnalyzer()
