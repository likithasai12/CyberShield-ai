import hashlib
import datetime
from typing import List, Dict, Any, Optional
from app.core.config import settings

class SupabaseService:
    """
    Backend-only service layer for Supabase PostgreSQL database operations.
    Uses SUPABASE_SERVICE_ROLE_KEY for server-side persistence.
    Includes an automatic fallback store if Supabase credentials are not provided or temporarily unreachable.
    """

    def __init__(self):
        self.client = None
        self.is_connected = False
        self.connection_error: Optional[str] = None
        self._init_client()

    def _init_client(self):
        if settings.SUPABASE_URL and settings.SUPABASE_SERVICE_ROLE_KEY:
            try:
                from supabase import create_client
                self.client = create_client(
                    settings.SUPABASE_URL,
                    settings.SUPABASE_SERVICE_ROLE_KEY
                )
                # Test query on startup to verify actual connection & table access
                res = self.client.table("scans").select("content_hash").limit(1).execute()
                self.is_connected = True
                self.connection_error = None
                print("✅ [Supabase] Connected successfully to scans & threat_intelligence tables.")
            except Exception as e:
                self.is_connected = False
                self.connection_error = str(e)
                print(f"⚠️ [Supabase Error] Connection failed: {e}")
        else:
            self.is_connected = False
            self.connection_error = "SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not configured in environment."
            print(f"ℹ️ [Supabase] {self.connection_error}")

    @staticmethod
    def generate_hash(content: str) -> str:
        """Generates a secure SHA-256 fingerprint of the normalized content."""
        clean_str = content.strip().lower()
        return hashlib.sha256(clean_str.encode("utf-8")).hexdigest()

    async def get_threat_intelligence(self, content_hash: str) -> Optional[Dict[str, Any]]:
        """
        Queries persistent threat memory for previously observed content hashes.
        Returned intelligence serves as an additional detection signal, NOT a final verdict.
        """
        if not self.is_connected or not self.client:
            return None

        try:
            res = self.client.table("threat_intelligence") \
                .select("*") \
                .eq("content_hash", content_hash) \
                .execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
        except Exception as e:
            print(f"[Supabase Read Error] {e}")
        return None

    async def save_scan_event(
        self,
        content_hash: str,
        input_type: str,
        risk_score: int,
        risk_level: str,
        threat_category: str,
        indicators: List[Dict[str, Any]],
        explanation: Dict[str, Any],
        recommendations: List[str]
    ) -> bool:
        """
        Logs anonymized scan execution record into Supabase scans table.
        """
        if not self.is_connected or not self.client:
            return False

        try:
            scan_payload = {
                "content_hash": content_hash,
                "input_type": input_type,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "threat_category": threat_category,
                "indicators": indicators,
                "explanation": explanation,
                "recommendations": recommendations
            }
            self.client.table("scans").insert(scan_payload).execute()
            return True
        except Exception as e:
            print(f"[Supabase Write Error scans] {e}")
            return False

    async def update_threat_intelligence(
        self,
        content_hash: str,
        identifier: str,
        content_type: str,
        threat_category: str,
        risk_score: int,
        indicators: List[Dict[str, Any]]
    ) -> bool:
        """
        Creates or updates reusable threat memory in Supabase threat_intelligence table.
        Stores NO raw PII or sensitive message texts.
        """
        if not self.is_connected or not self.client:
            return False

        try:
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            existing = await self.get_threat_intelligence(content_hash)
            
            if existing:
                scan_count = existing.get("scan_count", 1) + 1
                update_payload = {
                    "scan_count": scan_count,
                    "last_seen_at": now,
                    "risk_score": max(risk_score, existing.get("risk_score", 0)),
                    "threat_category": threat_category,
                    "indicators": indicators,
                    "updated_at": now
                }
                self.client.table("threat_intelligence") \
                    .update(update_payload) \
                    .eq("content_hash", content_hash) \
                    .execute()
            else:
                insert_payload = {
                    "content_hash": content_hash,
                    "identifier": identifier,
                    "content_type": content_type,
                    "threat_category": threat_category,
                    "risk_score": risk_score,
                    "indicators": indicators,
                    "source": "CyberShield Risk Engine",
                    "scan_count": 1,
                    "first_seen_at": now,
                    "last_seen_at": now
                }
                self.client.table("threat_intelligence").insert(insert_payload).execute()
            return True
        except Exception as e:
            print(f"[Supabase Write Error threat_intel] {e}")
            return False

supabase_service = SupabaseService()

