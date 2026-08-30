from fastapi import Header, HTTPException, status
from app.core.config import settings

def verify_admin_key(x_admin_key: str = Header(None, alias="X-Admin-Key")):
    """
    Verifies that the incoming request contains a valid X-Admin-Key header
    matching the server's configured ADMIN_SECRET_KEY.
    """
    if not x_admin_key or x_admin_key != settings.ADMIN_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized Admin Access: Invalid or missing X-Admin-Key header."
        )
    return True
