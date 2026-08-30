import os
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import uvicorn

if __name__ == "__main__":
    backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
    sys.path.insert(0, backend_dir)
    
    print("=" * 60)
    print("🛡️ CYBERSHIELD AI — STARTING SERVER")
    print("Server running at: http://localhost:8000")
    print("Swagger docs at:   http://localhost:8000/docs")
    print("=" * 60)
    
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
