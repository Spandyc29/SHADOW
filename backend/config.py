import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

FRONTEND_URL_RAW = os.getenv("FRONTEND_URL", "")
FRONTEND_URL = FRONTEND_URL_RAW.rstrip("/").strip() if FRONTEND_URL_RAW else None

ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()

_enable_docs_raw = os.getenv("ENABLE_DOCS", "")
if _enable_docs_raw:
    ENABLE_DOCS = _enable_docs_raw.strip().lower() in ("true", "1", "yes")
else:
    ENABLE_DOCS = ENVIRONMENT != "production"

def validate_config():
    missing = []
    if not SUPABASE_URL or not SUPABASE_URL.strip():
        missing.append("SUPABASE_URL")
    if not SUPABASE_KEY or not SUPABASE_KEY.strip():
        missing.append("SUPABASE_KEY")
    if missing:
        raise RuntimeError(f"Startup configuration error: missing required environment variable(s): {', '.join(missing)}")

validate_config()

