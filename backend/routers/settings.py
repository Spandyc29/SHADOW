import logging
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from dependencies.auth import get_current_user_context, UserAuthContext

logger = logging.getLogger("SHADOW")
router = APIRouter(prefix="/settings", tags=["settings"])


class ApiKeysUpdate(BaseModel):
    groq_api_key: Optional[str] = None
    vt_api_key: Optional[str] = None


def mask_key(key: Optional[str]) -> Optional[str]:
    """Mask key so full value is never exposed on GET requests."""
    if not key or not isinstance(key, str) or len(key.strip()) == 0:
        return None
    k = key.strip()
    if len(k) <= 8:
        return "••••••••"
    return f"{k[:4]}••••••••{k[-4:]}"


def get_user_stored_key(user_id: str, key_name: str) -> Optional[str]:
    """Helper for virustotal and shadow_ai to fetch user-specific key from DB."""
    try:
        from database import supabase
        res = supabase.table("user_settings").select(key_name).eq("user_id", user_id).execute()
        if res.data and len(res.data) > 0:
            val = res.data[0].get(key_name)
            if val and isinstance(val, str) and len(val.strip()) > 0:
                return val.strip()
    except Exception:
        pass
    return None


@router.get("/api-keys")
async def get_api_keys(user_ctx: UserAuthContext = Depends(get_current_user_context)):
    try:
        db_client = user_ctx.get_client()
        res = db_client.table("user_settings").select("*").eq("user_id", user_ctx.user_id).execute()
        data = res.data[0] if (res.data and len(res.data) > 0) else {}
        groq_raw = data.get("groq_api_key")
        vt_raw = data.get("vt_raw_key") or data.get("vt_api_key")

        return {
            "groq_api_key": mask_key(groq_raw),
            "vt_api_key": mask_key(vt_raw),
            "has_groq_key": bool(groq_raw and len(str(groq_raw).strip()) > 0),
            "has_vt_key": bool(vt_raw and len(str(vt_raw).strip()) > 0),
        }
    except Exception:
        return {
            "groq_api_key": None,
            "vt_api_key": None,
            "has_groq_key": False,
            "has_vt_key": False,
        }


@router.put("/api-keys")
async def update_api_keys(payload: ApiKeysUpdate, user_ctx: UserAuthContext = Depends(get_current_user_context)):
    try:
        db_client = user_ctx.get_client()
        update_data: Dict[str, Any] = {"user_id": user_ctx.user_id}
        if payload.groq_api_key is not None:
            update_data["groq_api_key"] = payload.groq_api_key.strip()
        if payload.vt_api_key is not None:
            update_data["vt_api_key"] = payload.vt_api_key.strip()

        res = db_client.table("user_settings").upsert(update_data, on_conflict="user_id").execute()
        saved = res.data[0] if (res.data and len(res.data) > 0) else update_data

        return {
            "message": "API keys updated successfully",
            "has_groq_key": bool(saved.get("groq_api_key")),
            "has_vt_key": bool(saved.get("vt_api_key")),
        }
    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail="Failed to update API keys.")
