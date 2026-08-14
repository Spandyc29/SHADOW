import logging
from typing import Optional, Dict, Any

from database import get_supabase_client
from supabase import Client

logger = logging.getLogger("SHADOW")


async def create_scan(
    *,
    user_id: str,
    analysis_type: str,
    file_name: str,
    file_size: Optional[int] = None,
    md5: Optional[str] = None,
    sha1: Optional[str] = None,
    sha256: Optional[str] = None,
    storage_path: Optional[str] = None,
    vt_status: Optional[str] = None,
    vt_detections: Optional[int] = None,
    vt_total_engines: Optional[int] = None,
    vt_permalink: Optional[str] = None,
    vt_raw: Optional[Dict[str, Any]] = None,
    access_token: Optional[str] = None,
):
    """
    Create a new scan entry in database.

    Used by:
    - File Upload
    - Hash Analysis
    - URL Analysis (future)
    - Domain Analysis (future)
    - IP Analysis (future)
    """

    try:
        db_client: Client = get_supabase_client(access_token)

        scan = {
            "user_id": user_id,
            "analysis_type": analysis_type,
            "file_name": file_name,
            "file_size": file_size,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "storage_path": storage_path,
            "vt_status": vt_status,
            "vt_detections": vt_detections,
            "vt_total_engines": vt_total_engines,
            "vt_permalink": vt_permalink,
            "vt_raw": vt_raw,
        }

        response = db_client.table("scans").insert(scan).execute()

        if not response.data:
            raise Exception("Database insert failed.")

        scan_id = response.data[0]["id"]

        logger.info(f"[SCAN SERVICE] Scan Created : {scan_id}")

        return response.data[0]

    except Exception as e:

        logger.exception("[SCAN SERVICE] Failed creating scan")

        raise e