import logging
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    status,
    Request,
)
from pydantic import BaseModel
from dependencies.rate_limiter import limiter
from services.hash_service import validate_hash
from services.normalizer import ThreatNormalizer
from services.scan_service import create_scan
from services.threat_gateway import ThreatGateway
from services.analysis_pipeline import AnalysisPipeline


from dependencies.auth import get_current_user_context_or_guest, UserAuthContext

logger = logging.getLogger("SHADOW")

router = APIRouter(
    prefix="/hash",
    tags=["Hash Analysis"]
)

class HashRequest(BaseModel):
    hash: str


@router.post("/analyze", status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def analyze_hash(
    request: Request = None,
    body: HashRequest = None,
    user_ctx: UserAuthContext = Depends(get_current_user_context_or_guest),
):
    hash_req = request if isinstance(request, HashRequest) else body
    if not hash_req:
        raise HTTPException(status_code=400, detail="Missing hash request payload")

    user_id = user_ctx.user_id
    is_guest = user_ctx.is_guest
    access_token = user_ctx.access_token

    try:
        hash_value = hash_req.hash.strip().lower()
        valid, hash_type = validate_hash(hash_value)

        if not valid:
            raise HTTPException(
                status_code=400,
                detail="Invalid hash format."
            )

        logger.info(f"[HASH] {hash_type.upper()} detected")

        vt_result = await ThreatGateway.lookup_indicator(
            hash_value,
            "hash"
        )

        normalized = ThreatNormalizer.normalize_hash_result(
            hash_value,
            vt_result
        )

        normalized = AnalysisPipeline.run(normalized)

        if is_guest:
            return {
                "guest_mode": True,
                "analysis_type": "hash",
                "hash_type": hash_type,
                "result": normalized
            }

        scan = await create_scan(
            user_id=user_id,
            analysis_type="hash",
            file_name=hash_value,
            md5=hash_value if hash_type == "md5" else None,
            sha1=hash_value if hash_type == "sha1" else None,
            sha256=hash_value if hash_type == "sha256" else None,
            vt_status=normalized.get("status"),
            vt_detections=normalized.get("detections"),
            vt_total_engines=normalized.get("total_engines"),
            vt_permalink=normalized.get("permalink"),
            vt_raw=normalized,
            access_token=access_token,
        )

        return {
            "guest_mode": False,
            "analysis_type": "hash",
            "hash_type": hash_type,
            "scan_id": scan["id"],
            "result": normalized,
        }

    except HTTPException:
        raise

    except Exception as e:

        logger.exception(e)

        raise HTTPException(
            status_code=500,
            detail="Hash analysis could not be completed."
        )