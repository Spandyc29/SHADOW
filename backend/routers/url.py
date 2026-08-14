import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status, Request
from pydantic import BaseModel
from dependencies.rate_limiter import limiter
from services.analysis_pipeline import AnalysisPipeline
from services.normalizer import ThreatNormalizer
from services.scan_service import create_scan
from services.threat_gateway import ThreatGateway
from services.url_service import extract_url_information
from services.url_validator import normalize_url


from dependencies.auth import get_current_user_context_or_guest, UserAuthContext

logger = logging.getLogger("SHADOW")

router = APIRouter(
    prefix="/url",
    tags=["URL Analysis"]
)

class URLRequest(BaseModel):
    url: str


@router.post("/analyze", status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def analyze_url(
    request: Request = None,
    body: URLRequest = None,
    user_ctx: UserAuthContext = Depends(get_current_user_context_or_guest),
):
    url_req = request if isinstance(request, URLRequest) else body
    if not url_req:
        raise HTTPException(status_code=400, detail="Missing url request payload")

    user_id = user_ctx.user_id
    is_guest = user_ctx.is_guest
    access_token = user_ctx.access_token

    try:
        normalized_url = normalize_url(url_req.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        ) from exc

    try:
        logger.info("[URL] URL analysis started")

        vt_result = await ThreatGateway.lookup_indicator(
            normalized_url,
            "url"
        )

        normalized = ThreatNormalizer.normalize_url_result(
            normalized_url,
            vt_result
        )

        normalized.update({
            "analysis_type": "url",
            "url": normalized_url,
            "url_info": extract_url_information(normalized_url),
        })

        analysis = AnalysisPipeline.run(normalized)

        if is_guest:
            return {
                "guest_mode": True,
                "analysis_type": "url",
                "url": normalized_url,
                "result": analysis,
            }

        scan = await create_scan(
            user_id=user_id,
            analysis_type="url",
            file_name=normalized_url,
            vt_status=analysis.get("status"),
            vt_detections=analysis.get("detections"),
            vt_total_engines=analysis.get("total_engines"),
            vt_permalink=analysis.get("permalink"),
            vt_raw=analysis,
            access_token=access_token,
        )

        return {
            "guest_mode": False,
            "analysis_type": "url",
            "url": normalized_url,
            "scan_id": scan["id"],
            "result": analysis,
        }

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception(exc)

        raise HTTPException(
            status_code=500,
            detail="URL analysis could not be completed."
        ) from exc
