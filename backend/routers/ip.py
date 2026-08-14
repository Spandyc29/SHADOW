import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status, Request
from pydantic import BaseModel
from dependencies.rate_limiter import limiter
from services.analysis_pipeline import AnalysisPipeline
from services.ip.ip_service import get_ip_details
from services.ip.ip_validator import normalize_ip
from services.normalizer import ThreatNormalizer
from services.scan_service import create_scan
from services.threat_gateway import ThreatGateway

from dependencies.auth import get_current_user_context_or_guest, UserAuthContext

logger = logging.getLogger("SHADOW")

router = APIRouter(
    prefix="/ip",
    tags=["IP Analysis"]
)

class IPRequest(BaseModel):
    ip: str


@router.post("/analyze", status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def analyze_ip(
    request: Request = None,
    body: IPRequest = None,
    user_ctx: UserAuthContext = Depends(get_current_user_context_or_guest),
):
    ip_req = request if isinstance(request, IPRequest) else body
    if not ip_req:
        raise HTTPException(status_code=400, detail="Missing ip request payload")

    user_id = user_ctx.user_id
    is_guest = user_ctx.is_guest
    access_token = user_ctx.access_token

    logger.info("[SHADOW] Validation Started")

    try:
        normalized_ip = normalize_ip(ip_req.ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        ) from exc

    try:
        logger.info(f"[SHADOW] IP Analysis Started for {normalized_ip}")

        logger.info(f"[SHADOW] VirusTotal Lookup Started for {normalized_ip}")
        vt_result = await ThreatGateway.lookup_indicator(
            normalized_ip,
            "ip"
        )
        logger.info("[SHADOW] VirusTotal Complete")

        normalized = ThreatNormalizer.normalize_ip_result(
            normalized_ip,
            vt_result
        )

        ip_info = await get_ip_details(normalized_ip)

        normalized.update({
            "analysis_type": "ip",
            "ip": normalized_ip,
            "ip_info": ip_info,
        })

        analysis = AnalysisPipeline.run(normalized)

        logger.info(f"[SHADOW] IP Analysis Finished for {normalized_ip}")

        if is_guest:
            return {
                "guest_mode": True,
                "analysis_type": "ip",
                "ip": normalized_ip,
                "result": analysis,
            }

        scan = await create_scan(
            user_id=user_id,
            analysis_type="ip",
            file_name=normalized_ip,
            vt_status=analysis.get("status"),
            vt_detections=analysis.get("detections"),
            vt_total_engines=analysis.get("total_engines"),
            vt_permalink=analysis.get("permalink"),
            vt_raw=analysis,
            access_token=access_token,
        )

        return {
            "guest_mode": False,
            "analysis_type": "ip",
            "ip": normalized_ip,
            "scan_id": scan["id"],
            "result": analysis,
        }

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception(exc)

        raise HTTPException(
            status_code=500,
            detail="IP analysis could not be completed."
        ) from exc
