import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status, Request
from pydantic import BaseModel
from dependencies.rate_limiter import limiter
from services.analysis_pipeline import AnalysisPipeline
from services.domain.domain_service import get_domain_details
from services.domain.domain_validator import normalize_domain
from services.normalizer import ThreatNormalizer
from services.scan_service import create_scan
from services.threat_gateway import ThreatGateway

from dependencies.auth import get_current_user_context_or_guest, UserAuthContext

logger = logging.getLogger("SHADOW")

router = APIRouter(
    prefix="/domain",
    tags=["Domain Analysis"]
)

class DomainRequest(BaseModel):
    domain: str


@router.post("/analyze", status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def analyze_domain(
    request: Request = None,
    body: DomainRequest = None,
    user_ctx: UserAuthContext = Depends(get_current_user_context_or_guest),
):
    domain_req = request if isinstance(request, DomainRequest) else body
    if not domain_req:
        raise HTTPException(status_code=400, detail="Missing domain request payload")

    user_id = user_ctx.user_id
    is_guest = user_ctx.is_guest
    access_token = user_ctx.access_token

    try:
        normalized_domain = normalize_domain(domain_req.domain)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        ) from exc

    try:
        logger.info(f"[DOMAIN] Domain analysis started for {normalized_domain}")

        vt_result = await ThreatGateway.lookup_indicator(
            normalized_domain,
            "domain"
        )

        normalized = ThreatNormalizer.normalize_domain_result(
            normalized_domain,
            vt_result
        )

        domain_details = await get_domain_details(normalized_domain)

        normalized.update({
            "analysis_type": "domain",
            "domain": normalized_domain,
            "domain_info": domain_details.get("info"),
            "dns_info": domain_details.get("dns"),
            "whois_info": domain_details.get("whois"),
        })

        analysis = AnalysisPipeline.run(normalized)

        if is_guest:
            return {
                "guest_mode": True,
                "analysis_type": "domain",
                "domain": normalized_domain,
                "result": analysis,
            }

        scan = await create_scan(
            user_id=user_id,
            analysis_type="domain",
            file_name=normalized_domain,
            vt_status=analysis.get("status"),
            vt_detections=analysis.get("detections"),
            vt_total_engines=analysis.get("total_engines"),
            vt_permalink=analysis.get("permalink"),
            vt_raw=analysis,
            access_token=access_token,
        )

        return {
            "guest_mode": False,
            "analysis_type": "domain",
            "domain": normalized_domain,
            "scan_id": scan["id"],
            "result": analysis,
        }

    except HTTPException:
        raise

    except Exception as exc:
        logger.exception(exc)

        raise HTTPException(
            status_code=500,
            detail="Domain analysis could not be completed."
        ) from exc
