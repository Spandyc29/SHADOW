from typing import Dict, Any, Optional
import logging
from fastapi import APIRouter, HTTPException, Response, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from services.report_engine import ReportEngine
from dependencies.auth import get_current_user_context_or_guest, UserAuthContext

logger = logging.getLogger("SHADOW")

router = APIRouter(prefix="/reports", tags=["reports"])


class RenderReportRequest(BaseModel):
    analysis_result: Dict[str, Any] = Field(..., description="Completed SHADOW analysis object")
    format: str = Field(default="html", description="Output format: html or json (pdf placeholder)")


@router.post("/render")
async def render_report(
    request: RenderReportRequest,
    user_ctx: UserAuthContext = Depends(get_current_user_context_or_guest)
):
    """
    Render a SHADOW analysis result into presentation format (HTML / JSON).
    """
    fmt = request.format.lower().strip()

    if fmt not in ["html", "json", "pdf"]:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format '{request.format}'. Supported formats: html, json, pdf"
        )

    try:
        report_engine = ReportEngine()

        if fmt == "pdf":
            pdf_bytes = report_engine.generate(
                analysis_data=request.analysis_result,
                output_format="pdf"
            )
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": "inline; filename=shadow_report.pdf"},
                status_code=200
            )

        rendered_content = report_engine.generate(
            analysis_data=request.analysis_result,
            output_format=fmt
        )

        if fmt == "html":
            return HTMLResponse(content=rendered_content, status_code=200)
        elif fmt == "json":
            return Response(
                content=rendered_content if isinstance(rendered_content, str) else str(rendered_content),
                media_type="application/json",
                status_code=200
            )

    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=400, detail="Report rendering failed.")
