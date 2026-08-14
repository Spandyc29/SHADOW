import csv
import io
import logging
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse, Response
from dependencies.auth import get_current_user_context, UserAuthContext

logger = logging.getLogger("SHADOW")
router = APIRouter(prefix="/scans", tags=["scans"])

@router.get("/")
async def get_scans(user_ctx: UserAuthContext = Depends(get_current_user_context)):
    try:
        db_client = user_ctx.get_client()
        result = db_client.table("scans")\
            .select("*")\
            .eq("user_id", user_ctx.user_id)\
            .order("created_at", desc=True)\
            .execute()

        return {"scans": result.data or []}

    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail="Failed to retrieve scans.")

@router.get("/export/bulk")
async def export_scans_bulk(format: str = "json", user_ctx: UserAuthContext = Depends(get_current_user_context)):
    try:
        db_client = user_ctx.get_client()
        result = db_client.table("scans")\
            .select("*")\
            .eq("user_id", user_ctx.user_id)\
            .order("created_at", desc=True)\
            .execute()
        scans = result.data or []

        if str(format).lower() == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "ID", "File Name", "Analysis Type", "Status",
                "Detections", "Total Engines", "MD5", "SHA256", "Created At"
            ])
            for s in scans:
                writer.writerow([
                    s.get("id"),
                    s.get("file_name"),
                    s.get("analysis_type"),
                    s.get("vt_status"),
                    s.get("vt_detections"),
                    s.get("vt_total_engines"),
                    s.get("md5"),
                    s.get("sha256"),
                    s.get("created_at"),
                ])

            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=scan_history_export.csv"}
            )
        else:
            return JSONResponse(
                content={"scans": scans},
                headers={"Content-Disposition": "attachment; filename=scan_history_export.json"}
            )

    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail="Export generation failed.")

@router.get("/{scan_id}/export")
async def export_scan(scan_id: str, user_ctx: UserAuthContext = Depends(get_current_user_context)):
    try:
        db_client = user_ctx.get_client()
        result = db_client.table("scans")\
            .select("*")\
            .eq("id", scan_id)\
            .eq("user_id", user_ctx.user_id)\
            .execute()

        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan_data = result.data[0]
        return JSONResponse(
            content=scan_data,
            headers={
                "Content-Disposition": f"attachment; filename=scan_{scan_id}.json"
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail="Failed to export scan.")

@router.get("/{scan_id}")
async def get_scan(scan_id: str, user_ctx: UserAuthContext = Depends(get_current_user_context)):
    try:
        db_client = user_ctx.get_client()
        result = db_client.table("scans")\
            .select("*")\
            .eq("id", scan_id)\
            .eq("user_id", user_ctx.user_id)\
            .execute()

        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=404, detail="Scan not found")

        return {"scan": result.data[0]}

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail="Failed to retrieve scan details.")

@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, user_ctx: UserAuthContext = Depends(get_current_user_context)):
    try:
        db_client = user_ctx.get_client()
        result = db_client.table("scans")\
            .delete()\
            .eq("id", scan_id)\
            .eq("user_id", user_ctx.user_id)\
            .execute()

        if not result.data or len(result.data) == 0:
            raise HTTPException(status_code=404, detail="Scan not found")

        return {"message": "Scan deleted successfully", "id": scan_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail="Failed to delete scan.")