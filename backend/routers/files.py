import uuid
import time
import tempfile
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import APIRouter, UploadFile, File, Header, HTTPException, status, Depends, Request
from dependencies.rate_limiter import limiter
import config
from services.analysis_pipeline import AnalysisPipeline
from services.file_type_service import detect_file_type, SUPPORTED_EXTENSIONS
from services.ioc_extractor import build_text_preview, extract_iocs
from database import supabase
from services.metadata_service import extract_metadata
from services.hash_service import generate_hashes
from services.normalizer import ThreatNormalizer
from services.scan_service import create_scan
from services.threat_gateway import ThreatGateway
from dependencies.auth import get_current_user_context_or_guest, UserAuthContext

logger = logging.getLogger("SHADOW")

router = APIRouter(prefix="/files", tags=["files"])

async def validate_file(file: UploadFile) -> None:
    if not file.filename:
        logger.warning("[SHADOW] Validation Failed: Filename is missing or empty.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid upload: Filename cannot be empty."
        )
    
    try:
        file.file.seek(0, 2)
        file_size = file.file.tell()
        file.file.seek(0)
    except Exception as e:
        logger.error(f"[SHADOW] Validation Error: Failed to determine file size. Details: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid upload: Unable to read file size."
        )

    if file_size == 0:
        logger.warning("[SHADOW] Validation Failed: Uploaded file is empty.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid upload: File is empty."
        )

    max_size = getattr(config, "MAX_FILE_SIZE", 100 * 1024 * 1024)
    if file_size > max_size:
        logger.warning(f"[SHADOW] Validation Failed: File size {file_size} bytes exceeds maximum limit.")
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Invalid upload: File size exceeds the maximum limit."
        )

    original_ext = Path(file.filename).suffix.lower()
    allowed_exts = getattr(config, "ALLOWED_EXTENSIONS", SUPPORTED_EXTENSIONS)
    if original_ext not in allowed_exts:
        logger.warning(f"[SHADOW] Validation Failed: Unsupported file extension '{original_ext}'.")
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Invalid upload: Unsupported file type '{original_ext}'."
        )

@router.post("/upload", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    user_ctx: UserAuthContext = Depends(get_current_user_context_or_guest)
) -> Dict[str, Any]:
    start_total = time.perf_counter()
    logger.info("[SHADOW] Upload Started")
    
    await validate_file(file)

    user_id = user_ctx.user_id
    is_guest = user_ctx.is_guest
    access_token = user_ctx.access_token
    db_client = user_ctx.get_client()

    scan_uuid = str(uuid.uuid4())
    original_ext = Path(file.filename).suffix.lower()
    secure_filename = f"{scan_uuid}{original_ext}"
    
    temp_dir_path = Path(getattr(config, "TEMP_DIR", tempfile.gettempdir()))
    temp_dir_path.mkdir(parents=True, exist_ok=True)
    temp_file_path = temp_dir_path / secure_filename

    try:
        try:
            start_save = time.perf_counter()
            file.file.seek(0)
            file_bytes = await file.read()
            with open(temp_file_path, "wb") as temp_file:
                temp_file.write(file_bytes)
            logger.info(f"[SHADOW] Temporary Saved (Duration: {time.perf_counter() - start_save:.4f}s)")
        except Exception as e:
            logger.error(f"[SHADOW] Storage Error: Failed to write temporary file. Details: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Pipeline Error: Failed to process incoming file stream."
            )

        try:
            start_meta = time.perf_counter()
            metadata = extract_metadata(str(temp_file_path))
            logger.info(f"[SHADOW] Metadata Complete (Duration: {time.perf_counter() - start_meta:.4f}s)")
        except Exception as e:
            logger.error(f"[SHADOW] Analysis Error: Metadata extraction failed. Details: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Pipeline Error: Static analysis metadata extraction failed."
            )

        try:
            start_hash = time.perf_counter()
            hashes = generate_hashes(file_bytes)
            logger.info(f"[SHADOW] Hash Complete (Duration: {time.perf_counter() - start_hash:.4f}s)")
        except Exception as e:
            logger.error(f"[SHADOW] Analysis Error: Hash generation failed. Details: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Pipeline Error: Cryptographic hashing failed."
            )

        try:
            start_type = time.perf_counter()
            file_type = detect_file_type(str(temp_file_path), file.filename)
            logger.info(f"[SHADOW] File Type Complete (Duration: {time.perf_counter() - start_type:.4f}s)")
        except Exception as e:
            logger.error(f"[SHADOW] Analysis Error: File type detection failed. Details: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Pipeline Error: File type detection failed."
            )

        try:
            start_ioc = time.perf_counter()
            ioc = extract_iocs(file_bytes, file_type)
            preview = build_text_preview(file_bytes, file_type)
            logger.info(f"[SHADOW] IOC Extraction Complete (Duration: {time.perf_counter() - start_ioc:.4f}s)")
        except Exception as e:
            logger.error(f"[SHADOW] Analysis Error: IOC extraction failed. Details: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Pipeline Error: IOC extraction failed."
            )

        try:
            start_vt = time.perf_counter()
            vt_result = await ThreatGateway.lookup_indicator(hashes["sha256"], "hash")
            logger.info(f"[SHADOW] VirusTotal Complete (Duration: {time.perf_counter() - start_vt:.4f}s)")
        except Exception as e:
            logger.error(f"[SHADOW] Threat Intel Error: VirusTotal lookup failed. Details: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Pipeline Error: Threat intelligence lookup failed."
            )

        normalized = ThreatNormalizer.normalize_hash_result(
            hashes["sha256"],
            vt_result
        )
        provider_file_type = normalized.get("file_type")
        normalized.update({
            "analysis_type": "file",
            "file_name": file.filename,
            "metadata": metadata,
            "hashes": hashes,
            "file_type": file_type,
            "provider_file_type": provider_file_type,
            "ioc": ioc,
            "preview": preview,
            "md5": hashes.get("md5"),
            "sha1": hashes.get("sha1"),
            "sha256": hashes.get("sha256"),
            "mime_type": file_type.get("mime"),
            "file_size": metadata.get("file_size"),
        })
        analysis = AnalysisPipeline.run(normalized)

        virustotal_summary = {
            "status": analysis.get("status"),
            "detections": analysis.get("detections"),
            "total_engines": analysis.get("total_engines"),
            "permalink": analysis.get("permalink")
        }

        if is_guest:
            scan_id = f"guest_tmp_{uuid.uuid4().hex[:8]}"
            logger.info(f"[SHADOW] Guest Scan Processed (Total Pipeline Duration: {time.perf_counter() - start_total:.4f}s)")
            logger.info("[SHADOW] Upload Finished")
            return {
                "scan_id": scan_id,
                "metadata": metadata,
                "hashes": hashes,
                "file_type": file_type,
                "ioc": ioc,
                "preview": preview,
                "virustotal_summary": virustotal_summary,
                "result": analysis,
                "storage_status": "skipped",
                "guest_mode_status": True,
                "upload_status": "success"
            }

        storage_path = f"scans/{user_id}/{secure_filename}"
        try:
            start_storage = time.perf_counter()
            storage_response = db_client.storage.from_("shadow-files").upload(
                path=storage_path,
                file=file_bytes,
                file_options={"content-type": file.content_type or "application/octet-stream"}
            )
            if hasattr(storage_response, "error") and storage_response.error:
                raise Exception(storage_response.error)
            logger.info(f"[SHADOW] Storage Complete (Duration: {time.perf_counter() - start_storage:.4f}s)")
        except Exception as e:
            logger.error(f"[SHADOW] Storage Error: Supabase Storage upload failed. Details: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Pipeline Error: Remote object storage sync failed."
            )

        try:
            start_db = time.perf_counter()
            scan = await create_scan(
                user_id=user_id,
                analysis_type="file",
                file_name=file.filename,
                file_size=len(file_bytes),
                md5=hashes.get("md5"),
                sha1=hashes.get("sha1"),
                sha256=hashes.get("sha256"),
                storage_path=storage_path,
                vt_status=analysis.get("status"),
                vt_detections=analysis.get("detections"),
                vt_total_engines=analysis.get("total_engines"),
                vt_permalink=analysis.get("permalink"),
                vt_raw=analysis,
                access_token=access_token,
            )
            scan_id = scan["id"]
            logger.info(
                f"[SHADOW] Database Complete (Duration: {time.perf_counter() - start_db:.4f}s)"
            )
        except Exception as e:
            logger.error(f"[SHADOW] Database Error: Supabase DB insertion failed. Details: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Pipeline Error: Database transaction failed."
            )

        logger.info(f"[SHADOW] Cleanup Complete (Total Pipeline Duration: {time.perf_counter() - start_total:.4f}s)")
        logger.info("[SHADOW] Upload Finished")
        return {
            "scan_id": scan_id,
            "metadata": metadata,
            "hashes": hashes,
            "file_type": file_type,
            "ioc": ioc,
            "preview": preview,
            "virustotal_summary": virustotal_summary,
            "result": analysis,
            "storage_status": "completed",
            "guest_mode_status": False,
            "upload_status": "success"
        }

    finally:
        if temp_file_path.exists():
            try:
                temp_file_path.unlink()
            except Exception as e:
                logger.error(f"[SHADOW] Cleanup Warning: Failed to delete temporary file {temp_file_path}. Details: {str(e)}")
