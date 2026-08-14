from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from collections import Counter
from fastapi import APIRouter, HTTPException, Depends
from dependencies.auth import get_current_user_context, UserAuthContext

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def calculate_trend_pct(current: float, previous: float, max_cap: float = 999.0) -> float:
    """Calculate percentage change between previous and current period, with safeguards for small denominators."""
    if previous == 0:
        return 100.0 if current > 0 else 0.0

    pct = ((current - previous) / previous) * 100.0

    # If previous count is very small (< 5), cap percentage to avoid extreme spikes like 5750%
    if previous < 5:
        return min(round(pct, 1), 100.0) if pct > 0 else max(round(pct, 1), -100.0)

    if pct > max_cap:
        return max_cap
    elif pct < -max_cap:
        return -max_cap

    return round(pct, 1)


def extract_category_names(raw_cats: Any) -> List[str]:
    """Helper to extract clean category strings from dict/list/string shapes."""
    if not raw_cats:
        return []

    items = []
    if isinstance(raw_cats, dict):
        items = list(raw_cats.values())
    elif isinstance(raw_cats, list):
        items = raw_cats
    else:
        items = [raw_cats]

    result = []
    for item in items:
        val = None
        if isinstance(item, dict):
            val = item.get("value") or item.get("name") or item.get("category")
        elif isinstance(item, str):
            val = item

        if val:
            cleaned = str(val).strip().lower()
            if cleaned and cleaned not in ("none", "clean", "safe", "unknown", "no threat detected"):
                result.append(cleaned)

    return result


def compute_top_threat_categories(scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate threat categories for malicious/suspicious scans.
    Caps at top 5 categories and groups remainder into 'other'.
    """
    counter = Counter()

    for s in scans:
        vt_status = s.get("vt_status")
        vt_raw = s.get("vt_raw") or {}
        verdict = str(vt_raw.get("verdict") or "").upper()
        vt_detections = s.get("vt_detections") or 0

        is_not_found = (vt_status == "not_found")
        is_threat_or_suspicious = (verdict in ("MALICIOUS", "SUSPICIOUS") or (not is_not_found and vt_detections > 0))

        if not is_threat_or_suspicious:
            continue

        attributes = (vt_raw.get("data") or {}).get("attributes") if isinstance(vt_raw.get("data"), dict) else {}
        pop_class = attributes.get("popular_threat_classification") if isinstance(attributes, dict) else {}
        if not isinstance(pop_class, dict):
            pop_class = {}

        # 1. threat_categories / popular_threat_category
        cats = extract_category_names(vt_raw.get("threat_categories"))
        if not cats:
            cats = extract_category_names(pop_class.get("popular_threat_category"))

        # 2. categories (top-level or inside attributes)
        if not cats:
            cats = extract_category_names(vt_raw.get("categories"))
        if not cats:
            cats = extract_category_names(attributes.get("categories"))

        # 3. threat_label / suggested_threat_label
        if not cats:
            label = vt_raw.get("threat_label") or pop_class.get("suggested_threat_label")
            if label:
                cleaned_label = str(label).strip().lower()
                if cleaned_label and cleaned_label not in ("none", "clean", "safe", "no threat detected"):
                    base_cat = cleaned_label.split(".")[0].split("-")[0].split("/")[0]
                    cats = [base_cat]

        # 4. tags (top-level or inside attributes)
        if not cats:
            tags = extract_category_names(vt_raw.get("tags")) or extract_category_names(attributes.get("tags"))
            filtered_tags = [t for t in tags if t not in ("apk", "contains-elf", "android", "x86", "64-bit", "peexe")]
            if filtered_tags:
                cats = [filtered_tags[0]]

        if not cats:
            cats = ["other"]

        for cat in set(cats):
            counter[cat] += 1

    total_threats = sum(counter.values())
    if total_threats == 0:
        return {"total_threats": 0, "categories": []}

    most_common = counter.most_common()
    categories_list = []

    if len(most_common) <= 5:
        top_items = most_common
        other_count = 0
    else:
        top_items = most_common[:5]
        other_count = sum(count for _, count in most_common[5:])

    for name, count in top_items:
        pct = round((count / total_threats) * 100.0, 1)
        categories_list.append({"name": name, "count": count, "pct": pct})

    if other_count > 0:
        other_pct = round((other_count / total_threats) * 100.0, 1)
        categories_list.append({"name": "other", "count": other_count, "pct": other_pct})

    return {
        "total_threats": total_threats,
        "categories": categories_list,
    }


def compute_scan_activity(scans: List[Dict[str, Any]], now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Compute scan activity metrics: today, this_week, this_month, and detection_rate.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    today = now.date()
    yesterday = today - timedelta(days=1)

    week_current_start = today - timedelta(days=6)
    week_prev_start = today - timedelta(days=13)
    week_prev_end = today - timedelta(days=7)

    month_current_start = today - timedelta(days=29)
    month_prev_start = today - timedelta(days=59)
    month_prev_end = today - timedelta(days=30)

    today_count = 0
    yesterday_count = 0

    week_current_count = 0
    week_prev_count = 0

    month_current_count = 0
    month_prev_count = 0

    week_current_detections = 0
    week_prev_detections = 0

    for s in scans:
        created_str = s.get("created_at")
        if not created_str:
            continue

        try:
            dt = datetime.fromisoformat(str(created_str).replace("Z", "+00:00"))
            scan_date = dt.date()
        except Exception:
            continue

        vt_status = s.get("vt_status")
        vt_raw = s.get("vt_raw") or {}
        verdict = str(vt_raw.get("verdict") or "").upper()
        vt_detections = s.get("vt_detections") or 0

        is_not_found = (vt_status == "not_found")
        is_threat_or_suspicious = (verdict in ("MALICIOUS", "SUSPICIOUS") or (not is_not_found and vt_detections > 0))

        # Today vs Yesterday
        if scan_date == today:
            today_count += 1
        elif scan_date == yesterday:
            yesterday_count += 1

        # This Week vs Previous Week
        if week_current_start <= scan_date <= today:
            week_current_count += 1
            if is_threat_or_suspicious:
                week_current_detections += 1
        elif week_prev_start <= scan_date <= week_prev_end:
            week_prev_count += 1
            if is_threat_or_suspicious:
                week_prev_detections += 1

        # This Month vs Previous Month
        if month_current_start <= scan_date <= today:
            month_current_count += 1
        elif month_prev_start <= scan_date <= month_prev_end:
            month_prev_count += 1

    curr_det_rate = round((week_current_detections / week_current_count * 100.0), 1) if week_current_count > 0 else 0.0
    det_rate_trend = calculate_trend_pct(week_current_detections, week_prev_detections)

    return {
        "today": {
            "count": today_count,
            "trend_pct": calculate_trend_pct(today_count, yesterday_count),
        },
        "this_week": {
            "count": week_current_count,
            "trend_pct": calculate_trend_pct(week_current_count, week_prev_count),
        },
        "this_month": {
            "count": month_current_count,
            "trend_pct": calculate_trend_pct(month_current_count, month_prev_count),
        },
        "detection_rate": {
            "pct": curr_det_rate,
            "trend_pct": det_rate_trend,
        },
    }


def compute_dashboard_stats(scans: List[Dict[str, Any]], now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Compute trend percentages and 7-day sparklines for dashboard stat categories.
    
    Categories: total_scans, clean, suspicious, threats, not_found.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    today = now.date()

    # Sparkline dates: 7 days, oldest (today - 6) to newest (today)
    sparkline_dates = [today - timedelta(days=i) for i in range(6, -1, -1)]
    date_to_sparkline_idx = {d.isoformat(): idx for idx, d in enumerate(sparkline_dates)}

    previous_start = today - timedelta(days=13)
    previous_end = today - timedelta(days=7)

    category_data = {
        "total_scans": {"current": 0, "previous": 0, "sparkline": [0] * 7},
        "clean": {"current": 0, "previous": 0, "sparkline": [0] * 7},
        "suspicious": {"current": 0, "previous": 0, "sparkline": [0] * 7},
        "threats": {"current": 0, "previous": 0, "sparkline": [0] * 7},
        "not_found": {"current": 0, "previous": 0, "sparkline": [0] * 7},
    }

    for s in scans:
        created_str = s.get("created_at")
        if not created_str:
            continue

        try:
            dt = datetime.fromisoformat(str(created_str).replace("Z", "+00:00"))
            scan_date = dt.date()
        except Exception:
            continue

        vt_status = s.get("vt_status")
        vt_raw = s.get("vt_raw") or {}
        verdict = str(vt_raw.get("verdict") or "").upper()
        vt_detections = s.get("vt_detections") or 0

        # Determine category flags
        is_not_found = (vt_status == "not_found")
        is_suspicious = (verdict == "SUSPICIOUS")
        is_threat = (verdict == "MALICIOUS" or (not is_not_found and not is_suspicious and vt_detections > 0))
        is_clean = (verdict == "CLEAN" or (not is_not_found and not is_suspicious and not is_threat and vt_detections == 0))

        matched_categories = ["total_scans"]
        if is_not_found:
            matched_categories.append("not_found")
        elif is_suspicious:
            matched_categories.append("suspicious")
        elif is_threat:
            matched_categories.append("threats")
        elif is_clean:
            matched_categories.append("clean")

        date_iso = scan_date.isoformat()
        if date_iso in date_to_sparkline_idx:
            spark_idx = date_to_sparkline_idx[date_iso]
            for cat in matched_categories:
                category_data[cat]["current"] += 1
                category_data[cat]["sparkline"][spark_idx] += 1
        elif previous_start <= scan_date <= previous_end:
            for cat in matched_categories:
                category_data[cat]["previous"] += 1

    response_data = {}
    for cat, data in category_data.items():
        current = data["current"]
        previous = data["previous"]
        trend_pct = calculate_trend_pct(current, previous)
        response_data[cat] = {
            "current": current,
            "previous": previous,
            "trend_pct": trend_pct,
            "sparkline": data["sparkline"],
        }

    return response_data


@router.get("/stats")
async def get_stats(user_ctx: UserAuthContext = Depends(get_current_user_context)):
    try:
        db_client = user_ctx.get_client()
        now = datetime.now(timezone.utc)
        today = now.date()

        # Query 60-day window to support 30-day month trends for current user
        start_date = today - timedelta(days=60)
        start_date_iso = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc).isoformat()

        result = db_client.table("scans")\
            .select("*")\
            .eq("user_id", user_ctx.user_id)\
            .gte("created_at", start_date_iso)\
            .order("created_at", desc=True)\
            .execute()
        window_scans = result.data or []

        # Always fetch recent 5 scans for current user
        recent_result = db_client.table("scans")\
            .select("*")\
            .eq("user_id", user_ctx.user_id)\
            .order("created_at", desc=True)\
            .limit(5)\
            .execute()
        recent_raw = recent_result.data or []

        stats_data = compute_dashboard_stats(window_scans, now=now)
        stats_data["top_threat_categories"] = compute_top_threat_categories(window_scans)
        stats_data["scan_activity"] = compute_scan_activity(window_scans, now=now)

        recent_scans = [
            {
                "id": s.get("id"),
                "file_name": s.get("file_name"),
                "vt_status": s.get("vt_status"),
                "vt_detections": s.get("vt_detections"),
                "vt_total_engines": s.get("vt_total_engines"),
                "created_at": s.get("created_at"),
            }
            for s in recent_raw
        ]

        stats_data["recent_scans"] = recent_scans
        stats_data["clean_files"] = stats_data["clean"]["current"]
        stats_data["threats_detected"] = stats_data["threats"]["current"]
        stats_data["not_found_count"] = stats_data["not_found"]["current"]

        return stats_data

    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=500, detail="Unable to fetch dashboard statistics.")
