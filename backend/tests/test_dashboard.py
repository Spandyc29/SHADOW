from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from main import app
from routers.dashboard import (
    compute_dashboard_stats,
    compute_top_threat_categories,
    compute_scan_activity,
    calculate_trend_pct,
)

client = TestClient(app)


def test_calculate_trend_pct_edge_cases():
    # Zero previous, zero current -> 0.0
    assert calculate_trend_pct(0, 0) == 0.0

    # Zero previous, positive current -> 100.0
    assert calculate_trend_pct(5, 0) == 100.0

    # Normal positive growth with previous >= 5 -> ((15 - 10) / 10) * 100 = 50.0
    assert calculate_trend_pct(15, 10) == 50.0

    # Small previous denominator (< 5) capped at 100.0 max
    assert calculate_trend_pct(117, 2) == 100.0

    # Negative growth -> ((5 - 10) / 10) * 100 = -50.0
    assert calculate_trend_pct(5, 10) == -50.0


def test_compute_dashboard_stats_empty():
    now = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)
    res = compute_dashboard_stats([], now=now)

    for cat in ["total_scans", "clean", "suspicious", "threats", "not_found"]:
        assert cat in res
        assert res[cat]["current"] == 0
        assert res[cat]["previous"] == 0
        assert res[cat]["trend_pct"] == 0.0
        assert res[cat]["sparkline"] == [0] * 7

    cats_res = compute_top_threat_categories([])
    assert cats_res["total_threats"] == 0
    assert cats_res["categories"] == []

    act_res = compute_scan_activity([], now=now)
    assert act_res["today"]["count"] == 0
    assert act_res["this_week"]["count"] == 0
    assert act_res["this_month"]["count"] == 0
    assert act_res["detection_rate"]["pct"] == 0.0


def test_compute_top_threat_categories_mixed_shapes_and_fallbacks():
    scans = [
        # List of dicts
        {
            "vt_status": "found",
            "vt_detections": 5,
            "vt_raw": {
                "verdict": "MALICIOUS",
                "threat_categories": [{"count": 2, "value": "trojan"}, {"count": 1, "value": "malware"}],
            },
        },
        # Nested data.attributes.popular_threat_classification
        {
            "vt_status": "found",
            "vt_detections": 3,
            "vt_raw": {
                "data": {
                    "attributes": {
                        "popular_threat_classification": {
                            "suggested_threat_label": "trojan.corrupted",
                            "popular_threat_category": [{"count": 2, "value": "trojan"}],
                        }
                    }
                }
            },
        },
        # List of strings
        {
            "vt_status": "found",
            "vt_detections": 3,
            "vt_raw": {
                "verdict": "MALICIOUS",
                "threat_categories": ["trojan", "adware"],
            },
        },
        # Fallback to categories dict/list
        {
            "vt_status": "found",
            "vt_detections": 1,
            "vt_raw": {
                "verdict": "SUSPICIOUS",
                "categories": {"Kaspersky": "phishing"},
            },
        },
        # Fallback to threat_label string
        {
            "vt_status": "found",
            "vt_detections": 10,
            "vt_raw": {
                "verdict": "MALICIOUS",
                "threat_label": "ransomware.wannacry",
            },
        },
        # Fallback to tags
        {
            "vt_status": "found",
            "vt_detections": 2,
            "vt_raw": {
                "verdict": "MALICIOUS",
                "tags": ["apk", "spyware"],
            },
        },
        # Clean scan - should be ignored
        {
            "vt_status": "found",
            "vt_detections": 0,
            "vt_raw": {"verdict": "CLEAN", "threat_categories": ["none"]},
        },
    ]

    res = compute_top_threat_categories(scans)
    assert res["total_threats"] > 0
    names = [c["name"] for c in res["categories"]]
    assert "trojan" in names
    assert "malware" in names
    assert "phishing" in names
    assert "ransomware" in names
    # Top 5 cap means 6th category 'spyware' goes into 'other'
    assert "other" in names
    assert len(res["categories"]) == 6  # 5 top + 'other'

    # Check percentages sum to 100% approximately
    total_pct = sum(c["pct"] for c in res["categories"])
    assert 99.0 <= total_pct <= 101.0


def test_compute_scan_activity_counts_and_detection_rate():
    now = datetime(2026, 8, 13, 12, 0, 0, tzinfo=timezone.utc)

    scans = [
        # Today (Aug 13): 2 total (1 threat, 1 clean)
        {
            "created_at": "2026-08-13T10:00:00Z",
            "vt_status": "found",
            "vt_detections": 5,
            "vt_raw": {"verdict": "MALICIOUS"},
        },
        {
            "created_at": "2026-08-13T11:00:00Z",
            "vt_status": "found",
            "vt_detections": 0,
            "vt_raw": {"verdict": "CLEAN"},
        },
        # Yesterday (Aug 12): 1 clean
        {
            "created_at": "2026-08-12T09:00:00Z",
            "vt_status": "found",
            "vt_detections": 0,
            "vt_raw": {"verdict": "CLEAN"},
        },
        # This Week (Aug 8): 1 threat
        {
            "created_at": "2026-08-08T14:00:00Z",
            "vt_status": "found",
            "vt_detections": 3,
            "vt_raw": {"verdict": "MALICIOUS"},
        },
        # Previous Week (Aug 5): 2 total (2 clean)
        {
            "created_at": "2026-08-05T10:00:00Z",
            "vt_status": "found",
            "vt_detections": 0,
            "vt_raw": {"verdict": "CLEAN"},
        },
        {
            "created_at": "2026-08-05T11:00:00Z",
            "vt_status": "found",
            "vt_detections": 0,
            "vt_raw": {"verdict": "CLEAN"},
        },
        # This Month (July 20): 1 clean
        {
            "created_at": "2026-07-20T10:00:00Z",
            "vt_status": "found",
            "vt_detections": 0,
            "vt_raw": {"verdict": "CLEAN"},
        },
    ]

    act = compute_scan_activity(scans, now=now)

    # Today: 2 today vs 1 yesterday -> +100%
    assert act["today"]["count"] == 2
    assert act["today"]["trend_pct"] == 100.0

    # This Week (Aug 7 to Aug 13): 4 total (Aug 13 x2, Aug 12 x1, Aug 8 x1)
    assert act["this_week"]["count"] == 4
    # Previous Week (July 31 to Aug 6): 2 total (Aug 5 x2)
    assert act["this_week"]["trend_pct"] == 100.0

    # Detection Rate for this week: 2 threats / 4 total scans = 50.0%
    assert act["detection_rate"]["pct"] == 50.0


def test_dashboard_stats_endpoint():
    mock_scans = [
        {
            "id": "scan-1",
            "file_name": "malware.exe",
            "vt_status": "found",
            "vt_detections": 10,
            "vt_total_engines": 70,
            "vt_raw": {"verdict": "MALICIOUS", "threat_categories": ["trojan"]},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    ]

    mock_execute = MagicMock()
    mock_execute.execute.return_value.data = mock_scans

    mock_db = MagicMock()
    mock_user_resp = MagicMock()
    mock_user_resp.user.id = "test-user-id"
    mock_db.auth.get_user.return_value = mock_user_resp
    mock_db.table.return_value.select.return_value.eq.return_value.gte.return_value.order.return_value = mock_execute
    mock_db.table.return_value.select.return_value.eq.return_value.order.return_value.limit.return_value = mock_execute

    with patch("dependencies.auth.get_supabase_client", return_value=mock_db):
        response = client.get("/dashboard/stats", headers={"Authorization": "Bearer mock_test_token"})

        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "clean" in data
        assert "suspicious" in data
        assert "threats" in data
        assert "not_found" in data
        assert "recent_scans" in data
        assert "top_threat_categories" in data
        assert "scan_activity" in data
        assert isinstance(data["top_threat_categories"]["categories"], list)
        assert "today" in data["scan_activity"]
        assert "detection_rate" in data["scan_activity"]

