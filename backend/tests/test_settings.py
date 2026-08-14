from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from main import app
from routers.settings import mask_key

client = TestClient(app)


def test_mask_key_helper():
    # Empty / None
    assert mask_key(None) is None
    assert mask_key("") is None
    assert mask_key("   ") is None

    # Short keys (<= 8 chars)
    assert mask_key("12345") == "••••••••"

    # Standard API keys
    assert mask_key("gsk_1234567890abcdef") == "gsk_••••••••cdef"
    assert mask_key("ec465d8f905cbf0d18422081469c003cba9e00d8760c4dfcdb9e1436a78f8fab") == "ec46••••••••8fab"


def test_get_api_keys_endpoint_masked():
    mock_row = {
        "user_id": "default",
        "groq_api_key": "gsk_1234567890abcdef",
        "vt_api_key": "ec465d8f905cbf0d18422081469c003cba9e00d8760c4dfcdb9e1436a78f8fab",
    }
    mock_execute = MagicMock()
    mock_execute.execute.return_value.data = [mock_row]

    mock_db = MagicMock()
    mock_user_resp = MagicMock()
    mock_user_resp.user.id = "default"
    mock_db.auth.get_user.return_value = mock_user_resp
    mock_db.table.return_value.select.return_value.eq.return_value = mock_execute

    with patch("dependencies.auth.get_supabase_client", return_value=mock_db):
        response = client.get("/settings/api-keys", headers={"Authorization": "Bearer mock_test_token"})
        assert response.status_code == 200
        data = response.json()
        assert data["has_groq_key"] is True
        assert data["has_vt_key"] is True
        assert "••••••••" in data["groq_api_key"]
        assert "••••••••" in data["vt_api_key"]


def test_update_api_keys_endpoint():
    mock_execute = MagicMock()
    mock_execute.execute.return_value.data = [{"user_id": "default", "groq_api_key": "gsk_test", "vt_api_key": "vt_test"}]

    mock_db = MagicMock()
    mock_user_resp = MagicMock()
    mock_user_resp.user.id = "default"
    mock_db.auth.get_user.return_value = mock_user_resp
    mock_db.table.return_value.upsert.return_value = mock_execute

    with patch("dependencies.auth.get_supabase_client", return_value=mock_db):
        payload = {"groq_api_key": "gsk_new12345678", "vt_api_key": "vt_new12345678"}
        response = client.put("/settings/api-keys", json=payload, headers={"Authorization": "Bearer mock_test_token"})

        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "API keys updated successfully"
        assert data["has_groq_key"] is True
        assert data["has_vt_key"] is True


def test_bulk_export_json_and_csv():
    mock_scans = [
        {
            "id": "scan-101",
            "file_name": "sample.exe",
            "analysis_type": "file",
            "vt_status": "found",
            "vt_detections": 0,
            "vt_total_engines": 75,
            "md5": "md5val",
            "sha256": "sha256val",
            "created_at": "2026-08-13T10:00:00Z",
        }
    ]

    mock_execute = MagicMock()
    mock_execute.execute.return_value.data = mock_scans

    mock_db = MagicMock()
    mock_user_resp = MagicMock()
    mock_user_resp.user.id = "default"
    mock_db.auth.get_user.return_value = mock_user_resp
    mock_db.table.return_value.select.return_value.eq.return_value.order.return_value = mock_execute

    with patch("dependencies.auth.get_supabase_client", return_value=mock_db):
        # Test JSON Bulk Export
        json_resp = client.get("/scans/export/bulk?format=json", headers={"Authorization": "Bearer mock_test_token"})
        assert json_resp.status_code == 200
        assert json_resp.headers["content-disposition"] == "attachment; filename=scan_history_export.json"
        json_data = json_resp.json()
        assert "scans" in json_data
        assert len(json_data["scans"]) == 1

        # Test CSV Bulk Export
        csv_resp = client.get("/scans/export/bulk?format=csv", headers={"Authorization": "Bearer mock_test_token"})
        assert csv_resp.status_code == 200
        assert csv_resp.headers["content-disposition"] == "attachment; filename=scan_history_export.csv"
        csv_text = csv_resp.text
        assert "ID,File Name,Analysis Type" in csv_text
        assert "scan-101,sample.exe,file" in csv_text
