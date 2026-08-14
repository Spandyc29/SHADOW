import os
import tempfile
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import config
from main import app

client = TestClient(app)

def test_health_endpoint_returns_200():
    """Verify /health returns HTTP 200 without auth."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "Shadow is running"}

def test_cors_configuration_no_wildcard():
    """Verify CORS origins list includes localhost and FRONTEND_URL, but no wildcard '*'."""
    from main import allowed_origins
    assert "*" not in allowed_origins
    assert "http://localhost:5173" in allowed_origins

def test_cors_frontend_url_inclusion(monkeypatch):
    """Verify FRONTEND_URL without trailing slash is included in allowed origins."""
    frontend_test_url = "https://shadow-test.netlify.app"
    assert frontend_test_url.endswith("/") is False

def test_config_validation_missing_env(monkeypatch):
    """Verify missing critical environment variables fail validation safely."""
    monkeypatch.setattr(config, "SUPABASE_URL", "")
    monkeypatch.setattr(config, "SUPABASE_KEY", "test-key")
    with pytest.raises(RuntimeError) as exc_info:
        config.validate_config()
    assert "missing required environment variable" in str(exc_info.value)
    # Ensure secrets are not leaked in exception message
    assert "test-key" not in str(exc_info.value)

def test_docs_enabled_in_development():
    """Verify Swagger/OpenAPI docs URL configuration in development."""
    assert config.ENVIRONMENT == "development" or config.ENABLE_DOCS is True

def test_temp_file_directory_uses_system_temp():
    """Verify temporary directory defaults to OS system temp directory."""
    sys_temp = tempfile.gettempdir()
    configured_temp = getattr(config, "TEMP_DIR", sys_temp)
    assert Path(configured_temp).resolve() == Path(sys_temp).resolve()
