import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_shadow_ai_real_completion_not_fallback():
    response = client.post("/api/shadow-ai/chat", json={
        "message": "Greetings, state your identity."
    })
    assert response.status_code == 200
    data = response.json()
    assert "reply" in data
    reply_text = data["reply"]
    # Ensure response is NOT the fallback error string
    assert "trouble responding right now" not in reply_text
    assert len(reply_text) > 0
