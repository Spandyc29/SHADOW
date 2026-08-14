from fastapi.testclient import TestClient
from main import app
from services.analysis_pipeline import AnalysisPipeline

client = TestClient(app)


def test_reports_render_html():
    analysis = AnalysisPipeline.run({
        "indicator": "1.1.1.1",
        "indicator_type": "ip",
        "status": "found",
        "detections": 5,
        "total_engines": 60,
    })

    assert "report" in analysis

    response = client.post("/reports/render", json={
        "analysis_result": analysis,
        "format": "html"
    }, headers={"x-guest-mode": "true"})

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "<!DOCTYPE html>" in response.text
    assert "SHADOW Security Report" in response.text


def test_reports_render_json():
    analysis = AnalysisPipeline.run({
        "indicator": "example.com",
        "indicator_type": "domain",
        "status": "found",
        "detections": 0,
        "total_engines": 50,
    })

    response = client.post("/reports/render", json={
        "analysis_result": analysis,
        "format": "json"
    }, headers={"x-guest-mode": "true"})

    assert response.status_code == 200
    res_data = response.json()
    assert "metadata" in res_data
    assert "fivew1h" in res_data


def test_reports_render_pdf():
    analysis = AnalysisPipeline.run({
        "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "indicator_type": "hash",
    })

    response = client.post("/reports/render", json={
        "analysis_result": analysis,
        "format": "pdf"
    }, headers={"x-guest-mode": "true"})

    assert response.status_code == 200
    assert "application/pdf" in response.headers["content-type"]
    assert response.content.startswith(b"%PDF")
