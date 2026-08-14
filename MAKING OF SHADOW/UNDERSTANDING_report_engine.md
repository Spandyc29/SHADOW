# UNDERSTANDING: Report Engine (5W1H & Executive Summary Generator)

## 1. WHAT WAS BUILT
* Integrated the **SHADOW Report Engine** directly into the core investigation pipeline (`AnalysisPipeline`).
* Implemented the **Executive Summary Generator** (`ExecutiveSummaryGenerator`), which produces a deterministic, rule-based SOC-style paragraph and bullet points for every investigation without using AI.
* Every analysis (File, Hash, URL, Domain, IP) now automatically includes structured `executive_summary` and `fivew1h` fields inside the `ReportSchema`.
* Created a dedicated API endpoint (`POST /reports/render`) to convert structured report data on-demand into styled HTML or JSON pages.

## 2. HOW IT WORKS (STEP BY STEP)
1. **Analysis Pipeline Execution**:
   * Analyzer → Threat Intelligence → Normalizer → Risk Engine → Confidence Engine → Recommendation Engine.
2. **Report Generation**:
   * Right after the Recommendation Engine finishes, `AnalysisPipeline.run()` calls `ReportEngine().build_report_schema(analysis)`.
   * `FiveW1HGenerator` sorts investigation findings into **Who, What, Where, When, Why, How**.
   * `ExecutiveSummaryGenerator` builds a SOC-style summary paragraph and bullet-point key findings specific to the indicator type (File, Hash, URL, Domain, IP).
   * The output is stored under the `"report"` key in the API response dictionary.
3. **On-Demand Presentation Rendering**:
   * When a client calls `POST /reports/render` with an `analysis_result` and format (`"html"` or `"json"`), `ReportEngine.generate()` delegates to `HTMLRenderer` or `JSONRenderer` and returns the webpage HTML or raw JSON.

## 3. FILES CHANGED / CREATED
* `backend/services/report_engine/generators/executive_summary.py`: Rule-based Executive Summary generator for File, Hash, URL, Domain, IP.
* `backend/services/report_engine/report_engine.py`: Updated to automatically populate `executive_summary` in every `ReportSchema`.
* `backend/services/analysis_pipeline.py`: Added Step 4 (`ReportEngine`) to populate `"report"` in every analysis result.
* `backend/services/report_engine/generators/fivew1h.py`: Transforms pipeline results into type-aware 5W1H schema buckets.
* `backend/services/report_engine/models/report_schema.py`: Pydantic models for Report Data & 5W1H & Executive Summary structures.
* `backend/services/report_engine/renderers/html_renderer.py`: Generates dark-themed, styled HTML report webpage.
* `backend/routers/reports.py`: FastAPI router defining `POST /reports/render`.
* `backend/main.py`: Included `reports.router` in the FastAPI app.

## 4. IMPORTANT DECISIONS MADE
* **Deterministic Rule-Based Logic (NO AI)**: Summaries are constructed from structured threat intelligence rules, verdicts, and engine metrics without calling external LLM/AI APIs.
* **Type Awareness**: Custom summary paragraphs and key findings adapted specifically for File, Hash, URL, Domain, and IP targets.
* **Structured Data in API Responses**: API responses contain JSON-structured `executive_summary` and `fivew1h` objects.

## 5. WHAT'S NOT DONE YET / LIMITATIONS
* **PDF Renderer**: `PDFRenderer` is currently a placeholder and returns HTTP 501.
* **IOC / Timeline Generators**: Timeline and technical summary generators return placeholder schemas until future updates.

## 6. HOW TO TEST THIS
1. Run pytest suite:
   ```bash
   venv\Scripts\python -m pytest
   ```
2. Test `POST /reports/render` via HTTP POST:
   ```bash
   curl -X POST http://localhost:8000/reports/render -H "Content-Type: application/json" -d '{"analysis_result": {"indicator": "1.1.1.1", "indicator_type": "ip", "verdict": "clean"}, "format": "json"}'
   ```
