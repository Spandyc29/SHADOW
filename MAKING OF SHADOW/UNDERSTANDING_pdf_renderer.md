# UNDERSTANDING: PDF Renderer

## 1. WHAT WAS BUILT
* Built a professional, enterprise-grade **PDF Renderer** (`PDFRenderer`) using `ReportLab` for the SHADOW Report Engine.
* It renders a complete, multi-page SOC Cyber Threat Analysis PDF document directly from a `ReportSchema` without calling AI or external APIs.

## 2. HOW IT WORKS (STEP BY STEP)
1. **Receive `ReportSchema`**: The renderer accepts the unified schema containing `metadata`, `executive_summary`, `fivew1h`, `ioc_summary`, `timeline`, and `technical_summary`.
2. **Build Document Layout**:
   * **Title Header Block**: Report ID, Generated Time, Target Name, Target Type, Engine Version.
   * **1. Executive Summary**: Summary paragraph and bulleted Key Findings.
   * **2. 5W1H Investigation Framework**: WHO, WHAT, WHERE, WHEN, WHY, HOW blocks formatted in key-value tables.
   * **3. IOC Summary**: Auto-wrapping table with `Type`, `Value`, `Source` columns.
   * **4. Investigation Timeline**: Chronological table with `Step`, `Title & Timestamp`, `Description`.
   * **5. Technical Summary**: Section tables for General Info, Hashes, Network, WHOIS, DNS, Threat Intel, Certificates, Behavior (omitting empty sections).
3. **Two-Pass Page Numbering (`NumberedCanvas`)**: Computes total pages dynamically to render running top headers on page 2+ and footer `"Page X of Y"` lines across all pages.
4. **Output PDF Bytes**: Compiles all flowables into a PDF buffer and returns raw `bytes`.

## 3. FILES CHANGED / CREATED
* `backend/services/report_engine/renderers/pdf_renderer.py`: Implemented ReportLab canvas, table styles, wrapping, and flowable assembly.
* `backend/services/report_engine/report_engine.py`: Connected `pdf_renderer` so `generate(..., output_format="pdf")` returns PDF bytes.
* `backend/routers/reports.py`: Updated `POST /reports/render` to return `application/pdf` responses.
* `backend/tests/test_reports_router.py`: Updated test suite to verify `POST /reports/render` with `format="pdf"`.

## 4. IMPORTANT DECISIONS MADE
* **Pure ReportLab Rendering**: Uses native ReportLab flowables and tables for maximum speed, zero browser/headless dependencies, and exact pixel alignment.
* **Auto-Wrapping Cells**: Long SHA256 hashes, URLs, and file paths are wrapped using `Paragraph` flowables inside table cells to prevent overflow.
* **Pure Presentation Component**: Operates 100% downstream of data generation; never mutates or calculates investigation values.

## 5. WHAT'S NOT DONE YET / LIMITATIONS
* **Custom Logo Upload**: Logo embedding in PDF headers is reserved for enterprise branding settings.

## 6. HOW TO TEST THIS
1. Open a terminal in the `backend` folder.
2. Run this test command:
   ```bash
   venv\Scripts\python -c "from services.report_engine import ReportEngine; engine = ReportEngine(); pdf = engine.generate({'indicator_type': 'file', 'file_name': 'sample.exe'}, 'pdf'); print(f'PDF Generated: {len(pdf)} bytes, Header: {pdf[:4]}')"
   ```
3. Test via API endpoint:
   ```bash
   curl -X POST http://localhost:8000/reports/render -H "Content-Type: application/json" -d '{"analysis_result": {"indicator": "1.1.1.1", "indicator_type": "ip"}, "format": "pdf"}' --output shadow_report.pdf
   ```
