# UNDERSTANDING: Executive Summary Generator

## 1. WHAT WAS BUILT
* Built a rule-based **Executive Summary Generator** (`ExecutiveSummaryGenerator`) for the SHADOW Report Engine.
* It automatically writes a clear, plain-English summary paragraph and a list of key findings for every security scan (File, Hash, URL, Domain, IP) without using any AI models.

## 2. HOW IT WORKS (STEP BY STEP)
1. **Receive Analysis Data**: The generator receives the completed security scan results after risk and confidence scores are calculated.
2. **Detect Target Type**: It identifies whether the target is a File, Hash, URL, Domain, or IP address.
3. **Draft Summary Paragraph**: It fills in a structured story template:
   * **Sentence 1**: Identifies the target name and type (e.g. "The submitted Windows Executable artifact 'sample.exe' was analyzed...").
   * **Sentence 2**: States the final verdict, risk score, and confidence level (e.g. "Classified as Suspicious with a Medium Risk Score (65/100)...").
   * **Sentence 3**: Highlights threat intelligence findings (e.g. "Identified 3 security engine flags and behavioral tags...").
   * **Sentence 4**: Gives clear analyst advice (e.g. "Analyst review and host isolation are recommended...").
4. **Compile Key Findings**: It creates a bulleted list of essential highlights (Verdict, Risk Level, Confidence, Engine Detections, File Type/Domain/IP details).
5. **Attach to Report**: The `ReportEngine` attaches the result into the `executive_summary` field of the `ReportSchema`.

## 3. FILES CHANGED / CREATED
* `backend/services/report_engine/generators/executive_summary.py`: Built the generator logic to format summaries and key findings for all 5 indicator types.
* `backend/services/report_engine/report_engine.py`: Connected the new generator so `executive_summary` is populated automatically.
* `backend/services/report_engine/generators/__init__.py`: Package file exporting `ExecutiveSummaryGenerator`.

## 4. IMPORTANT DECISIONS MADE
* **Zero AI / Deterministic Logic**: Used pure Python rule templates instead of AI calls so summary generation is instant, free, and 100% predictable.
* **Type-Specific Templates**: Created tailored paragraph sentences for Files, Hashes, URLs, Domains, and IPs instead of a single generic message.
* **Safe Number Parsing**: Handled cases where `risk_score` or `confidence_score` might be missing or `None` to prevent crash errors.

## 5. WHAT'S NOT DONE YET / LIMITATIONS
* **HTML Rendering Card**: The HTML renderer does not yet display the executive summary block at the top of the HTML webpage (it is currently inside the JSON schema).
* **Multi-lingual Support**: Summaries are currently generated in English only.

## 6. HOW TO TEST THIS
1. Open a terminal in the `backend` folder.
2. Run this test command:
   ```bash
   venv\Scripts\python -c "from services.report_engine import ReportEngine; import json; engine = ReportEngine(); print(json.dumps(engine.build_report_schema({'indicator_type': 'hash', 'indicator': '6eea89b0b1ede5189d40aa52293be374', 'associated_names': ['Rto eChallan pm13.apk'], 'verdict': 'suspicious', 'risk_score': 65}).model_dump()['executive_summary'], indent=2))"
   ```
3. Check if it outputs a clear `summary_text` paragraph and `key_findings` array.
