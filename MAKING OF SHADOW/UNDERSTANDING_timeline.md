# UNDERSTANDING: Timeline Generator

## 1. WHAT WAS BUILT
* Built a deterministic **Timeline Generator** (`TimelineGenerator`) for the SHADOW Report Engine.
* It constructs a step-by-step chronological timeline of the **SHADOW investigation workflow** (from submission to report generation) without using AI or external API calls.

## 2. HOW IT WORKS (STEP BY STEP)
1. **Read Investigation Context**: The generator inspects the normalized investigation object (indicator type, submitter info, timestamps, risk score, confidence rating, recommendation).
2. **Build Sequential Workflow Events**:
   * **Step 1 (Submission)**: Records when the target was submitted with a type-specific description (File, Hash, URL, Domain, IP).
   * **Step 2 (Historical Lookup - Optional)**: Adds a first-seen event if historical threat intelligence dates exist.
   * **Step 3 (Threat Intelligence)**: Logs provider query completion and engine detection count.
   * **Step 4 (Risk Engine)**: Records calculated Risk Score, Verdict, and Severity.
   * **Step 5 (Confidence Engine)**: Records Confidence Score and Confidence Level.
   * **Step 6 (Recommendation Engine)**: Logs recommended security actions.
   * **Step 7 (Report Engine Assembly)**: Logs report compilation completion.
3. **Format Timestamps**: Converts epoch numbers or ISO timestamps into human-readable UTC strings (`YYYY-MM-DD HH:MM:SS UTC`). If unavailable, sets timestamp to `"Timestamp Not Available"`.
4. **Number & Output**: Assigns sequential step numbers (`step: 1`, `step: 2`, ...) and attaches the array to `timeline` inside `ReportSchema`.

## 3. FILES CHANGED / CREATED
* `backend/services/report_engine/generators/timeline.py`: Created the step-by-step investigation timeline generator logic.
* `backend/services/report_engine/report_engine.py`: Connected `TimelineGenerator` so `timeline` is populated automatically.
* `backend/services/report_engine/generators/__init__.py`: Exported `TimelineGenerator`.

## 4. IMPORTANT DECISIONS MADE
* **Investigation Workflow Focus**: Represents the system's investigation pipeline steps rather than attacker malware execution timeline.
* **Zero Fake Timestamps**: If a timestamp is missing, it explicitly uses `"Timestamp Not Available"` instead of guessing or generating fake timestamps.
* **Type-Aware Descriptions**: Customizes step 1 descriptions based on target indicator type (File, Hash, URL, Domain, IP).

## 5. WHAT'S NOT DONE YET / LIMITATIONS
* **Attacker Execution Timeline (V2)**: Sandbox detonation/behavioral execution timelines (e.g. process tree creation timestamps) are reserved for V2 technical analysis modules.

## 6. HOW TO TEST THIS
1. Open a terminal in the `backend` folder.
2. Run this test command:
   ```bash
   venv\Scripts\python -c "from services.report_engine import ReportEngine; import json; engine = ReportEngine(); print(json.dumps(engine.build_report_schema({'indicator_type': 'file', 'file_name': 'sample.exe', 'created_at': 1784961864, 'verdict': 'clean'}).model_dump()['timeline'], indent=2))"
   ```
3. Verify it outputs numbered step objects with clean UTC timestamps and descriptions.
