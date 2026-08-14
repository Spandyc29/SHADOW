# UNDERSTANDING: IOC Summary Generator

## 1. WHAT WAS BUILT
* Built a deterministic **IOC Summary Generator** (`IOCSummaryGenerator`) for the SHADOW Report Engine.
* It extracts, normalizes, classifies, deduplicates, and sorts all Indicators of Compromise (IOCs) from an investigation without using AI or external API calls.

## 2. HOW IT WORKS (STEP BY STEP)
1. **Extract Raw Indicators**: The generator scans the investigation object for all possible indicators (User submissions, File hashes, Resolved IPs/Domains, File Paths, Behavioral registry keys/mutexes).
2. **Classify IOC Type**: It uses regex patterns to automatically recognize the IOC category (`SHA256`, `SHA1`, `MD5`, `SHA512`, `IP`, `Domain`, `URL`, `Email`, `File Name`, `File Path`, `Registry Key`, `Mutex`, `Certificate`).
3. **Normalize Values**: Hashes and domains are converted to lowercase strings, and extra whitespace is removed.
4. **Deduplicate & Attach Source**: It removes duplicate values while tracking the origin of each IOC (e.g. `"User Submission"`, `"File Metadata"`, `"DNS"`, `"Threat Intelligence"`, `"Behavioral Indicators"`).
5. **Sort by Type Preference**: Entries are grouped and sorted in standard SOC order (`SHA256` → `SHA1` → `MD5` → `IP` → `Domain` → `URL` → `Email` → `File Name` → `File Path` → `Other`).
6. **Attach to Report**: The `ReportEngine` attaches the result into the `ioc_summary` field of the `ReportSchema`.

## 3. FILES CHANGED / CREATED
* `backend/services/report_engine/generators/ioc_summary.py`: Built the extraction, normalization, deduplication, and sorting generator logic.
* `backend/services/report_engine/report_engine.py`: Connected `IOCSummaryGenerator` so `ioc_summary` is populated automatically.
* `backend/services/report_engine/generators/__init__.py`: Exported `IOCSummaryGenerator`.

## 4. IMPORTANT DECISIONS MADE
* **Zero AI / Deterministic Processing**: Uses regular expressions and string rules to guarantee zero latency and no AI cost.
* **Insertion-Order Preserved Deduplication**: Uses set tracking so the first instance of an IOC defines its origin source.
* **Preferred Sorting Hierarchy**: Groups hashes first, followed by network infrastructure (IPs/Domains/URLs), and endpoint artifacts (File Names/Paths).

## 5. WHAT'S NOT DONE YET / LIMITATIONS
* **HTML Table Rendering**: The HTML renderer does not yet display the IOC list in a visual web table (it is currently inside the JSON schema output).
* **Extended Behavioral Sub-objects**: Advanced malware sandbox artifacts (like dynamic API call hooks) will be integrated in V2.

## 6. HOW TO TEST THIS
1. Open a terminal in the `backend` folder.
2. Run this test command:
   ```bash
   venv\Scripts\python -c "from services.report_engine import ReportEngine; import json; engine = ReportEngine(); print(json.dumps(engine.build_report_schema({'indicator_type': 'domain', 'domain': 'MALICIOUS-DOMAIN.COM', 'resolved_ip': '192.168.1.1'}).model_dump()['ioc_summary'], indent=2))"
   ```
3. Check if it outputs a clean, sorted, deduplicated `iocs` list with `type`, `value`, and `source`.
