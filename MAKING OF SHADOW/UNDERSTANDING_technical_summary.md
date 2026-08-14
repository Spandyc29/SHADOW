# UNDERSTANDING: Technical Summary Generator

## 1. WHAT WAS BUILT
* Built a deterministic **Technical Summary Generator** (`TechnicalSummaryGenerator`) for the SHADOW Report Engine.
* It organizes raw/normalized threat intelligence data into structured key-value technical sections (General Information, Hashes, File Information, Network Information, WHOIS, DNS, Threat Intelligence, Certificates, Behavior) for SOC and DFIR analysts without calling AI or external APIs.

## 2. HOW IT WORKS (STEP BY STEP)
1. **Extract Categorized Metadata**: The generator reads investigation properties from the normalized dictionary (Target type, Hashes, Network info, WHOIS records, DNS entries, Threat engine scores, SSL Certificates).
2. **Build Candidate Sections**:
   * **General Information**: Indicator Type, Target Name, Scan Timestamp, Verdict, Risk Level, Confidence.
   * **Hashes**: MD5, SHA1, SHA256, SHA512.
   * **File Information**: File Name, File Size, MIME Type, File Type, Extension.
   * **Network Information**: IP Address, Domain, URL, ASN, ISP, Country, Reverse DNS.
   * **WHOIS Information**: Registrar, Registration Date, Expiration Date, Name Servers.
   * **DNS Information**: A Records, AAAA Records, MX Records, NS Records, TXT Records.
   * **Threat Intelligence**: Detection Ratio, Reputation Score, Tags, Categories.
   * **Certificates**: JARM Hash, HTTPS Certificate, SSL Information.
   * **Behavior**: Behavioral Indicators, Attack Vectors, IOC Count.
3. **Filter & Omit Empty Sections**: Using `add_section_if_valid()`, any section that lacks meaningful data is completely omitted from the dictionary. Individual missing fields in active sections display `"Not Available"`.
4. **Attach to Report**: The `ReportEngine` attaches the result into the `technical_summary` field of the `ReportSchema`.

## 3. FILES CHANGED / CREATED
* `backend/services/report_engine/generators/technical_summary.py`: Implemented section organization and filtering logic.
* `backend/services/report_engine/report_engine.py`: Connected `TechnicalSummaryGenerator` so `technical_summary` is populated automatically.
* `backend/services/report_engine/generators/__init__.py`: Exported `TechnicalSummaryGenerator`.

## 4. IMPORTANT DECISIONS MADE
* **Strict Section Omission**: Sections with zero relevant data are completely dropped to prevent visual clutter for DFIR responders.
* **No Paragraphs / Key-Value Only**: Structured strictly as dictionary key-values to support automated SIEM indexing and SOC tab views.
* **Deterministic Rules (Zero AI)**: Pure Python filtering logic guarantees zero latency and no external API costs.

## 5. WHAT'S NOT DONE YET / LIMITATIONS
* **HTML Table Cards**: The HTML renderer does not yet display the Technical Summary in accordion/tabbed UI cards (currently stored in JSON schema output).

## 6. HOW TO TEST THIS
1. Open a terminal in the `backend` folder.
2. Run this test command:
   ```bash
   venv\Scripts\python -c "from services.report_engine import ReportEngine; import json; engine = ReportEngine(); print(json.dumps(engine.build_report_schema({'indicator_type': 'domain', 'domain': 'malicious-domain.com', 'resolved_ip': '192.168.1.1', 'whois': {'registrar': 'GoDaddy'}}).model_dump()['technical_summary'], indent=2))"
   ```
3. Verify it outputs categorized technical sections without empty sections.
