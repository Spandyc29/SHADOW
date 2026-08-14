# SHADOW — 5W1H Escalation Report Engine
### Architecture, Planning & Implementation Reference

**Version:** 1.0
**Status:** Planning Complete — Ready for Implementation
**Owner:** Spandan Chavan
**Last Updated:** 07 Aug 2026

---

## 1. Purpose

SOC L1 analysts investigate indicators (hash, IP, domain, URL, file) and must escalate
findings to L2 with a clear, structured summary. Today this is manual and time-consuming.

**Goal:** SHADOW automatically converts raw scan/investigation data into a structured,
readable **5W1H escalation report** — reducing documentation overhead and ensuring
consistent, complete handoffs from L1 to L2.

This is not just a "PDF export" feature. It is SHADOW's core differentiator: turning a
**scanner** into an **investigation platform**.

---

## 2. Where This Fits in SHADOW's Architecture

```
Indicator (File / Hash / URL / Domain / IP)
        ↓
Threat Intelligence (VirusTotal, etc.)
        ↓
Normalizer            ← converts all indicator types into ONE common object shape
        ↓
Risk Engine            ← calculates risk_score, severity
        ↓
Confidence Engine       ← calculates confidence_score
        ↓
Recommendation Engine   ← calculates recommended_action, priority
        ↓
SHADOW Report Engine    ← NEW — central hub for all report output types
    ├── 5W1H Generator          ✅ BUILD NOW
    ├── PDF Renderer            ✅ BUILD NOW
    ├── JSON Renderer           🔜 later
    ├── Executive Summary       🔜 later
    ├── IOC Summary             🔜 later
    ├── Timeline                🔜 later
    └── Technical Findings      🔜 later
        ↓
Universal Report UI (existing dashboard + new Report Preview screen)
        ↓
(Optional, future) Shadow AI    ← consumes Report Engine output, adds natural-language polish
```

**Key principle:** Report Engine is 100% deterministic and works fully without AI.
AI is an optional enhancement layer on top, never a dependency.

---

## 3. Why a Central Report Engine (not a standalone 5W1H generator)

- Matches existing pattern in SHADOW: Risk Engine, Confidence Engine, Recommendation
  Engine are all single-purpose modules that consume the normalized object. Report
  Engine follows the same contract.
- Avoids duplicate parsing logic if more report types (Executive Summary, Timeline,
  etc.) are added later — they all plug into the same input.
- Clean seam for future AI integration — AI wraps Report Engine output, never touches
  core logic.

**Responsibilities INSIDE Report Engine:**
- All sub-generators (5W1H, and future: Executive Summary, IOC Summary, Timeline, etc.)
- Format renderers (PDF, JSON, HTML)
- Transforming normalized object → report-shaped data
- Report templates/layout definitions

**Responsibilities OUTSIDE Report Engine (not its job):**
- Fetching threat intel (VT calls) — happens before Normalizer
- Calculating risk/confidence scores — Report Engine only reads these, never computes them
- AI/LLM calls — Shadow AI is a separate consumer layer
- Actual screen rendering — Universal Report UI owns that; Report Engine returns data/HTML

---

## 4. Implementation Scope — V1 (build now)

To avoid scope creep, V1 includes ONLY:
- [x] 5W1H Generator
- [x] PDF Renderer (clean/light theme, print-friendly)
- [x] In-app Preview screen (dark theme, matches dashboard)
- [x] Edit Mode (manual override per section)

**Explicitly NOT in V1** (placeholder folders only, empty stub functions):
- Executive Summary generator
- IOC Summary generator
- Timeline generator
- Technical Findings generator
- JSON Renderer
- Shadow AI narrative summary

```
ReportEngine/
  ├── generators/
  │   ├── fiveWOneH.js          ← BUILD NOW
  │   ├── executiveSummary.js   ← stub: return "not implemented"
  │   ├── iocSummary.js         ← stub
  │   └── timeline.js           ← stub
  ├── renderers/
  │   ├── pdfRenderer.js        ← BUILD NOW
  │   └── jsonRenderer.js       ← stub
```

---

## 5. 5W1H Field Mapping (source: normalized object)

This mapping is **type-agnostic** — same generator works for hash, IP, domain, URL,
and file, because they all resolve to the same normalized object shape. Only the
"Where" field is conditionally filled per indicator type.

| 5W1H | Field | Source Data | Fallback if missing |
|------|-------|--------------|----------------------|
| **WHAT** | What happened | `verdict` + `threat_label` + `indicator_type` | "Classification unavailable" |
| **WHO** | What/who is involved | `associated_names` / `indicator_value` | Use `indicator_value` directly |
| **WHEN** | Timing | `first_seen`, `last_analysis` | Scan timestamp |
| **WHERE** | Origin/context | IP → `geo_location`; Domain → `registrar`; URL → `host`; File/Hash → `source` (e.g. "Manual Upload via SHADOW") | "Not applicable for this indicator type" |
| **WHY** | Reasoning | `risk_factors[]` + `confidence_factors[]` | "No specific factors flagged" |
| **HOW** | Behavior/mechanism | `tags[]` + `detection_ratio` (e.g. 3/65) | "No behavior tags available" |

Plus a closing block:
- **Recommended Action** — from `recommended_action` + `priority` (Recommendation Engine output)

---

## 6. Normalized Object — Expected Shape (input to Report Engine)

```json
{
  "indicator_type": "hash | ip | domain | url | file",
  "indicator_value": "6eea89b0b1ede5189d40aa52293be374",
  "verdict": "suspicious | malicious | clean",
  "severity": "low | medium | high",
  "risk_score": 38,
  "risk_max": 90,
  "confidence_score": 65,
  "confidence_max": 100,
  "risk_factors": ["3 security engines flagged...", "..."],
  "confidence_factors": ["65 usable engines contributed...", "..."],
  "threat_label": "trojan.corrupted",
  "threat_category": "trojan",
  "tags": ["apk", "android", "obfuscated", "telephony"],
  "associated_names": ["Rto eChallan pm13.apk"],
  "first_seen": "2026-07-25T12:14:24Z",
  "last_analysis": "2026-07-25T12:14:24Z",
  "detection_ratio": "3/65",
  "recommended_action": "Investigate & Monitor",
  "priority": "Medium",
  "type_specific": {
    "geo_location": null,
    "registrar": null,
    "host": null,
    "file_type": "Android APK",
    "file_size": "4.34 MB"
  }
}
```

> If SHADOW's current Normalizer doesn't yet produce this exact shape, adapt field
> names — but keep the principle: ONE shape, all indicator types map into it.

---

## 7. UI Flow (end to end)

```
1. User views scan result (existing dashboard)
        ↓
2. Clicks "Generate 5W1H Report" button
        ↓
3. Report Preview screen opens (in-app, dark theme, matches dashboard style)
        ↓
4. User can [Edit] any section inline
        ↓
5. User clicks [Export as PDF] or [Copy Summary]
        ↓
6. PDF generated (clean/light theme, print-optimized)
```

**Why preview-first (not direct-to-PDF):**
- Lets analyst catch missing/wrong data before exporting
- Matches real SOC tool UX patterns (e.g. ticketing systems show a draft before submit)
- Enables the Edit Mode step naturally

**Why a separate "Generate 5W1H Report" button (not reusing "Export Report"):**
- Report generation may take a moment (especially once AI summary is added later)
- Keeps user intent explicit: "Export Report" (raw data dump) vs "Generate 5W1H"
  (structured investigation narrative) are different outputs

---

## 8. In-App Preview — Layout Reference

Dark theme, card-based, matches existing SHADOW dashboard styling.

```
┌─────────────────────────────────────────────┐
│  🛡️ SHADOW — Escalation Report      [✏️ Edit]  │
│  Scan ID: 7bbd9452-...  |  Generated: [date]  │
├─────────────────────────────────────────────┤
│  📌 WHAT                                       │
│  Suspicious Android APK flagged as             │
│  trojan.corrupted with medium risk severity.   │
│                                                │
│  👤 WHO                                        │
│  Indicator: 6eea89b0b1ede... (MD5)             │
│  File: Rto eChallan pm13.apk                   │
│                                                │
│  🕐 WHEN                                       │
│  First Seen: 25 Jul 2026, 12:14 PM             │
│  Last Analysis: 25 Jul 2026, 12:14 PM          │
│                                                │
│  📍 WHERE                                      │
│  Source: Manual Upload via SHADOW              │
│                                                │
│  ❓ WHY                                        │
│  • 3 security engines flagged this indicator   │
│  • Threat intelligence classified as trojan    │
│  • Suspicious characteristics: obfuscated      │
│                                                │
│  ⚙️ HOW                                        │
│  Tags: apk, android, obfuscated, telephony     │
│  Detection: 3/65 engines                       │
├─────────────────────────────────────────────┤
│  🎯 RECOMMENDED ACTION                         │
│  Investigate & Monitor (Priority: Medium)      │
├─────────────────────────────────────────────┤
│         [ Export as PDF ]  [ Copy Summary ]    │
└─────────────────────────────────────────────┘
```

---

## 9. PDF Export — Layout Reference

Clean, light/white background, print-optimized (dark theme is bad for printing/email
attachments). Same data, different renderer.

```
================================================
  SHADOW — THREAT ESCALATION REPORT
  Scan ID: 7bbd9452-...
  Generated: 07 Aug 2026, 14:32
================================================

WHAT
Suspicious Android APK flagged as trojan.corrupted
with medium risk severity (38/90).

WHO
Indicator: 6eea89b0b1ede5189d40aa52293be374 (MD5)
Associated File: Rto eChallan pm13.apk

WHEN
First Seen: 25 Jul 2026, 12:14 PM
Last Analysis: 25 Jul 2026, 12:14 PM

WHERE
Source: Manual Upload via SHADOW

WHY
- 3 security engines flagged this indicator
- Threat intelligence classified as 'trojan.corrupted'
- Malicious classification confirmed by category: trojan
- Suspicious characteristics detected: obfuscated

HOW
Tags: apk, android, obfuscated, telephony, reflection
Detection Ratio: 3/65 engines

------------------------------------------------
RECOMMENDED ACTION: Investigate & Monitor
Priority: Medium
------------------------------------------------

Generated by SHADOW Analysis Pipeline
[⚠️ Manually reviewed & edited by analyst — if edited]
```

**Tooling options:** `jsPDF` or `react-pdf` (client-side, no backend needed).

---

## 10. Edit Mode — Behavior Spec

- Toggle button `[✏️ Edit]` on the preview screen switches each 5W1H section from
  static text to an editable `<textarea>`, pre-filled with auto-generated content.
- Each section has a **"Reset to Auto-generated"** option to undo manual edits.
- Edited state is tracked in local component state (`reportData`), not mutating the
  original normalized object — so re-generating never loses the source data.
- If any section was edited, PDF export includes a small flag:
  `⚠️ Manually reviewed & edited by [analyst]` — improves audit trust; shows the report
  isn't purely automated.

**Minimal state shape:**
```js
const [reportData, setReportData] = useState(generatedReport); // from 5W1H generator
const [isEditing, setIsEditing] = useState(false);
const [wasEdited, setWasEdited] = useState(false); // set true on any manual change
```

Export (PDF/Copy) always reads from current `reportData`, whether auto-generated or edited.

---

## 11. Type-Specific Conditional Logic (WHERE field example)

```js
function getWhereField(normalizedObj) {
  switch (normalizedObj.indicator_type) {
    case "ip":
      return normalizedObj.type_specific.geo_location || "Location unavailable";
    case "domain":
      return normalizedObj.type_specific.registrar || "Registrar unavailable";
    case "url":
      return normalizedObj.type_specific.host || "Host unavailable";
    case "hash":
    case "file":
      return "Source: Manual Upload via SHADOW";
    default:
      return "Not applicable for this indicator type";
  }
}
```

All other 5W1H fields (WHAT, WHO, WHEN, WHY, HOW) are filled identically regardless
of indicator type — only WHERE needs this branch.

---

## 12. Future Roadmap (explicitly OUT of V1 — do not build yet)

Ordered by likely future priority:

1. **Shadow AI narrative layer** — consumes Report Engine's deterministic output,
   generates a natural-language paragraph version. AI never replaces the rule-based
   engine; it's purely additive/optional.
2. **JSON Renderer** — for exporting to SIEM/ticketing systems programmatically.
3. **Executive Summary generator** — shorter, leadership-facing version of the report.
4. **IOC Summary generator** — tabular list of all IOCs across multiple related scans.
5. **Timeline generator** — visual/chronological view across multiple scans of related
   indicators (e.g. campaign tracking).
6. **Technical Findings generator** — deep technical appendix (raw VT data, entropy,
   full engine breakdown) for L2/L3 analysts who want raw evidence.
7. **Custom scoring engine** (replacing/supplementing VT-only risk scoring) — see
   separate long-term SHADOW roadmap notes.
8. **Multi-source aggregation** (AbuseIPDB, OTX, URLhaus, Shodan) feeding into
   Normalizer — also a separate long-term roadmap item.
9. **Basic Log Analyzer** — build only after covering relevant SOC log-analysis study
   topics, so the feature reflects real understanding, not a superficial wrapper.
10. **Basic Network Analyzer** — build only after completing the Networking study
    series (Topic 19 + Block 4 revision), for the same reason.

---

## 13. Build Order Checklist (V1)

- [ ] Confirm Normalizer output matches (or is adapted to) the schema in Section 6
- [ ] Write `fiveWOneH.js` generator (pure function: normalized object → 5W1H object)
- [ ] Build Report Preview screen (React component, dark theme, matches dashboard)
- [ ] Add "Generate 5W1H Report" button on scan result page
- [ ] Add Edit Mode (textarea toggle + reset-to-auto per section)
- [ ] Build `pdfRenderer.js` (light theme, print-friendly)
- [ ] Wire "Export as PDF" and "Copy Summary" buttons
- [ ] Test across all 5 indicator types (hash, IP, domain, URL, file) to confirm
      type-agnostic logic + WHERE field branching works correctly
- [ ] (Optional, if time permits) Wire report generation into Scan History, so past
      scans can also generate a 5W1H report retroactively

---

## 14. One-Line Summary (for resume / interview use)

> "Built a deterministic 5W1H escalation report generator inside SHADOW's Report
> Engine — converts raw threat intelligence data into a structured, analyst-editable
> investigation summary for SOC L1→L2 handoff, exportable as PDF. Architecture is
> AI-optional: fully functional without AI, with a future Shadow AI layer planned to
> add natural-language narrative on top of the same deterministic output."
