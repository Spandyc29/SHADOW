# SHADOW Report Preview Frontend — Study Notes (August 8, 2026)

Simple, easy-to-understand study notes summarizing everything we built, fixed, and learned today while creating the **SHADOW Security Report Preview Frontend**.

---

## 📌 1. Main Goal of Today's Work

We built the entire **Report Preview Frontend Screen (`/report-preview`)** for SHADOW. 

The backend Report Engine was already complete and frozen (`POST /reports/render`). Our job today was to build a state-of-the-art, interactive, full-width Report Preview screen in React that displays threat analysis results, allows analyst editing, copies summaries, and exports clean PDF reports.

---

## 💡 2. Important Concepts & Lessons Learned

### Lesson 1: Full-Width Stacked Layout vs Multi-Column Grid
* **The Problem with 3-Column Grids**:
  - In a multi-column grid, cards in the same row are forced to match height.
  - If a section like "WHERE" has only 1 line of text, but sits next to a tall "WHAT" card with 10 lines of hashes, the short card shows a massive empty blank space.
  - Narrow column widths also cause text to wrap too quickly, pushing reports across 3+ printed pages.
* **The Solution**:
  - We restructured the 5W1H Threat Intelligence Breakdown into a **Single-Column Full-Width Stacked Layout** (sequential WHO → WHAT → WHERE → WHEN → WHY → HOW).
  - Each card takes 100% width, eliminating blank gaps and preventing excessive page wrapping in PDFs.

---

### Lesson 2: React Conditional Rendering vs Browser Print Engine (`@media print`)
* **The Problem**:
  - We built collapsible accordion sections for "Deep Technical Summary".
  - Initially, we used React conditional rendering: `{isOpen && <div className="accordion-body">...</div>}`.
  - When an accordion was collapsed on screen (`isOpen = false`), React removed the `<div className="accordion-body">` element from the HTML DOM tree completely.
  - When the user clicked **Print / Save PDF**, the browser print engine captured the live DOM. Because the collapsed data nodes didn't exist in the DOM, the exported PDF showed only section headers with zero data underneath!
* **The Solution**:
  - Always keep the data elements in the DOM tree!
  - Instead of `{isOpen && ...}`, we rendered `<div className={`accordion-body ${isOpen ? "accordion-open" : "accordion-closed"}`}>`.
  - On screen, CSS hides `.accordion-closed` (`display: none`).
  - In `@media print`, CSS forces all accordion bodies to render (`display: block !important; visibility: visible !important;`).
  - **Result**: Accordions collapse interactively on screen, but 100% of technical data prints cleanly in PDF exports!

---

### Lesson 3: Category Deduplication & Text Cleaning (`cleanAndDedupeCategories`)
* **The Problem**:
  - Multiple threat intelligence engines return the same threat category in slightly different casing, spacing, or with source attribution tags.
  - *Example raw output*: `"searchengines, search engines and portals, search engines, Search Engines/Portals (alphaMountain.ai)"`.
  - *Example raw output*: `"Business/Economy, Information Technology (alphaMountain.ai), computersandsoftware, information technology, information technology"`.
* **How We Fixed It (5-Step Algorithm)**:
  1. **Strip Attribution**: Removed source tags in parentheses like `(alphaMountain.ai)` or `(VirusTotal)`.
  2. **Normalized Comparison Key**: Converted strings to lowercase alphanumeric keys (`"searchengineportal"`) so near-duplicates map to the exact same comparison key regardless of casing or punctuation.
  3. **Readable Title Formatting**: Mapped raw un-spaced lowercase words (`computersandsoftware` → `Computers & Software`, `searchengines` → `Search Engines`).
  4. **Deduplication**: Retained only one unique entry per category key, choosing the cleanest, best-capitalized title.
  5. **Clean Result**:
     - `google.com` domain report → `"Search Engines & Portals"`
     - `microsoft.com` URL report → `"Business / Economy, Information Technology, Computers & Software"`

---

### Lesson 4: Metric Card Color Accents (Risk vs Confidence)
* **Risk Severity Accents**:
  - Risk Level & Risk Score use traffic-light threat colors:
    - **Clean / Low Risk**: Emerald Green (`#10b981`)
    - **Suspicious / Medium Risk**: Amber Orange (`#f59e0b`)
    - **Malicious / High Risk**: Crimson Red (`#ef4444`)
* **Confidence Accents**:
  - Confidence Level & Confidence Score use **Blue Shades** (`#2563eb`, `#0284c7`, `#64748b`).
  - *Why?* Confidence rating indicates how certain our engines are, NOT how dangerous the threat is. Using red or green for confidence would confuse analysts, so blue shades keep confidence clear and distinct from risk severity.

---

### Lesson 5: Practical SaaS UI Details
* **SaaS Toolbar Buttons**:
  - Styled action buttons (`Back to Investigation`, `Copy Summary`, `Edit Report`, `Print / Save PDF`) with Notion/Linear style rounded rectangle borders (`border-radius: 8px`), consistent 38px height, Lucide icons, and hover shadows.
* **Deterministic Report ID Generator (`getReportId`)**:
  - Created a fallback hash resolver so every report displays a real unique ID (e.g. `REP-C3506CA6`), avoiding hardcoded placeholder strings like `"REP-CUSTOM"`.
* **Copy Summary & IOC Copy Actions**:
  - Integrated `navigator.clipboard.writeText(...)` to compile plain-text investigation summaries and allow per-row IOC value copying with instant dark toast notifications.
* **Print Protection (`.no-print`)**:
  - Added `.no-print` classes to action bars, copy buttons, accordion chevrons, and toasts so PDF printouts contain ONLY clean report document content.

---

## 🛠️ 3. Summary of Files Updated Today

1. **`frontend/src/pages/ReportPreview.jsx`**:
   - Added Report Preview page component, API fetching, `Copy Summary` plain-text generator, `Executive Summary` card, stacked `5W1H` breakdown, `IOC Summary` table with per-row copy actions, vertical `Investigation Timeline`, interactive `Deep Technical Summary` accordions, category cleaner `cleanAndDedupeCategories`, Report ID resolver `getReportId`, and Edit Mode handlers.

2. **`frontend/src/styles/report-preview.css`**:
   - Added 100% full-width layout, SaaS toolbar button styles, 4-card left accent borders, metric icon badges, Executive Summary card styles, IOC table styles, vertical timeline layout, accordion styles, toast notification animation, confidential footer styling, and A4 print overrides (`@media print`).

3. **`backend/services/report_engine/generators/fivew1h.py` & `html_renderer.py`**:
   - Updated clean string extraction for threat category dict objects in 5W1H generators.

---

## ✅ 4. Final Status

- **Frontend Production Build (`npm run build`)**: `✓ built in 1.21s` with **0 errors**.
- **Backend Test Suite (`pytest backend/tests`)**: **107 passed, 0 failures**.
- **Supported Indicator Types**: Verified across **File**, **Hash**, **Domain**, **URL**, and **IP** reports.
