# SHADOW — Report Engine Frontend Build Plan

**Status:** Backend 100% complete (Report Engine, all generators, all renderers, 107/107 tests passing)
**Now:** Frontend wiring — this is the remaining work
**Last Updated:** 08 Aug 2026

---

## Where things stand

Backend already has:
- `ReportSchema` (normalized input, works for all indicator types)
- Report Engine + 5 generators (5W1H, Executive Summary, IOC Summary, Timeline, Technical Summary)
- 3 renderers (HTML, JSON, PDF)
- API endpoint: `/reports/render`

Frontend has: none of this wired up yet. Dashboard/scan result pages exist and work
(Hash/IP/Domain/URL analysis), but there's no way for the user to trigger report
generation, see a preview, or export it.

**This doc is the phase-by-phase plan to close that gap.**

---

## Guardrail before starting

Build ONLY what's listed per phase. Do not jump ahead to Edit Mode, multiple report
types (Escalation/DFIR/Notes), or Scan History integration until the phase before it
is fully working and tested. This is the same scope discipline used for the backend —
it's what kept that phase from sprawling, and it applies here too.

---

## Phase 1 — Trigger + Static Preview (build this first)

**Goal:** Clicking a button shows the report on screen. No PDF yet. No editing yet.
Just: data in, structured report visible.

### 1.1 — "Generate 5W1H Report" button
- Add to the existing scan result page, next to "Export Report"
- On click: call `POST /reports/render` with the current scan's normalized data +
  `type: "5w1h"`
- Show a loading state while waiting (this is a real API call, not instant)

### 1.2 — Report Preview screen/modal
- New route or modal — light theme (white background), NOT the dashboard's dark theme
  (matches the "printable/shareable" intent we decided on)
- Renders the HTML response from the backend
- Sections in order: header (Report ID, generated date, indicator) → Verdict/Risk/
  Confidence mini-cards → WHAT (paragraph) → WHO/WHEN/WHERE/HOW (compact grid) → WHY
  (bullets) → Tags (pills) → Recommended Action (highlighted box) → footer disclaimer
- Reference the mockup already built for this — same visual structure, same field
  layout, same order

### 1.3 — Manual test across all 5 indicator types
- Generate a report for: hash, IP, domain, URL, file
- Confirm the WHERE field correctly branches per type (geo for IP, registrar for
  domain, host for URL, "Manual Upload via SHADOW" for hash/file)
- Confirm nothing breaks when a field is missing/empty (e.g. no associated_names)

**Phase 1 is done when:** you can click the button on any scan type and see a
correctly-populated, readable report on screen.

---

## Phase 2 — PDF Export

**Goal:** The preview you already built can now be downloaded as a PDF.

### 2.1 — Wire "Export as PDF" button
- Calls the backend PDF renderer (already built) with the same report data
- Triggers a file download

### 2.2 — Visual QA
- Open the actual downloaded PDF, not just the in-app preview
- Check: page breaks look right, nothing gets cut off, colors print reasonably,
  fonts render correctly
- Test with a report that has a LOT of tags/risk factors (long content) and one with
  very little (short content) — layout should hold up both ways

### 2.3 — "Copy Summary" button
- Plain-text version of the report copied to clipboard
- Quick win, do this alongside PDF since it reuses the same data

**Phase 2 is done when:** PDF downloads correctly and looks right when opened, for
every indicator type, with both long and short content.

---

## Phase 3 — Edit Mode

**Goal:** Analyst can manually adjust any section before exporting.

### 3.1 — Edit toggle
- `[Edit]` button switches each 5W1H section from static text to an editable
  `<textarea>`, pre-filled with the auto-generated content
- State: `reportData` (current content, editable) + `isEditing` (bool) + `wasEdited`
  (bool, set true on any change)

### 3.2 — "Reset to auto-generated" per section
- Restores that section's original generated text
- Needs the original generated output kept separately from the edited state so reset
  actually works

### 3.3 — Edited flag on export
- If `wasEdited` is true, PDF/preview shows: "Manually reviewed & edited by [analyst]"
- Export (PDF/Copy) always reads current `reportData`, whether edited or not

**Phase 3 is done when:** you can edit a section, see it reflected in the PDF, reset
it back, and the edited flag shows correctly when something was actually changed.

---

## Phase 4 — Polish (only after 1–3 are solid)

- Loading skeletons instead of blank states during report generation
- Error handling: what shows if `/reports/render` fails or times out
- Scan History integration: generate a report for a past scan, not just the current one
- Visual polish pass on the preview screen (spacing, consistency with dashboard style
  guide already established)

---

## Explicitly NOT in this build (parked, do not start)

- Multiple report types (Escalation / DFIR / Notes) — revisit only after Phase 1–3 are
  solid and fully explainable. The backend generators (Executive Summary, IOC Summary,
  Timeline, Technical Summary) already exist, so adding a "template" that picks which
  generators to include is a config change, not new engineering — but it's still a
  new decision to make later, not now.
- Shadow AI narrative layer — separate phase entirely, comes after Report Engine
  frontend is fully working
- Log Analyzer / Network Analyzer — unrelated to this phase, parked per earlier roadmap

---

## Order of work, summarized

```
Phase 1: Button → Static Preview (all 5 indicator types tested)
Phase 2: PDF Export + Copy Summary
Phase 3: Edit Mode
Phase 4: Polish + error handling + Scan History hookup
─────────────────────────────────────────────
(stop here for V1 — everything else is future roadmap)
```

Each phase should end with something you can actually demo, not a half-working
in-between state. If Phase 1 is fully working, that alone is demo-able — don't wait
until Phase 4 to show progress.
