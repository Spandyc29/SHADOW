# SHADOW AI — Companion Pet Assistant
### Architecture, Requirements & Build Plan

**Version:** 1.0 (Planning)
**Status:** Requirements gathered — Ready for phased implementation
**Last Updated:** 08 Aug 2026

---

## 1. Core Principle (non-negotiable)

**Shadow AI explains. It never decides.**

- It will NEVER state or imply a verdict (malicious/safe/clean/suspicious) on its own.
- All verdicts come exclusively from the deterministic Risk Engine / Confidence
  Engine / Recommendation Engine.
- Shadow AI's job is to explain, contextualize, summarize, and answer questions
  about data that already exists — using both the current scan's data AND its own
  general security knowledge to make that data understandable.
- This boundary exists so the deterministic engines remain the single source of
  truth. AI is advisory only, never authoritative.

This principle must be enforced at multiple layers (see Section 6 — Guardrails), not
left to hope that the model behaves.

---

## 2. What Shadow AI Is (product concept)

A small animated companion character that lives on screen as a draggable, persistent
widget — visible across the whole app, not tied to any one page. Clicking it opens a
sidebar chat panel. Conceptually similar to a desktop pet / assistant, but scoped to
SOC investigation work.

Two operating modes:

1. **Scan-context mode** — active when a report/scan is currently open. The AI has
   access to that scan's normalized data (verdict, risk factors, tags, timestamps,
   etc.) and answers questions about it specifically.
2. **General help mode** — active when no scan context exists (e.g. user is on the
   Dashboard). The AI answers general questions about SHADOW itself — what a feature
   does, how to use something, what a term means.

---

## 3. V1 Scope (build this)

- [ ] Floating draggable widget (animated character, idle bounce/blink animation)
- [ ] Widget persists position across page navigation (global/root-level component)
- [ ] Click (not drag) opens a sidebar chat panel, slide-in from the side
- [ ] Chat works in scan-context mode: answers questions about the currently open
      scan/report using its normalized data + general security knowledge
- [ ] Chat works in general help mode: answers questions about SHADOW's features
      when no scan is open
- [ ] Backend: Groq API (free tier) for the LLM
- [ ] Guardrails: system prompt instruction + response filtering to block/rephrase
      any verdict-like language (see Section 6)
- [ ] UI disclaimer visible in the chat panel: something like "Shadow AI explains —
      it does not decide. Verdicts come from SHADOW's Risk Engine."

## Explicitly OUT of V1 (parked for V2)

- **Related cases / cross-scan search** — requires querying the full Scan History
  database and retrieving relevant past scans (a RAG-style retrieval system). This is
  a genuinely separate, more complex piece of engineering and should be its own
  future milestone, not bundled into V1.
- Proactive/unprompted insights (AI volunteering observations without being asked)
- Voice interaction
- Any ability for the AI to trigger actions (re-scan, escalate, edit report) — V1 is
  read-only / conversational only

---

## 4. Architecture — where this fits

```
SHADOW App (any page)
        |
        v
Floating Pet Widget (global, persistent position)
        |  (click)
        v
Sidebar Chat Panel
        |
        v
Mode Detection: is a scan/report currently open?
        |
   +----+----+
   v         v
Scan-Context   General Help
Mode           Mode
   |             |
   v             v
Build prompt   Build prompt
with current   with SHADOW
scan's         feature/app
normalized     knowledge
data
   |             |
   +------+------+
          v
   Groq API call
   (system prompt enforces
    "explain only, never verdict")
          v
   Response Filter
   (check for verdict-language,
    block/rephrase if found)
          v
   Display in chat
```

**Important:** This consumes the SAME normalized object that the Report Engine uses
(ReportSchema) — no new data pipeline needed for scan-context mode. Shadow AI reads
from the same source of truth, it doesn't duplicate or reinterpret scoring logic.

---

## 5. Widget UX Spec

- **Appearance:** Animated character, idle animation (bounce/blink) when not in use
- **Position:** Draggable anywhere on screen via mouse; persists at whatever position
  the user leaves it, across navigation
- **Click vs Drag distinction:** If mouse-down-to-mouse-up movement is below a small
  threshold (e.g. <5px), treat as a click (open chat). If movement exceeds that,
  treat as a drag (reposition only, don't open chat).
- **Chat panel:** Opens as a sidebar, slides in from the side (not a modal/overlay
  that blocks the whole screen — user should still be able to see/interact with the
  page behind it if needed)
- **Persistence:** Widget renders at the root/app level (outside page-specific
  routes) so it survives navigation between Dashboard, Upload Scan, Report Preview,
  etc.

---

## 6. Guardrails — enforcing "never verdict"

Two layers, as decided:

### Layer 1 — System prompt instruction
The system prompt sent to Groq must explicitly state the rule, e.g.:

> "You are Shadow AI, a security analysis assistant. You explain threat intelligence
> data and answer questions about SHADOW's features. You must NEVER state or imply a
> verdict (e.g. 'this is malicious', 'this is safe', 'this is clean') — verdicts are
> exclusively determined by SHADOW's deterministic Risk Engine. If asked for a
> verdict, redirect to the Risk Score/Verdict already shown in the report, and offer
> to explain what contributed to that score instead."

### Layer 2 — Response filtering
Before displaying any AI response, scan it for verdict-declaring language patterns
(e.g. "this is malicious", "this file is safe", "I can confirm this is..."). If
detected:
- Either block the response and show a fallback message, or
- Strip/rephrase the offending sentence while keeping the rest of the explanation

Exact word/phrase list and filtering logic to be defined at implementation time —
start with an obvious list (malicious, safe, clean, dangerous, harmless, confirmed
threat, etc. combined with first-person declarative phrasing) and refine based on
testing.

### Layer 3 — UI-level disclaimer
Visible, persistent note in the chat panel: "Shadow AI explains — it does not
decide. Verdicts come from SHADOW's Risk Engine." This sets user expectations
regardless of what the model outputs.

---

## 7. Build Order (phased, same discipline as Report Engine)

```
Phase 1: Widget only
  - Build the draggable, animated pet widget
  - Confirm drag/position-persistence works across page navigation
  - No chat functionality yet -- just prove the widget itself works

Phase 2: Chat UI (no AI yet)
  - Click opens/closes sidebar panel
  - Basic chat UI (input box, message list) -- can use hardcoded/placeholder
    responses at this stage to test the UI without burning API calls

Phase 3: Groq integration -- scan-context mode only
  - Wire real API calls
  - Pass current scan's normalized data into the prompt
  - Implement guardrail layers (system prompt + response filter)
  - Test thoroughly: ask it "is this malicious?" and similar leading questions,
    confirm it always redirects rather than answering directly

Phase 4: General help mode
  - Detect when no scan context exists
  - Give the AI a knowledge base about SHADOW's own features (can be a static
    text block describing what each part of SHADOW does, fed into the prompt)
  - Test general questions ("what does risk score mean", "how do I export a report")
```

Do not start Phase 2 until Phase 1 is solid. Do not start Phase 3 until Phase 2's UI
works cleanly. This mirrors exactly how the Report Engine phases were run -- each
phase should be demo-able on its own before moving to the next.

---

## 8. Test checklist (once V1 is built)

- [ ] Widget drags smoothly, position persists across at least 3 different page
      navigations
- [ ] Click (no drag) reliably opens the chat panel; drag never accidentally opens it
- [ ] In scan-context mode, ask leading questions ("is this dangerous?", "should I
      block this?", "confirm this is malicious") -- verify AI always redirects to the
      Risk Engine's existing verdict rather than answering directly
- [ ] In scan-context mode, ask genuine explanation questions ("why is this
      suspicious?", "what does obfuscated mean?") -- verify it gives a helpful,
      accurate explanation using the scan's actual data
- [ ] In general help mode (no scan open), ask about SHADOW features -- verify
      accurate, helpful answers
- [ ] Confirm the "explains, doesn't decide" disclaimer is visible in the chat UI
- [ ] No console errors, build succeeds

---

## 9. One-line summary (for resume / interview use)

> "Designed and built Shadow AI, a companion assistant within SHADOW that explains
> threat intelligence findings in natural language -- with a hard architectural
> boundary preventing it from ever issuing a verdict. All verdicts remain the
> exclusive responsibility of SHADOW's deterministic Risk Engine; Shadow AI is
> advisory-only, enforced through system-prompt constraints and response-level
> filtering -- a safety-first design choice reflecting how AI should assist, not
> replace, analyst judgment."

---

## 10. Future roadmap (V2+, not started)

1. **Related cases / cross-scan search** -- RAG-style retrieval over Scan History
2. Proactive insights (AI notices patterns without being asked)
3. Voice interaction
4. Action-taking capability (re-scan, escalate) -- would need careful guardrail
   redesign since this crosses from advisory into action-taking
