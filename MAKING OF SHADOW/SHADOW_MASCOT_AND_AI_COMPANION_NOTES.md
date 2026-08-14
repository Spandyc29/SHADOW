# SHADOW Mascot & Shadow AI Architecture Notes 🤖💬

---

## Executive Overview

The **SHADOW Companion & AI Assistant** system consists of two tightly integrated components:
1. **SHADOW Character Mascot (`ShadowCharacter.jsx`)**: A 100% code-driven 2D vector cyber-ninja floating companion widget present across the entire web application.
2. **Shadow AI Chat Engine (`ShadowChatPanel.jsx` & `/api/shadow-ai/chat`)**: A scan-context aware threat intelligence assistant powered by Groq server-side proxy with strict Risk Engine guardrails.

---

## Component Architecture Diagram

```
[ Layout.jsx (App Root) ]
        │
        ├── [ ShadowCharacter.jsx ] (Global Floating Vector Mascot)
        │         │
        │         ├── [ ShadowFaceSystem.jsx ] (14-State SVG Morphing Facial Expressions)
        │         ├── [ ShadowStateController.js ] (State Priority Machine & Micro-Behaviors)
        │         └── [ ShadowConstants.js ] (Priority Matrix & Layout Specs)
        │
        └── [ ShadowChatPanel.jsx ] (Right Sidebar Glassmorphism Chat UI)
                  │
                  ├── [ ScanContext.jsx ] (Active Report Scan Data Hook)
                  └── POST http://localhost:8000/api/shadow-ai/chat
                            │
                            └── [ backend/routers/shadow_ai.py ] (FastAPI Proxy)
                                      │
                                      ├── System Prompt Injection
                                      ├── Groq API Call (llama-3.3-70b-versatile)
                                      └── Layer 2 Guardrail Verdict Filter
```

---

## 1. Vector Mascot Character System

- **Vector SVG Geometry (`viewBox="0 0 320 400"`)**: Constructed entirely out of resolution-independent SVG paths (`<path>`, `<polygon>`, `<rect>`) without raster PNG images or sprite sheets.
- **Silhouette Fidelity**: Reconstructs the broad-shouldered cyber-ninja silhouette matching `SHADOW_Bot.png` (cowl hood, chest armor plate, cyber core reactor emblem, shoulder pauldrons, gauntlets, utility belt, kneepads, combat boots with glowing cyan energy sole lines).
- **Interactive Drag & Drop**:
  - Pointer events capture dragging across the viewport.
  - 5px movement threshold (`DRAG_THRESHOLD = 5`) cleanly separates pointer drags from clicks.
  - Viewport boundary clamping (`clampPosition`) prevents mascot from being lost off-screen.
  - Saved position persists across navigation and browser reloads via `localStorage` key `'shadow-companion-position'`.
- **14 Production Expression States**:
  - `IDLE`, `ATTENTION`, `HAPPY`, `CURIOUS`, `THINKING`, `TALKING`, `ALERT`, `WARNING`, `CONFUSED`, `SLEEPING`, `SURPRISED`, `FOCUSED`, `SUCCESS`, `ERROR`.
- **Dynamic Micro-Behaviors**:
  - Continuous floating animation (`@keyframes shadow-prod-float`).
  - Torso breathing expansion (`@keyframes shadow-torso-breath`).
  - Head tilt micro-motion (`@keyframes shadow-head-tilt`).
  - Organic micro-blinking and real-time cursor eye-tracking (`eyeOffset`).

---

## 2. Shadow AI Sidebar Chat Panel

- **Slide-in Sidebar**: 380px glassmorphism dark panel sliding in from the right edge (`z-index: 9950`).
- **Mandatory Risk Engine Disclaimer Notice**:
  > *"Shadow AI explains — it does not decide. Verdicts come from SHADOW's Risk Engine."*
- **Scan-Context Mode**:
  - Automatically receives active report telemetry (`ScanContext.jsx`) when viewing `/report-preview`, `/upload`, or `/scan/:id`.
  - Injects verdict, risk score, confidence score, threat label, risk factors, and tags into the AI reasoning context.
- **Widget State Sync**:
  - Clicking mascot toggles chat panel open/closed.
  - While AI processes a query, mascot switches to `THINKING` state, displaying rotating visor reticles.

---

## 3. Security, Guardrails & Backend Proxy

- **Server-Side API Proxy (`backend/routers/shadow_ai.py`)**:
  - `POST /api/shadow-ai/chat` proxy endpoint holds `GROQ_API_KEY` in `backend/.env`.
  - Frontend never exposes API keys or communicates directly with external LLM providers.
- **Dual-Layer Guardrail Architecture**:
  1. *Layer 1 (System Prompt)*: Instructs LLM that all verdicts belong exclusively to SHADOW's Risk Engine.
  2. *Layer 2 (Response Filter)*: Backend scans generated LLM text for verdict-declaring patterns (`"this is malicious"`, `"this is safe"`, `"I can confirm"`, etc.) and replaces violations with redirect notices back to the Risk Engine.
- **Graceful Error Fallback**: If API limits or network timeouts occur, logs errors server-side and returns friendly user messages without breaking the UI.

---

## 4. Key File Directory

| Module | File Path |
| :--- | :--- |
| **Global Mascot Mount** | `frontend/src/components/Layout.jsx` |
| **Vector Mascot Component** | `frontend/src/components/shadow/ShadowCharacter.jsx` |
| **Face Expression System** | `frontend/src/components/shadow/ShadowFaceSystem.jsx` |
| **State Machine Controller** | `frontend/src/components/shadow/ShadowStateController.js` |
| **Constants & Priority Hierarchy** | `frontend/src/components/shadow/ShadowConstants.js` |
| **Mascot Styling & Keyframes** | `frontend/src/styles/shadow-character.css` |
| **Chat Sidebar UI Component** | `frontend/src/components/shadow/ShadowChatPanel.jsx` |
| **Chat Sidebar Styling** | `frontend/src/styles/shadow-chat-panel.css` |
| **Scan Context Provider** | `frontend/src/context/ScanContext.jsx` |
| **Backend FastAPI Router** | `backend/routers/shadow_ai.py` |
| **Backend Config & `.env`** | `backend/config.py` & `backend/.env` |

---

## 5. Environment & Execution

```bash
# Start Backend FastAPI Server
cd backend
venv\Scripts\python -m uvicorn main:app --reload

# Start Frontend Dev Server
cd frontend
npm run dev
```
