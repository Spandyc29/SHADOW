import React, { useState, useEffect, useRef } from 'react';
import ShadowFaceSystem from './ShadowFaceSystem';
import ShadowChatPanel from './ShadowChatPanel';
import { shadowStateController } from './ShadowStateController';
import { SHADOW_STATES, DEFAULT_STORAGE_KEY } from './ShadowConstants';
import '../../styles/shadow-character.css';

const DRAG_THRESHOLD = 5;

const getMascotDimensions = () => {
  if (typeof window === 'undefined') return { width: 136, height: 170 };
  if (window.innerWidth <= 640) return { width: 96, height: 120 };
  if (window.innerWidth <= 1024) return { width: 120, height: 150 };
  return { width: 136, height: 170 };
};

export default function ShadowCharacter({
  stateOverride = null,
  hideFace = false,
  enableDragging = true,
  storageKey = DEFAULT_STORAGE_KEY,
  className = '',
  style = {},
}) {
  const [controllerState, setControllerState] = useState({
    state: shadowStateController.getCurrentState(),
    isBlinking: false,
    eyeOffset: { x: 0, y: 0 },
    microTilt: 0,
  });

  const [isHovered, setIsHovered] = useState(false);
  const [isDraggingState, setIsDraggingState] = useState(false);
  const [isChatOpen, setIsChatOpen] = useState(false);

  const activeState = stateOverride || controllerState.state;

  // Viewport-clamped position
  const clampPosition = (x, y) => {
    const minX = 10;
    const minY = 10;
    const { width, height } = getMascotDimensions();
    const maxX = Math.max(minX, window.innerWidth - width - 10);
    const maxY = Math.max(minY, window.innerHeight - height - 10);

    return {
      x: Math.min(Math.max(minX, x), maxX),
      y: Math.min(Math.max(minY, y), maxY),
    };
  };

  const getInitialPosition = () => {
    const { width, height } = getMascotDimensions();
    const defaultX = Math.max(10, window.innerWidth - width - 24);
    const defaultY = Math.max(10, window.innerHeight - height - 24);

    try {
      const saved = localStorage.getItem(storageKey);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (typeof parsed.x === 'number' && typeof parsed.y === 'number') {
          // If saved position is overlapping content area (e.g. left side or middle), reset to bottom-right
          if (parsed.x < window.innerWidth - width - 100 || parsed.y < window.innerHeight - height - 100) {
            return { x: defaultX, y: defaultY };
          }
          return clampPosition(parsed.x, parsed.y);
        }
      }
    } catch (e) {
      console.warn('Failed to load SHADOW character position:', e);
    }
    return { x: defaultX, y: defaultY };
  };

  const [position, setPosition] = useState(getInitialPosition);
  const containerRef = useRef(null);

  const dragInfoRef = useRef({
    isPointerDown: false,
    hasMovedPastThreshold: false,
    startX: 0,
    startY: 0,
    initialPosX: 0,
    initialPosY: 0,
  });

  const reactionTimerRef = useRef(null);
  const [isDizzy, setIsDizzy] = useState(false);

  const shakeTrackerRef = useRef({
    lastX: 0,
    lastY: 0,
    lastDirX: 0,
    flipCount: 0,
    lastFlipTime: Date.now(),
    isDizzy: false,
    timer: null,
  });

  const checkShakeVelocity = (clientX, clientY) => {
    const tracker = shakeTrackerRef.current;
    if (tracker.isDizzy) return;

    const now = Date.now();
    const deltaX = clientX - tracker.lastX;

    if (Math.abs(deltaX) > 16) {
      const dirX = deltaX > 0 ? 1 : -1;

      if (tracker.lastDirX !== 0 && dirX !== tracker.lastDirX) {
        if (now - tracker.lastFlipTime < 280) {
          tracker.flipCount += 1;
        } else {
          tracker.flipCount = 1;
        }
        tracker.lastFlipTime = now;

        if (tracker.flipCount >= 4) {
          // Trigger Head Spinning Dizzy Reaction!
          tracker.isDizzy = true;
          setIsDizzy(true);
          shadowStateController.setState(SHADOW_STATES.CONFUSED, true);

          if (tracker.timer) clearTimeout(tracker.timer);
          tracker.timer = setTimeout(() => {
            tracker.isDizzy = false;
            tracker.flipCount = 0;
            setIsDizzy(false);
            shadowStateController.setState(SHADOW_STATES.IDLE, true);
          }, 1800);
        }
      }
      tracker.lastDirX = dirX;
      tracker.lastX = clientX;
      tracker.lastY = clientY;
    }
  };

  // 1. Subscribe to State Controller
  useEffect(() => {
    const unsubscribe = shadowStateController.subscribe((data) => {
      setControllerState((prev) => {
        if (
          prev.state === data.state &&
          prev.isBlinking === data.isBlinking &&
          prev.microTilt === data.microTilt &&
          prev.eyeOffset?.x === data.eyeOffset?.x &&
          prev.eyeOffset?.y === data.eyeOffset?.y
        ) {
          return prev;
        }
        return data;
      });
    });
    return () => unsubscribe();
  }, []);

  // 2. Cursor Eye Tracking Listener & Hover Shake Detection
  useEffect(() => {
    const handleMouseMoveGlobal = (e) => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        shadowStateController.updateCursorTracking(e.clientX, e.clientY, rect);

        // Check if pointer is hovering directly over mascot or dragging
        const pad = 10;
        const isNearMascot =
          e.clientX >= rect.left - pad &&
          e.clientX <= rect.right + pad &&
          e.clientY >= rect.top - pad &&
          e.clientY <= rect.bottom + pad;

        if (isNearMascot || dragInfoRef.current.isPointerDown) {
          checkShakeVelocity(e.clientX, e.clientY);
        }
      }
    };
    window.addEventListener('mousemove', handleMouseMoveGlobal);
    return () => window.removeEventListener('mousemove', handleMouseMoveGlobal);
  }, []);

  // 3. Save position to localStorage
  useEffect(() => {
    if (enableDragging) {
      try {
        localStorage.setItem(storageKey, JSON.stringify(position));
      } catch (e) {
        console.warn('Failed to save SHADOW character position:', e);
      }
    }
  }, [position, enableDragging, storageKey]);

  // 4. Handle Window Resize
  useEffect(() => {
    if (enableDragging) {
      const handleResize = () => {
        setPosition((prev) => clampPosition(prev.x, prev.y));
      };
      window.addEventListener('resize', handleResize);
      return () => window.removeEventListener('resize', handleResize);
    }
  }, [enableDragging]);

  // 5. Handle Global Custom Event to Open Chat Panel
  useEffect(() => {
    const handleOpenChat = () => {
      setIsChatOpen(true);
      shadowStateController.setState(SHADOW_STATES.HAPPY, true);
    };
    window.addEventListener('shadow-open-chat', handleOpenChat);
    return () => window.removeEventListener('shadow-open-chat', handleOpenChat);
  }, []);

  // Hover Handlers
  const handleMouseEnter = () => {
    setIsHovered(true);
    if (!dragInfoRef.current.isPointerDown && activeState === SHADOW_STATES.IDLE) {
      shadowStateController.setState(SHADOW_STATES.ATTENTION);
    }
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
    shadowStateController.resetEyeOffset();
    if (!dragInfoRef.current.isPointerDown && activeState === SHADOW_STATES.ATTENTION) {
      shadowStateController.setState(SHADOW_STATES.IDLE);
    }
  };

  // Click Reaction Helper & Chat Panel Toggle
  const triggerClickReaction = () => {
    if (reactionTimerRef.current) clearTimeout(reactionTimerRef.current);
    shadowStateController.setState(SHADOW_STATES.HAPPY, true);

    // Toggle Chat Panel on clean click
    setIsChatOpen((prev) => !prev);

    reactionTimerRef.current = setTimeout(() => {
      if (shadowStateController.getCurrentState() === SHADOW_STATES.HAPPY) {
        shadowStateController.setState(isHovered ? SHADOW_STATES.ATTENTION : SHADOW_STATES.IDLE, true);
      }
    }, 1200);
  };

  // Pointer Event Handlers for Dragging vs Click Detection
  const handlePointerDown = (e) => {
    if (!enableDragging) return;
    if (e.button !== undefined && e.button !== 0) return;

    dragInfoRef.current = {
      isPointerDown: true,
      hasMovedPastThreshold: false,
      startX: e.clientX,
      startY: e.clientY,
      initialPosX: position.x,
      initialPosY: position.y,
    };

    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const handlePointerMove = (e) => {
    const drag = dragInfoRef.current;
    if (!drag.isPointerDown) return;

    const dx = e.clientX - drag.startX;
    const dy = e.clientY - drag.startY;

    if (!drag.hasMovedPastThreshold) {
      if (Math.hypot(dx, dy) >= DRAG_THRESHOLD) {
        drag.hasMovedPastThreshold = true;
        setIsDraggingState(true);
        if (activeState === SHADOW_STATES.IDLE || activeState === SHADOW_STATES.HAPPY) {
          shadowStateController.setState(SHADOW_STATES.ATTENTION);
        }
      }
    }

    if (drag.hasMovedPastThreshold) {
      const newX = drag.initialPosX + dx;
      const newY = drag.initialPosY + dy;
      setPosition(clampPosition(newX, newY));
      checkShakeVelocity(e.clientX, e.clientY);
    }
  };

  const handlePointerUp = (e) => {
    const drag = dragInfoRef.current;
    if (!drag.isPointerDown) return;

    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }

    drag.isPointerDown = false;
    setIsDraggingState(false);

    if (!drag.hasMovedPastThreshold) {
      triggerClickReaction();
    } else {
      if (activeState === SHADOW_STATES.ATTENTION) {
        shadowStateController.setState(isHovered ? SHADOW_STATES.ATTENTION : SHADOW_STATES.IDLE, true);
      }
    }
  };

  const handlePointerCancel = () => {
    dragInfoRef.current.isPointerDown = false;
    setIsDraggingState(false);
  };

  const isAlert = activeState === SHADOW_STATES.ALERT || activeState === SHADOW_STATES.ERROR;

  return (
    <>
      <div
        ref={containerRef}
        className={`shadow-production-character ${isDraggingState ? 'is-dragging' : ''} ${isHovered ? 'is-hovered' : ''} ${isDizzy ? 'is-dizzy-spinning' : ''} ${className} pdf-exclude no-print`.trim()}
        data-html2canvas-ignore="true"
        style={
          enableDragging
            ? {
                left: `${position.x}px`,
                top: `${position.y}px`,
                ...style,
              }
            : { position: 'relative', left: 'auto', top: 'auto', ...style }
        }
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerCancel}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        tabIndex={0}
        role="button"
        aria-label="SHADOW Production Coded AI Mascot"
      >
        <svg
          className="shadow-master-svg"
          viewBox="0 0 320 400"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <filter id="m-purple-glow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="6.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            <filter id="m-cyan-glow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="5.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            <filter id="m-alert-glow" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="7.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Gradients matching PNG reference */}
            <linearGradient id="m-hood-grad" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#2d303a" />
              <stop offset="40%" stopColor="#1a1c23" />
              <stop offset="100%" stopColor="#0c0e14" />
            </linearGradient>

            <linearGradient id="m-screen-glass" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#0f1522" />
              <stop offset="50%" stopColor="#070a12" />
              <stop offset="100%" stopColor="#020408" />
            </linearGradient>

            <linearGradient id="m-armor-metal" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#383d4a" />
              <stop offset="60%" stopColor="#1e222d" />
              <stop offset="100%" stopColor="#0f121a" />
            </linearGradient>
          </defs>

          {/* ================= 0. GROUNDING FLOOR SHADOW ================= */}
          <g id="shadow-grounding-shadow" className="shadow-grounding-shadow">
            <ellipse cx="160" cy="356" rx="84" ry="14" fill="#000000" opacity="0.55" />
          </g>

          {/* ================= 1. CLEAN BACK HOOD ================= */}
          <g id="shadow-back">
            {/* Outer Hood Cowl Drape matching PNG curve */}
            <path
              d="M 52 95 C 52 15, 268 15, 268 95 C 268 165, 225 178, 160 178 C 95 178, 52 165, 52 95 Z"
              fill="url(#m-hood-grad)"
              stroke="#0b0e14"
              strokeWidth="3"
            />
            {/* Inner Hood Shadow Folds */}
            <path d="M 64 85 C 64 35, 256 35, 256 85 Z" fill="#090a0f" opacity="0.5" />
          </g>

          {/* ================= 2. LEGS, KNEEPADS & COMBAT BOOTS ================= */}
          <g id="shadow-legs">
            {/* Left Leg */}
            <path d="M 124 245 L 108 322 L 144 322 L 148 245 Z" fill="#151823" stroke="#27282f" strokeWidth="2" />
            {/* Right Leg */}
            <path d="M 196 245 L 212 322 L 176 322 L 172 245 Z" fill="#151823" stroke="#27282f" strokeWidth="2" />

            {/* Hexagonal Tactical Knee Pads */}
            <polygon points="106,268 138,268 142,288 138,306 106,306 102,288" fill="#1e222d" stroke="#00f0ff" strokeWidth="1.2" />
            <polygon points="214,268 182,268 178,288 182,306 214,306 218,288" fill="#1e222d" stroke="#00f0ff" strokeWidth="1.2" />

            {/* Combat Boots */}
            <path d="M 94 322 L 148 322 L 150 344 L 88 344 Z" fill="#090d16" stroke="#334155" strokeWidth="2" />
            <path d="M 226 322 L 172 322 L 170 344 L 232 344 Z" fill="#090d16" stroke="#334155" strokeWidth="2" />

            {/* Boot Energy Soles */}
            <line x1="90" y1="342" x2="148" y2="342" stroke="#00f0ff" strokeWidth="2.5" filter="url(#m-cyan-glow)" />
            <line x1="172" y1="342" x2="230" y2="342" stroke="#00f0ff" strokeWidth="2.5" filter="url(#m-cyan-glow)" />
          </g>

          {/* ================= 3. CLEAN COMPACT TORSO & TACTICAL CHEST ARMOR ================= */}
          <g id="shadow-body" className="shadow-prod-torso-group">
            {/* Tactical Neck Collar Seal */}
            <path d="M 112 144 Q 160 156 208 144 Q 196 168 124 168 Z" fill="#0f121a" stroke="#334155" strokeWidth="1.5" />

            {/* Main Stealth Suit Torso */}
            <path d="M 104 162 Q 160 150 216 162 L 202 255 Q 160 264 118 255 Z" fill="url(#m-hood-grad)" stroke="#1a1c23" strokeWidth="2.5" />

            {/* Angular Layered Chest Armor Plate */}
            <polygon points="118,174 202,174 194,236 126,236" fill="url(#m-armor-metal)" stroke="#475569" strokeWidth="2" />
            <polygon points="130,182 190,182 184,226 136,226" fill="#0f121a" stroke="#334155" strokeWidth="1.5" />

            {/* Tactical Harness Straps */}
            <line x1="118" y1="174" x2="144" y2="236" stroke="#27282f" strokeWidth="3" />
            <line x1="202" y1="174" x2="176" y2="236" stroke="#27282f" strokeWidth="3" />

            {/* Cyber Core Reactor Emblem — Purple SHADOW Accent with Cyan AI Core */}
            <polygon points="160,185 177,199 160,213 143,199" fill="url(#m-screen-glass)" stroke="#a855f7" strokeWidth="2" filter="url(#m-purple-glow)" />
            <polygon points="160,189 173,199 160,209 147,199" fill="#00f0ff" filter="url(#m-cyan-glow)" />
            <circle cx="160" cy="199" r="4" fill="#ffffff" />
            <line x1="126" y1="199" x2="142" y2="199" stroke="#a855f7" strokeWidth="2" />
            <line x1="178" y1="199" x2="194" y2="199" stroke="#a855f7" strokeWidth="2" />

            {/* Utility Belt & Pouches */}
            <rect x="112" y="246" width="96" height="12" rx="3" fill="#090d16" stroke="#334155" strokeWidth="1.5" />
            <rect x="120" y="244" width="16" height="16" rx="2" fill="#1e222d" stroke="#475569" strokeWidth="1" />
            <rect x="184" y="244" width="16" height="16" rx="2" fill="#1e222d" stroke="#475569" strokeWidth="1" />
            <rect x="152" y="243" width="16" height="18" rx="3" fill="#1e222d" stroke="#00f0ff" strokeWidth="1.5" />
          </g>

          {/* ================= 4. BROAD TACTICAL SHOULDER ARMOR & ARMS ================= */}
          {/* Left Arm & Broad Shoulder Pauldron */}
          <g id="shadow-left-arm" className="shadow-prod-left-arm">
            <path d="M 88 174 L 62 235 L 82 242 L 104 186 Z" fill="#151823" stroke="#27282f" strokeWidth="2" />
            <polygon points="40,154 96,146 108,178 50,188" fill="url(#m-armor-metal)" stroke="#00f0ff" strokeWidth="1.8" />
            <rect x="60" y="210" width="26" height="24" rx="4" fill="#0f121a" stroke="#38bdf8" strokeWidth="1.2" />
            <path d="M 62 235 L 50 255 L 70 260 L 80 242 Z" fill="#020617" stroke="#334155" strokeWidth="1.5" />
            <line x1="58" y1="246" x2="74" y2="250" stroke="#00f0ff" strokeWidth="1.5" />
          </g>

          {/* Right Arm & Broad Shoulder Pauldron */}
          <g id="shadow-right-arm" className="shadow-prod-right-arm">
            <path d="M 232 174 L 258 235 L 238 242 L 216 186 Z" fill="#151823" stroke="#27282f" strokeWidth="2" />
            <polygon points="280,154 224,146 212,178 270,188" fill="url(#m-armor-metal)" stroke="#00f0ff" strokeWidth="1.8" />
            <rect x="234" y="210" width="26" height="24" rx="4" fill="#0f121a" stroke="#38bdf8" strokeWidth="1.2" />
            <path d="M 258 235 L 270 255 L 250 260 L 240 242 Z" fill="#020617" stroke="#334155" strokeWidth="1.5" />
            <line x1="262" y1="246" x2="246" y2="250" stroke="#00f0ff" strokeWidth="1.5" />
          </g>

          {/* ================= 5. HEAD, HOOD & DIGITAL SCREEN VISOR ================= */}
          <g id="shadow-head" className="shadow-prod-head-group" style={{ transform: `rotate(${controllerState.microTilt || 0}deg)` }}>
            {/* Main Cowl Hood Front Rim */}
            <path
              d="M 64 88 C 64 18, 256 18, 256 88 C 256 150, 216 160, 160 160 C 104 160, 64 150, 64 88 Z"
              fill="url(#m-hood-grad)"
              stroke="#1e293b"
              strokeWidth="3"
            />

            {/* Side Mechanical Ear Attachments */}
            <rect x="48" y="78" width="16" height="28" rx="5" fill="#1a1c23" stroke="#00f0ff" strokeWidth="1.5" />
            <rect x="256" y="78" width="16" height="28" rx="5" fill="#1a1c23" stroke="#00f0ff" strokeWidth="1.5" />

            {/* Hood Crest Seam Line */}
            <path d="M 160 22 L 160 48" stroke="#00f0ff" strokeWidth="2" strokeDasharray="3 3" opacity="0.65" />

            {/* Deep Visor Screen Outer Rim */}
            <rect
              x="80"
              y="48"
              width="160"
              height="96"
              rx="28"
              fill="url(#m-screen-glass)"
              stroke={isAlert ? "#f97316" : "#00f0ff"}
              strokeWidth="3.5"
              filter={isAlert ? "url(#m-alert-glow)" : "url(#m-cyan-glow)"}
            />

            {/* Visor Screen Glass Reflection Highlight */}
            <path d="M 96 56 Q 160 48 224 56 Q 160 66 96 56 Z" fill="#ffffff" opacity="0.12" />

            {/* Embedded Code-Controlled Vector Face System */}
            {!hideFace && (
              <foreignObject x="82" y="50" width="156" height="92">
                <ShadowFaceSystem
                  state={activeState}
                  isBlinking={controllerState.isBlinking}
                  eyeOffset={controllerState.eyeOffset}
                />
              </foreignObject>
            )}
          </g>
        </svg>
      </div>

      {/* Floating Sidebar Chat Panel */}
      <ShadowChatPanel isOpen={isChatOpen} onClose={() => setIsChatOpen(false)} />
    </>
  );
}
