import React from 'react';
import { SHADOW_STATES } from './ShadowConstants';

/**
 * ShadowFaceSystem.jsx
 * Production SVG digital face system rendering 14 distinct, morphing expression states
 * over the physical screen of the SHADOW helmet.
 */
export default function ShadowFaceSystem({
  state = SHADOW_STATES.IDLE,
  isBlinking = false,
  eyeOffset = { x: 0, y: 0 },
}) {
  const isIdle = state === SHADOW_STATES.IDLE;
  const isAttention = state === SHADOW_STATES.ATTENTION;
  const isHappy = state === SHADOW_STATES.HAPPY;
  const isCurious = state === SHADOW_STATES.CURIOUS;
  const isThinking = state === SHADOW_STATES.THINKING;
  const isTalking = state === SHADOW_STATES.TALKING;
  const isAlert = state === SHADOW_STATES.ALERT;
  const isWarning = state === SHADOW_STATES.WARNING;
  const isConfused = state === SHADOW_STATES.CONFUSED;
  const isSleeping = state === SHADOW_STATES.SLEEPING;
  const isSurprised = state === SHADOW_STATES.SURPRISED;
  const isFocused = state === SHADOW_STATES.FOCUSED;
  const isSuccess = state === SHADOW_STATES.SUCCESS;
  const isError = state === SHADOW_STATES.ERROR;

  const effectiveBlink = isBlinking || isSleeping;

  // Compute eye displacement transform string from eyeOffset
  const eyeTransform = `translate(${eyeOffset.x || 0}px, ${eyeOffset.y || 0}px)`;

  return (
    <div className={`shadow-face-system state-${state}`}>
      <svg
        className="shadow-face-svg"
        viewBox="0 0 460 270"
        preserveAspectRatio="xMidYMid meet"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          {/* Cyber Cyan Glow Filter */}
          <filter id="p-cyber-glow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="5.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Attention Flare Glow Filter */}
          <filter id="p-attention-glow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="8" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Alert Red/Amber Glow Filter */}
          <filter id="p-alert-glow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="7.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Gradients */}
          <linearGradient id="p-eye-cyan" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#e0f2fe" />
            <stop offset="35%" stopColor="#38bdf8" />
            <stop offset="75%" stopColor="#00f0ff" />
            <stop offset="100%" stopColor="#0284c7" />
          </linearGradient>

          <linearGradient id="p-eye-alert" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#fef08a" />
            <stop offset="45%" stopColor="#f97316" />
            <stop offset="100%" stopColor="#dc2626" />
          </linearGradient>

          <linearGradient id="p-eye-warning" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#fef9c3" />
            <stop offset="50%" stopColor="#eab308" />
            <stop offset="100%" stopColor="#ca8a04" />
          </linearGradient>

          <linearGradient id="p-eye-success" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#dcfce7" />
            <stop offset="45%" stopColor="#4ade80" />
            <stop offset="100%" stopColor="#16a34a" />
          </linearGradient>
        </defs>

        {/* ================= SCREEN HUD FRAME ACCENTS ================= */}
        <g className="hud-frame" opacity="0.45">
          <path d="M 35 40 L 35 25 L 50 25" stroke="#00f0ff" strokeWidth="2.5" fill="none" />
          <path d="M 425 40 L 425 25 L 410 25" stroke="#00f0ff" strokeWidth="2.5" fill="none" />
          <path d="M 35 230 L 35 245 L 50 245" stroke="#00f0ff" strokeWidth="2.5" fill="none" />
          <path d="M 425 230 L 425 245 L 410 245" stroke="#00f0ff" strokeWidth="2.5" fill="none" />
          <line x1="60" y1="245" x2="110" y2="245" stroke="#00f0ff" strokeWidth="1.5" strokeDasharray="4 4" />
          <line x1="350" y1="245" x2="400" y2="245" stroke="#00f0ff" strokeWidth="1.5" strokeDasharray="4 4" />
        </g>

        {/* THINKING: Rotating Background Reticle */}
        {isThinking && (
          <g className="thinking-hud">
            <circle
              cx="230"
              cy="125"
              r="85"
              stroke="#00f0ff"
              strokeWidth="2"
              strokeDasharray="16 10 6 10"
              fill="none"
              opacity="0.55"
              className="p-thinking-spinner"
            />
            <line x1="60" y1="125" x2="400" y2="125" stroke="#00f0ff" strokeWidth="1" opacity="0.3" />
          </g>
        )}

        {/* ALERT & WARNING: Warning Reticles */}
        {(isAlert || isWarning || isError) && (
          <g className="alert-hud">
            <polygon
              points="230,18 244,36 216,36"
              fill={isAlert || isError ? "#f97316" : "#eab308"}
              filter="url(#p-alert-glow)"
              className="p-alert-triangle"
            />
            <circle
              cx="230"
              cy="125"
              r="95"
              stroke={isAlert || isError ? "#ef4444" : "#eab308"}
              strokeWidth="2.5"
              strokeDasharray="20 10"
              fill="none"
              opacity="0.65"
              className="p-alert-pulse-ring"
            />
          </g>
        )}

        {/* ATTENTION & SUCCESS & FOCUSED: Target Ring */}
        {(isAttention || isSuccess || isFocused) && (
          <g className="attention-hud">
            <circle
              cx="230"
              cy="125"
              r="92"
              stroke={isSuccess ? "#4ade80" : "#38bdf8"}
              strokeWidth="2.5"
              fill="none"
              filter="url(#p-attention-glow)"
              className="p-attention-ring"
            />
          </g>
        )}

        {/* ================= VECTOR EYES LAYER ================= */}
        <g
          className="eyes-layer"
          transform={eyeTransform}
          filter={
            isAttention || isSuccess
              ? "url(#p-attention-glow)"
              : isAlert || isError || isWarning
              ? "url(#p-alert-glow)"
              : "url(#p-cyber-glow)"
          }
        >
          {/* BLINK or SLEEPING */}
          {effectiveBlink && (
            <g className="eyes-closed">
              {isSleeping ? (
                <>
                  <path d="M 120 125 Q 162 145 204 125" stroke="#38bdf8" strokeWidth="10" strokeLinecap="round" fill="none" />
                  <path d="M 256 125 Q 298 145 340 125" stroke="#38bdf8" strokeWidth="10" strokeLinecap="round" fill="none" />
                </>
              ) : (
                <>
                  <line x1="120" y1="125" x2="204" y2="125" stroke="#00f0ff" strokeWidth="10" strokeLinecap="round" />
                  <line x1="256" y1="125" x2="340" y2="125" stroke="#00f0ff" strokeWidth="10" strokeLinecap="round" />
                </>
              )}
            </g>
          )}

          {/* HAPPY / SUCCESS (^ ^) */}
          {(isHappy || isSuccess) && !effectiveBlink && (
            <g className="eyes-happy">
              <path d="M 120 142 Q 162 90 204 142" stroke={isSuccess ? "#4ade80" : "#00f0ff"} strokeWidth="14" strokeLinecap="round" fill="none" />
              <path d="M 256 142 Q 298 90 340 142" stroke={isSuccess ? "#4ade80" : "#00f0ff"} strokeWidth="14" strokeLinecap="round" fill="none" />
            </g>
          )}

          {/* SURPRISED (O O) */}
          {isSurprised && !effectiveBlink && (
            <g className="eyes-surprised">
              <circle cx="162" cy="120" r="32" fill="url(#p-eye-cyan)" />
              <circle cx="298" cy="120" r="32" fill="url(#p-eye-cyan)" />
              <circle cx="162" cy="116" r="10" fill="#ffffff" />
              <circle cx="298" cy="116" r="10" fill="#ffffff" />
            </g>
          )}

          {/* CONFUSED (Asymmetric Eyes) */}
          {isConfused && !effectiveBlink && (
            <g className="eyes-confused">
              <rect x="120" y="98" width="84" height="52" rx="14" fill="url(#p-eye-cyan)" />
              <rect x="256" y="112" width="70" height="34" rx="8" fill="url(#p-eye-cyan)" transform="rotate(10, 291, 129)" />
              <circle cx="152" cy="118" r="8" fill="#ffffff" />
              <circle cx="285" cy="125" r="6" fill="#ffffff" />
            </g>
          )}

          {/* CURIOUS */}
          {isCurious && !effectiveBlink && (
            <g className="eyes-curious">
              <rect x="120" y="94" width="84" height="58" rx="14" fill="url(#p-eye-cyan)" />
              <rect x="256" y="104" width="84" height="46" rx="14" fill="url(#p-eye-cyan)" transform="rotate(-5, 298, 127)" />
              <circle cx="158" cy="116" r="8" fill="#ffffff" />
              <circle cx="286" cy="120" r="8" fill="#ffffff" />
            </g>
          )}

          {/* IDLE / ATTENTION / THINKING / ALERT / WARNING / FOCUSED / ERROR / TALKING */}
          {!effectiveBlink && !isHappy && !isSuccess && !isSurprised && !isConfused && !isCurious && (
            <g className="eyes-open">
              {/* Left Eye */}
              <rect
                x="120"
                y={isAlert || isError ? "108" : isWarning ? "112" : isThinking || isFocused ? "114" : isAttention ? "94" : "104"}
                width="84"
                height={isAlert || isError ? "36" : isWarning ? "32" : isThinking || isFocused ? "32" : isAttention ? "58" : "46"}
                rx={isAlert || isError ? "5" : "14"}
                fill={isAlert || isError ? "url(#p-eye-alert)" : isWarning ? "url(#p-eye-warning)" : "url(#p-eye-cyan)"}
                transform={isAlert || isError ? "rotate(6, 162, 125)" : "none"}
              />

              {/* Right Eye */}
              <rect
                x="256"
                y={isAlert || isError ? "108" : isWarning ? "112" : isThinking || isFocused ? "114" : isAttention ? "94" : "104"}
                width="84"
                height={isAlert || isError ? "36" : isWarning ? "32" : isThinking || isFocused ? "32" : isAttention ? "58" : "46"}
                rx={isAlert || isError ? "5" : "14"}
                fill={isAlert || isError ? "url(#p-eye-alert)" : isWarning ? "url(#p-eye-warning)" : "url(#p-eye-cyan)"}
                transform={isAlert || isError ? "rotate(-6, 298, 125)" : "none"}
              />

              {/* Pupil Highlights */}
              <circle cx="148" cy={isAttention ? "116" : "120"} r="8" fill="#ffffff" opacity="0.95" />
              <circle cx="284" cy={isAttention ? "116" : "120"} r="8" fill="#ffffff" opacity="0.95" />
              <ellipse cx="178" cy={isAttention ? "128" : "130"} rx="4" ry="7" fill="#ffffff" opacity="0.4" />
              <ellipse cx="314" cy={isAttention ? "128" : "130"} rx="4" ry="7" fill="#ffffff" opacity="0.4" />
            </g>
          )}
        </g>

        {/* ================= VECTOR MOUTH LAYER ================= */}
        <g
          className="mouth-layer"
          filter={
            isSuccess
              ? "url(#p-attention-glow)"
              : isAlert || isError || isWarning
              ? "url(#p-alert-glow)"
              : "url(#p-cyber-glow)"
          }
        >
          {/* TALKING: Sound Waveform Equalizer */}
          {isTalking && (
            <g className="mouth-talking">
              <rect className="p-vbar p-vbar-1" x="175" y="185" width="8" height="24" rx="4" fill="#00f0ff" />
              <rect className="p-vbar p-vbar-2" x="197" y="180" width="8" height="34" rx="4" fill="#38bdf8" />
              <rect className="p-vbar p-vbar-3" x="219" y="174" width="22" height="46" rx="6" fill="#00f0ff" />
              <rect className="p-vbar p-vbar-4" x="253" y="180" width="8" height="34" rx="4" fill="#38bdf8" />
              <rect className="p-vbar p-vbar-5" x="275" y="185" width="8" height="24" rx="4" fill="#00f0ff" />
            </g>
          )}

          {/* HAPPY / SUCCESS: Smile Curve */}
          {(isHappy || isSuccess) && (
            <path
              d="M 185 185 Q 230 218 275 185"
              stroke={isSuccess ? "#4ade80" : "#00f0ff"}
              strokeWidth="7"
              strokeLinecap="round"
              fill="none"
            />
          )}

          {/* SURPRISED: Small Circle Mouth */}
          {isSurprised && (
            <circle cx="230" cy="195" r="12" stroke="#00f0ff" strokeWidth="4" fill="none" />
          )}

          {/* CONFUSED: Wavy Line */}
          {isConfused && (
            <path d="M 190 195 Q 210 185 230 195 Q 250 205 270 195" stroke="#00f0ff" strokeWidth="5" strokeLinecap="round" fill="none" />
          )}

          {/* ALERT / ERROR: Warning Angle Notch */}
          {(isAlert || isError) && (
            <path
              d="M 190 196 L 230 208 L 270 196"
              stroke="#f97316"
              strokeWidth="6"
              strokeLinecap="round"
              strokeLinejoin="round"
              fill="none"
            />
          )}

          {/* SLEEPING: Soft ZZZ */}
          {isSleeping && (
            <g className="mouth-sleeping">
              <rect x="195" y="195" width="70" height="4" rx="2" fill="#0284c7" opacity="0.6" />
              <text x="325" y="88" fill="#38bdf8" fontSize="22" fontWeight="bold" opacity="0.75" className="p-zzz">z</text>
              <text x="345" y="62" fill="#38bdf8" fontSize="28" fontWeight="bold" opacity="0.9" className="p-zzz p-zzz-2">Z</text>
            </g>
          )}

          {/* IDLE / ATTENTION / THINKING / WARNING / FOCUSED / CURIOUS: Digital Mouth Dash */}
          {!isTalking && !isHappy && !isSuccess && !isSurprised && !isConfused && !isAlert && !isError && !isSleeping && (
            <rect
              x="195"
              y="195"
              width="70"
              height="6"
              rx="3"
              fill={isWarning ? "#eab308" : isAttention ? "#7dd3fc" : "#00f0ff"}
              opacity={isThinking || isFocused ? "0.6" : "0.85"}
            />
          )}
        </g>
      </svg>
    </div>
  );
}
