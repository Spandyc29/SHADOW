import React from 'react';

/**
 * ShadowFace.jsx
 * High-detail, programmable vector SVG digital face mounted over the blank physical screen of SHADOW helmet.
 * Scaled and positioned proportionally for the enhanced ~170px mascot presentation.
 */
export default function ShadowFace({ expression = 'idle' }) {
  const isBlink = expression === 'blink';
  const isThinking = expression === 'thinking';
  const isHappy = expression === 'happy';
  const isAlert = expression === 'alert';
  const isTalking = expression === 'talking';
  const isSleeping = expression === 'sleeping';
  const isAttention = expression === 'attention';

  return (
    <div className={`shadow-face-container expression-${expression}`}>
      <svg
        className="shadow-face-svg"
        viewBox="0 0 460 270"
        preserveAspectRatio="xMidYMid meet"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          {/* Cyber Cyan Glow Filter */}
          <filter id="cyber-glow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="5.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Attention Flare Glow Filter */}
          <filter id="attention-glow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="8" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Alert Amber/Red Glow Filter */}
          <filter id="alert-glow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="7" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Cyan Eye Gradient */}
          <linearGradient id="eye-cyan-grad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#e0f2fe" />
            <stop offset="35%" stopColor="#38bdf8" />
            <stop offset="75%" stopColor="#00f0ff" />
            <stop offset="100%" stopColor="#0284c7" />
          </linearGradient>

          {/* Alert Eye Gradient */}
          <linearGradient id="eye-alert-grad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#fef08a" />
            <stop offset="45%" stopColor="#f97316" />
            <stop offset="100%" stopColor="#dc2626" />
          </linearGradient>
        </defs>

        {/* Screen Corner Cyber HUD Accents */}
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
              className="thinking-spinner"
            />
            <line x1="60" y1="125" x2="400" y2="125" stroke="#00f0ff" strokeWidth="1" opacity="0.3" />
          </g>
        )}

        {/* ALERT: Warning Ring */}
        {isAlert && (
          <g className="alert-hud">
            <polygon
              points="230,18 244,36 216,36"
              fill="#f97316"
              filter="url(#alert-glow)"
              className="alert-triangle"
            />
            <circle
              cx="230"
              cy="125"
              r="95"
              stroke="#ef4444"
              strokeWidth="2.5"
              strokeDasharray="20 10"
              fill="none"
              opacity="0.65"
              className="alert-pulse-ring"
            />
          </g>
        )}

        {/* ATTENTION: Dynamic Focus Target Ring */}
        {isAttention && (
          <g className="attention-hud">
            <circle
              cx="230"
              cy="125"
              r="92"
              stroke="#38bdf8"
              strokeWidth="2.5"
              fill="none"
              filter="url(#attention-glow)"
              className="attention-ring"
            />
          </g>
        )}

        {/* ================= EYES LAYER ================= */}
        <g
          className={`eyes-layer ${isAlert ? 'eyes-alert' : ''}`}
          filter={isAttention ? 'url(#attention-glow)' : isAlert ? 'url(#alert-glow)' : 'url(#cyber-glow)'}
        >
          {/* EYES: BLINK or SLEEPING */}
          {(isBlink || isSleeping) && (
            <g className="eyes-closed">
              {/* Left Eye Line */}
              {isSleeping ? (
                <path d="M 120 125 Q 162 145 204 125" stroke="#38bdf8" strokeWidth="10" strokeLinecap="round" fill="none" />
              ) : (
                <line x1="120" y1="125" x2="204" y2="125" stroke="#00f0ff" strokeWidth="10" strokeLinecap="round" />
              )}
              {/* Right Eye Line */}
              {isSleeping ? (
                <path d="M 256 125 Q 298 145 340 125" stroke="#38bdf8" strokeWidth="10" strokeLinecap="round" fill="none" />
              ) : (
                <line x1="256" y1="125" x2="340" y2="125" stroke="#00f0ff" strokeWidth="10" strokeLinecap="round" />
              )}
            </g>
          )}

          {/* EYES: HAPPY (^ ^) */}
          {isHappy && (
            <g className="eyes-happy">
              <path d="M 120 142 Q 162 90 204 142" stroke="#00f0ff" strokeWidth="14" strokeLinecap="round" fill="none" />
              <path d="M 256 142 Q 298 90 340 142" stroke="#00f0ff" strokeWidth="14" strokeLinecap="round" fill="none" />
            </g>
          )}

          {/* EYES: IDLE / THINKING / ALERT / TALKING / ATTENTION */}
          {!isBlink && !isSleeping && !isHappy && (
            <g className={`eyes-open ${isAttention ? 'eyes-attention' : ''} ${isThinking ? 'eyes-thinking' : ''}`}>
              {/* Left Eye */}
              <rect
                x="120"
                y={isAlert ? "108" : isThinking ? "114" : isAttention ? "94" : "104"}
                width="84"
                height={isAlert ? "36" : isThinking ? "32" : isAttention ? "58" : "46"}
                rx={isAlert ? "5" : "14"}
                fill={isAlert ? "url(#eye-alert-grad)" : "url(#eye-cyan-grad)"}
                transform={isAlert ? "rotate(6, 162, 125)" : undefined}
              />

              {/* Right Eye */}
              <rect
                x="256"
                y={isAlert ? "108" : isThinking ? "114" : isAttention ? "94" : "104"}
                width="84"
                height={isAlert ? "36" : isThinking ? "32" : isAttention ? "58" : "46"}
                rx={isAlert ? "5" : "14"}
                fill={isAlert ? "url(#eye-alert-grad)" : "url(#eye-cyan-grad)"}
                transform={isAlert ? "rotate(-6, 298, 125)" : undefined}
              />

              {/* Iris Pupil & Inner Highlights */}
              <circle cx="148" cy={isAttention ? "116" : "120"} r="8" fill="#ffffff" opacity="0.95" />
              <circle cx="284" cy={isAttention ? "116" : "120"} r="8" fill="#ffffff" opacity="0.95" />
              <ellipse cx="178" cy={isAttention ? "128" : "130"} rx="4" ry="7" fill="#ffffff" opacity="0.4" />
              <ellipse cx="314" cy={isAttention ? "128" : "130"} rx="4" ry="7" fill="#ffffff" opacity="0.4" />
            </g>
          )}
        </g>

        {/* ================= MOUTH & LOWER INDICATOR LAYER ================= */}
        <g
          className="mouth-layer"
          filter={isAttention ? 'url(#attention-glow)' : isAlert ? 'url(#alert-glow)' : 'url(#cyber-glow)'}
        >
          {/* TALKING: Sound Waveform Audio Bars */}
          {isTalking && (
            <g className="mouth-talking">
              <rect className="vbar vbar-1" x="175" y="185" width="8" height="24" rx="4" fill="#00f0ff" />
              <rect className="vbar vbar-2" x="197" y="180" width="8" height="34" rx="4" fill="#38bdf8" />
              <rect className="vbar vbar-3" x="219" y="174" width="22" height="46" rx="6" fill="#00f0ff" />
              <rect className="vbar vbar-4" x="253" y="180" width="8" height="34" rx="4" fill="#38bdf8" />
              <rect className="vbar vbar-5" x="275" y="185" width="8" height="24" rx="4" fill="#00f0ff" />
            </g>
          )}

          {/* HAPPY: Curved Digital Smile */}
          {isHappy && (
            <path
              d="M 185 185 Q 230 218 275 185"
              stroke="#00f0ff"
              strokeWidth="7"
              strokeLinecap="round"
              fill="none"
            />
          )}

          {/* ALERT: Warning Angle Notch */}
          {isAlert && (
            <path
              d="M 190 196 L 230 208 L 270 196"
              stroke="#f97316"
              strokeWidth="6"
              strokeLinecap="round"
              strokeLinejoin="round"
              fill="none"
            />
          )}

          {/* SLEEPING: Soft ZZZ indicators */}
          {isSleeping && (
            <g className="mouth-sleeping">
              <rect x="195" y="195" width="70" height="4" rx="2" fill="#0284c7" opacity="0.6" />
              <text x="325" y="88" fill="#38bdf8" fontSize="22" fontWeight="bold" opacity="0.75" className="zzz-text">z</text>
              <text x="345" y="62" fill="#38bdf8" fontSize="28" fontWeight="bold" opacity="0.9" className="zzz-text zzz-2">Z</text>
            </g>
          )}

          {/* IDLE / THINKING / ATTENTION: Minimalist Digital Mouth Dash */}
          {!isTalking && !isHappy && !isAlert && !isSleeping && (
            <rect
              x="195"
              y="195"
              width="70"
              height="6"
              rx="3"
              fill={isAttention ? "#7dd3fc" : "#00f0ff"}
              opacity={isThinking ? "0.6" : "0.85"}
            />
          )}
        </g>
      </svg>
    </div>
  );
}
