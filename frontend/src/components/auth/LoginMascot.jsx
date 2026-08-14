import React from "react";

export default function LoginMascot() {
  return (
    <div className="login-mascot-wrapper">
      {/* Background Radial Glow */}
      <div className="mascot-glow-bg" />

      {/* Main Mascot SVG Graphic */}
      <svg
        viewBox="0 0 320 360"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="mascot-svg"
      >
        <defs>
          {/* Linear & Radial Gradients */}
          <linearGradient id="mascot-hood-grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#2c1a4d" />
            <stop offset="50%" stopColor="#161226" />
            <stop offset="100%" stopColor="#0b0816" />
          </linearGradient>

          <linearGradient id="mascot-purple-glow" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#a855f7" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#7c3aed" stopOpacity="0.2" />
          </linearGradient>

          <linearGradient id="mascot-cyan-glow" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#22d3ee" />
            <stop offset="100%" stopColor="#06b6d4" />
          </linearGradient>

          <radialGradient id="pedestal-ring-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#a855f7" stopOpacity="0.6" />
            <stop offset="60%" stopColor="#22d3ee" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#0b0a10" stopOpacity="0" />
          </radialGradient>

          <radialGradient id="eye-glow-cyan" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ffffff" />
            <stop offset="40%" stopColor="#22d3ee" />
            <stop offset="100%" stopColor="#00b4d8" stopOpacity="0.8" />
          </radialGradient>

          {/* Filters for Glow Effects */}
          <filter id="neon-glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          <filter id="neon-glow-purple" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* ================= 1. BACKGROUND DRAGON/SHIELD HEXAGON WATERMARK ================= */}
        <g opacity="0.15">
          {/* Outer Hexagon Frame */}
          <polygon
            points="160,20 280,85 280,225 160,290 40,225 40,85"
            stroke="#a855f7"
            strokeWidth="1.5"
            strokeDasharray="6 4"
          />
          <polygon
            points="160,32 268,93 268,217 160,278 52,217 52,93"
            stroke="#22d3ee"
            strokeWidth="1"
          />
          {/* Subtle Dragon/Shield Outline */}
          <path
            d="M 160 55 C 190 75, 230 75, 240 100 C 250 140, 220 185, 160 235 C 100 185, 70 140, 80 100 C 90 75, 130 75, 160 55 Z"
            fill="none"
            stroke="#a855f7"
            strokeWidth="1.5"
          />
        </g>

        {/* ================= 2. PEDESTAL GLOWING TECH RING (FEET BASE) ================= */}
        <g id="pedestal-tech-ring">
          {/* Outer Pedestal Glow Ellipse */}
          <ellipse cx="160" cy="315" rx="105" ry="32" fill="url(#pedestal-ring-glow)" />

          {/* Concentric Neon Rings */}
          <ellipse cx="160" cy="315" rx="90" ry="24" stroke="#a855f7" strokeWidth="2" filter="url(#neon-glow-purple)" opacity="0.7" />
          <ellipse cx="160" cy="315" rx="72" ry="18" stroke="#22d3ee" strokeWidth="2.5" filter="url(#neon-glow-cyan)" />
          <ellipse cx="160" cy="315" rx="50" ry="12" stroke="#ffffff" strokeWidth="1" opacity="0.6" />

          {/* Tech Pedestal Nodes */}
          <circle cx="70" cy="315" r="3" fill="#22d3ee" filter="url(#neon-glow-cyan)" />
          <circle cx="250" cy="315" r="3" fill="#22d3ee" filter="url(#neon-glow-cyan)" />
          <circle cx="160" cy="339" r="3" fill="#a855f7" filter="url(#neon-glow-purple)" />
          <circle cx="160" cy="291" r="3" fill="#a855f7" filter="url(#neon-glow-purple)" />
        </g>

        {/* ================= 3. LEGS & COMBAT BOOTS ================= */}
        <g id="mascot-legs">
          {/* Left Leg */}
          <path d="M 125 240 L 112 292 L 144 292 L 148 240 Z" fill="#151322" stroke="#2c2842" strokeWidth="2" />
          {/* Right Leg */}
          <path d="M 195 240 L 208 292 L 176 292 L 172 240 Z" fill="#151322" stroke="#2c2842" strokeWidth="2" />

          {/* Hexagonal Tactical Knee Pads */}
          <polygon points="108,255 138,255 142,272 138,285 108,285 104,272" fill="#1e1a34" stroke="#22d3ee" strokeWidth="1.5" />
          <polygon points="212,255 182,255 178,272 182,285 212,285 216,272" fill="#1e1a34" stroke="#22d3ee" strokeWidth="1.5" />

          {/* Combat Boots */}
          <path d="M 98 292 L 148 292 L 150 312 L 92 312 Z" fill="#0b0816" stroke="#4c3b70" strokeWidth="2" />
          <path d="M 222 292 L 172 292 L 170 312 L 228 312 Z" fill="#0b0816" stroke="#4c3b70" strokeWidth="2" />

          {/* Boot Neon Soles */}
          <line x1="94" y1="310" x2="148" y2="310" stroke="#22d3ee" strokeWidth="2.5" filter="url(#neon-glow-cyan)" />
          <line x1="172" y1="310" x2="226" y2="310" stroke="#22d3ee" strokeWidth="2.5" filter="url(#neon-glow-cyan)" />
        </g>

        {/* ================= 4. TORSO & CHEST ARMOR ================= */}
        <g id="mascot-body">
          {/* Main Stealth Suit Torso */}
          <path d="M 104 162 Q 160 150 216 162 L 202 245 Q 160 254 118 245 Z" fill="url(#mascot-hood-grad)" stroke="#2c2842" strokeWidth="2.5" />

          {/* Layered Chest Armor Plate */}
          <polygon points="120,174 200,174 192,230 128,230" fill="#18142b" stroke="#7c3aed" strokeWidth="1.8" />
          <polygon points="132,182 188,182 182,220 138,220" fill="#0f0c1d" stroke="#2c2842" strokeWidth="1.5" />

          {/* Chest Emblem Badge (Hexagon S) */}
          <polygon points="160,188 174,196 174,212 160,220 146,212 146,196" fill="#1e1938" stroke="#a855f7" strokeWidth="1.5" filter="url(#neon-glow-purple)" />
          <text x="160" y="208" textAnchor="middle" fill="#22d3ee" fontSize="13" fontWeight="900" fontFamily="sans-serif">S</text>

          {/* Belt */}
          <rect x="112" y="236" width="96" height="12" rx="3" fill="#0b0816" stroke="#4c3b70" strokeWidth="1.5" />
          <rect x="152" y="233" width="16" height="18" rx="3" fill="#1e1938" stroke="#22d3ee" strokeWidth="1.5" />
        </g>

        {/* ================= 5. SHOULDER PAULDRONS & ARMS ================= */}
        {/* Left Arm & Broad Pauldron */}
        <g id="mascot-left-arm">
          <path d="M 88 174 L 62 230 L 82 236 L 104 186 Z" fill="#151322" stroke="#2c2842" strokeWidth="2" />
          <polygon points="40,154 96,146 108,178 50,188" fill="#221a3a" stroke="#a855f7" strokeWidth="1.8" filter="url(#neon-glow-purple)" />
          <rect x="60" y="205" width="24" height="22" rx="4" fill="#0f0c1d" stroke="#22d3ee" strokeWidth="1.2" />
        </g>

        {/* Right Arm & Broad Pauldron */}
        <g id="mascot-right-arm">
          <path d="M 232 174 L 258 230 L 238 236 L 216 186 Z" fill="#151322" stroke="#2c2842" strokeWidth="2" />
          <polygon points="280,154 224,146 212,178 270,188" fill="#221a3a" stroke="#a855f7" strokeWidth="1.8" filter="url(#neon-glow-purple)" />
          <rect x="236" y="205" width="24" height="22" rx="4" fill="#0f0c1d" stroke="#22d3ee" strokeWidth="1.2" />
        </g>

        {/* ================= 6. HEAD, HOOD & GLOWING CYAN VISOR EYES ================= */}
        <g id="mascot-head">
          {/* Outer Ninja Hood */}
          <path
            d="M 64 88 C 64 18, 256 18, 256 88 C 256 150, 216 160, 160 160 C 104 160, 64 150, 64 88 Z"
            fill="url(#mascot-hood-grad)"
            stroke="#7c3aed"
            strokeWidth="2.5"
            filter="url(#neon-glow-purple)"
          />

          {/* Tactical Headband Ribbon Flowing Left */}
          <path d="M 66 100 Q 30 110 10 140 Q 25 155 58 125 Z" fill="#7c3aed" opacity="0.9" filter="url(#neon-glow-purple)" />
          <path d="M 66 105 Q 40 135 25 180 Q 40 185 62 140 Z" fill="#581c87" opacity="0.8" />

          {/* Deep Visor Screen Outer Rim */}
          <rect
            x="80"
            y="48"
            width="160"
            height="96"
            rx="28"
            fill="#090714"
            stroke="#22d3ee"
            strokeWidth="3"
            filter="url(#neon-glow-cyan)"
          />

          {/* Ear Mechanical Knobs */}
          <rect x="48" y="78" width="16" height="28" rx="5" fill="#1e1938" stroke="#a855f7" strokeWidth="1.5" />
          <rect x="256" y="78" width="16" height="28" rx="5" fill="#1e1938" stroke="#a855f7" strokeWidth="1.5" />
          <circle cx="56" cy="92" r="4" fill="#22d3ee" />
          <circle cx="264" cy="92" r="4" fill="#22d3ee" />

          {/* ================= 7. EXPRESSIVE GLOWING CYAN EYES ================= */}
          {/* Left Angled Glowing Cyan Eye */}
          <polygon
            points="102,82 136,88 132,112 108,106"
            fill="url(#eye-glow-cyan)"
            filter="url(#neon-glow-cyan)"
          />
          {/* Right Angled Glowing Cyan Eye */}
          <polygon
            points="218,82 184,88 188,112 212,106"
            fill="url(#eye-glow-cyan)"
            filter="url(#neon-glow-cyan)"
          />

          {/* Visor Glass Scan Line / Highlight */}
          <path d="M 88 56 Q 160 48 232 56" stroke="#ffffff" strokeWidth="2" opacity="0.3" />
        </g>
      </svg>
    </div>
  );
}
