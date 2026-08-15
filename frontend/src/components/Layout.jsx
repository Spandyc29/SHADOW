import { useState, useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Menu } from "lucide-react";
import Sidebar from "./Sidebar";
import ShadowCharacter from "./shadow/ShadowCharacter";
import "../styles/layout.css";

function Layout() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setIsMobileMenuOpen(false);
  }, [location.pathname]);

  return (
    <div className="layout">
      {/* MOBILE COMPACT HEADER BAR */}
      <header className="mobile-header">
        <div className="mobile-header-brand">
          <div className="hexagon-logo-wrapper mini">
            <svg viewBox="0 0 60 60" className="hexagon-logo-svg">
              <polygon
                points="30,3 56,17 56,43 30,57 4,43 4,17"
                fill="none"
                stroke="#a855f7"
                strokeWidth="3.5"
                className="hex-stroke"
              />
              <text
                x="30"
                y="37"
                textAnchor="middle"
                fill="#22d3ee"
                fontSize="24"
                fontWeight="900"
                fontFamily="sans-serif"
              >
                S
              </text>
            </svg>
          </div>
          <span className="mobile-brand-title">SHADOW</span>
        </div>

        <button
          type="button"
          className="mobile-menu-trigger"
          onClick={() => setIsMobileMenuOpen((prev) => !prev)}
          aria-label="Toggle Mobile Navigation"
        >
          <Menu size={24} />
        </button>
      </header>

      {/* BACKDROP OVERLAY FOR MOBILE DRAWER */}
      {isMobileMenuOpen && (
        <div
          className="sidebar-backdrop"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* SIDEBAR DRAWER / DESKTOP SIDEBAR */}
      <Sidebar
        isOpen={isMobileMenuOpen}
        onClose={() => setIsMobileMenuOpen(false)}
      />

      <main className="main-content">
        <Outlet />
      </main>

      {/* SHADOW AI Companion — Production Vector Mascot */}
      <ShadowCharacter />
    </div>
  );
}

export default Layout;