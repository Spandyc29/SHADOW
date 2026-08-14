import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { LayoutDashboard, UploadCloud, History, Settings, LogOut } from "lucide-react";
import "../styles/sidebar.css";

function Sidebar() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, isGuest, logout } = useAuth();

  const handleLogoutAction = async () => {
    if (window.confirm("Terminate SHADOW terminal session?")) {
      await logout();
      navigate("/login");
    }
  };

  const isActive = (path) => (location.pathname === path ? "active" : "");

  return (
    <aside className="sidebar">
      {/* SHADOW BRANDING HEADER */}
      <div className="sidebar-brand">
        <div className="hexagon-logo-wrapper">
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
        <div className="brand-text-container">
          <h1 className="sidebar-brand-title">SHADOW</h1>
          <span className="sidebar-brand-subtitle">THREAT INTELLIGENCE</span>
        </div>
        {isGuest && <span className="guest-badge">GUEST OPERATOR</span>}
      </div>

      {/* NAVIGATION ITEMS */}
      <nav className="nav-links">
        <Link to="/dashboard" className={`nav-item ${isActive("/dashboard")}`}>
          <LayoutDashboard size={20} className="nav-icon" />
          <span>Dashboard</span>
        </Link>
        <Link to="/upload" className={`nav-item ${isActive("/upload")}`}>
          <UploadCloud size={20} className="nav-icon" />
          <span>Upload Scan</span>
        </Link>
        <Link to="/history" className={`nav-item ${isActive("/history")}`}>
          <History size={20} className="nav-icon" />
          <span>Scan History</span>
        </Link>
        <Link to="/settings" className={`nav-item ${isActive("/settings")}`}>
          <Settings size={20} className="nav-icon" />
          <span>Settings</span>
        </Link>
      </nav>

      {/* SHADOW AI ASSISTANT CARD */}
      <div className="sidebar-ai-card">
        <div className="sidebar-ai-header">
          <div className="sidebar-ai-icon-wrapper">
            <span className="sidebar-ai-pulse-dot" />
            <svg className="sidebar-ai-bot-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="11" width="18" height="10" rx="3" />
              <circle cx="9" cy="16" r="1.5" fill="currentColor" />
              <circle cx="15" cy="16" r="1.5" fill="currentColor" />
              <path d="M12 4v7" />
              <path d="M8 4h8" />
            </svg>
          </div>
          <div>
            <h3 className="sidebar-ai-title">SHADOW AI</h3>
          </div>
        </div>
        <p className="sidebar-ai-description">
          Your intelligent security assistant is ready to help.
        </p>
        <button
          type="button"
          onClick={() => window.dispatchEvent(new CustomEvent('shadow-open-chat'))}
          className="btn-sidebar-ask-ai"
        >
          Ask SHADOW AI
        </button>
      </div>

      {/* SIDEBAR FOOTER */}
      <div className="sidebar-footer">
        {user ? (
          <button className="btn-sidebar-logout" onClick={handleLogoutAction}>
            <LogOut size={18} />
            <span>Terminate Session</span>
          </button>
        ) : (
          <div className="guest-footer-panel">
            <Link to="/login" className="btn-sidebar-auth primary">
              Sign In
            </Link>
            <div className="auth-panel-divider" />
            <Link to="/register" className="btn-sidebar-auth secondary">
              Register
            </Link>
          </div>
        )}
      </div>
    </aside>
  );
}

export default Sidebar;
