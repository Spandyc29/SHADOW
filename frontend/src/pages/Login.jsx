import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { supabase } from "../supabaseClient";
import { useAuth } from "../context/AuthContext";
import LoginMascot from "../components/auth/LoginMascot";
import {
  User,
  Lock,
  Eye,
  EyeOff,
  ArrowRight,
  Terminal,
  ShieldCheck,
  TrendingUp,
  FileText,
} from "lucide-react";
import "../styles/auth-gateway.css";

function Login() {
  const navigate = useNavigate();
  const { loginAsGuest } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [success, setSuccess] = useState(false);

  const handleAuthentication = async (e) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg("");

    const { error } = await supabase.auth.signInWithPassword({ email, password });

    if (error) {
      setErrorMsg(error.message);
      setLoading(false);
    } else {
      setSuccess(true);
      setTimeout(() => navigate("/dashboard"), 1200);
    }
  };

  return (
    <div className="auth-gateway-root">
      <div className="auth-gateway-container">
        {/* ================= LEFT BRANDING PANEL ================= */}
        <div className="auth-left-panel">
          <div className="auth-left-header">
            <span className="tracked-label text-purple-accent">SHADOW PROTOCOL</span>
            <h2 className="tagline">SECURE. ANALYZE. PROTECT.</h2>
          </div>

          {/* Vector Mascot Centerpiece */}
          <div className="mascot-centerpiece-container">
            <LoginMascot />
          </div>

          {/* 4 Feature Callouts Grid */}
          <div className="auth-feature-grid">
            <div className="feature-card">
              <div className="feature-icon-wrapper">
                <ShieldCheck size={20} />
              </div>
              <div className="feature-info">
                <h4>THREAT INTELLIGENCE</h4>
                <p>Real-time Analysis</p>
              </div>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrapper">
                <Lock size={20} />
              </div>
              <div className="feature-info">
                <h4>SECURE ACCESS</h4>
                <p>End-to-End Encrypted</p>
              </div>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrapper">
                <TrendingUp size={20} />
              </div>
              <div className="feature-info">
                <h4>RISK SCORING</h4>
                <p>Smart Evaluation</p>
              </div>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrapper">
                <FileText size={20} />
              </div>
              <div className="feature-info">
                <h4>INVESTIGATION</h4>
                <p>Detailed Reports</p>
              </div>
            </div>
          </div>

          {/* Left Footer Status */}
          <div className="auth-left-footer">
            <span className="status-dot active-dot"></span>
            <span>SHADOW PROTOCOL GATEWAY • v1.0.0 • ALL SYSTEMS SECURE</span>
          </div>
        </div>

        {/* ================= RIGHT FORM PANEL ================= */}
        <div className="auth-right-panel">
          <div className="glass-auth-card">
            {/* Hexagon Logo Badge Header */}
            <div className="auth-brand-header">
              <div className="hexagon-logo-wrapper">
                <svg viewBox="0 0 60 60" className="hexagon-logo-svg">
                  <polygon
                    points="30,3 56,17 56,43 30,57 4,43 4,17"
                    fill="none"
                    stroke="#a855f7"
                    strokeWidth="3"
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
              <h1 className="brand-title">SHADOW</h1>
              <p className="subtitle">— Threat Intelligence Protocol Gateway —</p>
            </div>

            {/* Error / Success Notifications */}
            {errorMsg && <div className="banner-error">⚠️ [ERR_AUTH_FAIL]: {errorMsg}</div>}
            {success && (
              <div className="banner-success">🔒 [OK]: Authorization Granted. Initializing console...</div>
            )}

            {/* Form Inputs */}
            <form onSubmit={handleAuthentication} className="auth-form">
              <div className="input-group">
                <label className="tracked-label">OPERATOR EMAIL</label>
                <div className="input-with-icon">
                  <User size={18} className="field-icon" />
                  <input
                    type="email"
                    required
                    placeholder="operator@shadow.io"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
              </div>

              <div className="input-group">
                <label className="tracked-label">SECURITY ACCESS TOKEN</label>
                <div className="input-with-icon password-wrapper">
                  <Lock size={18} className="field-icon" />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                  <button
                    type="button"
                    className="btn-toggle-eye"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label="Toggle password visibility"
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>

              {/* Checkbox & Forgot Link */}
              <div className="form-utilities">
                <label className="checkbox-container">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                  />
                  <span className="checkmark"></span>
                  <span className="checkbox-label-text">Remember Context</span>
                </label>
                <span
                  className="link-dummy"
                  onClick={() => alert("Forwarding recovery framework payload...")}
                >
                  Forgot Access Key?
                </span>
              </div>

              {/* Primary Authenticate Button */}
              <button type="submit" className="btn-primary" disabled={loading}>
                <span>{loading ? "VERIFYING CREDENTIALS..." : "AUTHENTICATE"}</span>
                {!loading && <ArrowRight size={18} className="btn-arrow-icon" />}
              </button>
            </form>

            {/* Hexagon Badge Divider */}
            <div className="divider-line">
              <div className="divider-badge">
                <span>OR</span>
              </div>
            </div>

            {/* Secondary Cyan Guest Button */}
            <button
              type="button"
              className="btn-guest-access"
              onClick={() => {
                loginAsGuest();
                navigate("/dashboard");
              }}
            >
              <div className="guest-btn-left">
                <Terminal size={20} className="guest-icon" />
              </div>
              <div className="guest-btn-content">
                <span className="guest-btn-title">INITIALIZE GUEST CONSOLE</span>
                <span className="guest-btn-subtitle">Limited Access • Isolated Session</span>
              </div>
              <div className="guest-btn-right">
                <ArrowRight size={18} className="guest-btn-arrow" />
              </div>
            </button>

            {/* Footer Link */}
            <p className="auth-footer-link">
              New operator deployment? <Link to="/register">Create Profile</Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;