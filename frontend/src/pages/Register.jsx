import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { supabase } from "../supabaseClient";
import LoginMascot from "../components/auth/LoginMascot";
import {
  User,
  Mail,
  Lock,
  Eye,
  EyeOff,
  ArrowRight,
  ShieldCheck,
  TrendingUp,
  FileText,
} from "lucide-react";
import "../styles/auth-gateway.css";

function Register() {
  const navigate = useNavigate();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const handleRegistration = async (e) => {
    e.preventDefault();
    setErrorMsg("");

    if (password.length < 8) {
      setErrorMsg("Security keys must exceed 8 alphanumeric structures.");
      return;
    }
    if (password !== confirmPassword) {
      setErrorMsg("Security key mismatches detected inside confirmation structures.");
      return;
    }

    setLoading(true);
    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: { data: { full_name: fullName } },
    });

    if (error) {
      setErrorMsg(error.message);
      setLoading(false);
    } else {
      alert(
        "Registration request processed. Verify your operational profile via email validation link."
      );
      navigate("/login");
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
              <p className="subtitle">— Provision New Operator Profile —</p>
            </div>

            {/* Error / Success Notifications */}
            {errorMsg && <div className="banner-error">⚠️ [VALIDATION_ERR]: {errorMsg}</div>}

            {/* Form Inputs */}
            <form onSubmit={handleRegistration} className="auth-form">
              <div className="input-group">
                <label className="tracked-label">OPERATOR LEGAL IDENTITY NAME</label>
                <div className="input-with-icon">
                  <User size={18} className="field-icon" />
                  <input
                    type="text"
                    required
                    placeholder="Alex Mercer"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                  />
                </div>
              </div>

              <div className="input-group">
                <label className="tracked-label">COMMUNICATIONS ROUTING EMAIL</label>
                <div className="input-with-icon">
                  <Mail size={18} className="field-icon" />
                  <input
                    type="email"
                    required
                    placeholder="a.mercer@shadow.io"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>
              </div>

              <div className="input-group">
                <label className="tracked-label">TARGET CIPHER KEY (MIN 8 CHARS)</label>
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

              <div className="input-group">
                <label className="tracked-label">CONFIRM TARGET CIPHER KEY</label>
                <div className="input-with-icon password-wrapper">
                  <Lock size={18} className="field-icon" />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    placeholder="••••••••••••"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                  />
                </div>
              </div>

              <button type="submit" className="btn-primary" disabled={loading}>
                <span>{loading ? "COMPILING PROFILE MATRICES..." : "DEPLOY PROFILE KEY"}</span>
                {!loading && <ArrowRight size={18} className="btn-arrow-icon" />}
              </button>
            </form>

            <p className="auth-footer-link">
              Already verified terminal operator? <Link to="/login">Sign In</Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Register;
