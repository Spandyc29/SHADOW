import { useNavigate } from "react-router-dom";
import "../styles/auth-gateway.css";

function AccessDenied() {
  const navigate = useNavigate();

  return (
    <div className="auth-gateway-root">
      <div className="glass-auth-card access-denied-box">
        <div className="alert-icon">🚫</div>
        <h1>Access Denied</h1>
        <p>Elevated clearance token required. Please sign in or register an account to access advanced history telemetry and custom parameters.</p>
        
        <div className="action-button-group">
          <button className="btn-primary" onClick={() => navigate("/login")}>
            Authenticate Operator
          </button>
          <button className="btn-secondary" onClick={() => navigate("/register")}>
            Register Profile
          </button>
        </div>
      </div>
    </div>
  );
}

export default AccessDenied;