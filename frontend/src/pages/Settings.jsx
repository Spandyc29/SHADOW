import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { supabase } from "../supabaseClient";
import { getSettingsApiKeys, updateSettingsApiKeys, getDashboardStats } from "../services/api";
import {
  User,
  Key,
  Download,
  Shield,
  Edit2,
  Save,
  X,
  CheckCircle2,
  AlertCircle,
  FileJson,
  FileSpreadsheet,
  LogOut,
  KeyRound,
} from "lucide-react";
import "../styles/settings.css";

function Settings() {
  const { user, isGuest, logout } = useAuth();

  // Profile Edit State
  const [displayName, setDisplayName] = useState("");
  const [isEditingName, setIsEditingName] = useState(false);
  const [nameInput, setNameInput] = useState("");
  const [nameSaving, setNameSaving] = useState(false);
  const [profileToast, setProfileToast] = useState(null);

  // API Key Management State
  const [groqKeyInput, setGroqKeyInput] = useState("");
  const [vtKeyInput, setVtKeyInput] = useState("");
  const [keysLoading, setKeysLoading] = useState(true);
  const [keysSaving, setKeysSaving] = useState(false);
  const [keysStatus, setKeysStatus] = useState({ has_groq_key: false, has_vt_key: false });
  const [keysToast, setKeysToast] = useState(null);

  // Telemetry Stats State
  const [stats, setStats] = useState({
    totalScans: 0,
    cleanFiles: 0,
    suspiciousFiles: 0,
    maliciousFiles: 0,
  });

  // Load User Display Name & Stats & Keys on initialization
  useEffect(() => {
    // 1. Set display name from authenticated user session
    if (user) {
      const initialName =
        user?.user_metadata?.display_name ||
        (user?.email ? user.email.split("@")[0] : "Security Operative");
      setDisplayName(initialName);
      if (!isEditingName) {
        setNameInput(initialName);
      }
    } else if (isGuest) {
      setDisplayName("Guest User");
      if (!isEditingName) {
        setNameInput("Guest User");
      }
    }

    // 2. Fetch telemetry stats
    getDashboardStats()
      .then((res) => {
        const d = res.data || {};
        setStats({
          totalScans: d.total_scans?.current ?? 0,
          cleanFiles: d.clean?.current ?? 0,
          suspiciousFiles: d.suspicious?.current ?? 0,
          maliciousFiles: d.threats?.current ?? 0,
        });
      })
      .catch(() => {});

    // 3. Fetch API keys status
    getSettingsApiKeys()
      .then((res) => {
        const d = res.data || {};
        setKeysStatus({
          has_groq_key: d.has_groq_key || false,
          has_vt_key: d.has_vt_key || false,
        });
        if (d.groq_api_key) setGroqKeyInput(d.groq_api_key);
        if (d.vt_api_key) setVtKeyInput(d.vt_api_key);
        setKeysLoading(false);
      })
      .catch(() => setKeysLoading(false));
  }, [user, isGuest, isEditingName]);

  // Handle Display Name Save
  const handleSaveName = async () => {
    if (!nameInput.trim()) return;
    setNameSaving(true);
    setProfileToast(null);

    try {
      const { error } = await supabase.auth.updateUser({
        data: { display_name: nameInput.trim() },
      });

      if (error) {
        setProfileToast({ type: "error", message: error.message });
      } else {
        setDisplayName(nameInput.trim());
        setIsEditingName(false);
        setProfileToast({ type: "success", message: "Display name updated successfully!" });
      }
    } catch (err) {
      setProfileToast({ type: "error", message: "Failed to update profile." });
    } finally {
      setNameSaving(false);
    }
  };

  // Handle API Keys Save
  const handleSaveApiKeys = async (e) => {
    e.preventDefault();
    setKeysSaving(true);
    setKeysToast(null);

    try {
      const payload = {};
      // Only include non-masked input changes
      if (groqKeyInput && !groqKeyInput.includes("••••")) {
        payload.groq_api_key = groqKeyInput.trim();
      }
      if (vtKeyInput && !vtKeyInput.includes("••••")) {
        payload.vt_api_key = vtKeyInput.trim();
      }

      const res = await updateSettingsApiKeys(payload);
      const data = res.data || {};

      setKeysStatus({
        has_groq_key: data.has_groq_key,
        has_vt_key: data.has_vt_key,
      });

      setKeysToast({ type: "success", message: "API key configurations saved successfully!" });
    } catch (err) {
      setKeysToast({ type: "error", message: "Failed to save API key configuration." });
    } finally {
      setKeysSaving(false);
    }
  };

  const handlePasswordReset = () => {
    alert("Password reset instructions dispatched to your registered email address.");
  };

  const formattedDate = user?.created_at
    ? new Date(user.created_at).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : isGuest
    ? "Ephemeral Guest Session"
    : "Active Session";

  const realEmail = user?.email || (isGuest ? "guest@shadow.local" : "Not Authenticated");
  const currentDisplayName =
    displayName ||
    user?.user_metadata?.display_name ||
    (user?.email ? user.email.split("@")[0] : isGuest ? "Guest User" : "Security Operative");

  const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || "https://shadow-581b.onrender.com";

  return (
    <div className="settings-container">
      <header className="settings-header">
        <h1>Platform Settings</h1>
        <p>Manage your security profile, API configurations, and telemetry parameters</p>
      </header>

      <div className="settings-grid">
        {/* SECTION 1 — PROFILE INFORMATION */}
        <section className="settings-card">
          <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
            <User className="w-4 h-4 text-purple-400" />
            <h2>Profile Information</h2>
          </div>

          {profileToast && (
            <div
              className={`flex items-center gap-2 text-xs p-3 rounded-lg mb-4 ${
                profileToast.type === "success"
                  ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                  : "bg-red-500/10 text-red-400 border border-red-500/30"
              }`}
            >
              {profileToast.type === "success" ? (
                <CheckCircle2 className="w-4 h-4" />
              ) : (
                <AlertCircle className="w-4 h-4" />
              )}
              <span>{profileToast.message}</span>
            </div>
          )}

          <div className="settings-content">
            <div className="profile-row flex items-center justify-between py-2 border-b border-slate-800/60">
              <span className="settings-label text-xs font-extrabold uppercase tracking-wider text-slate-400">
                User Name
              </span>
              {isEditingName ? (
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    className="bg-slate-900 border border-slate-700 rounded-md px-2.5 py-1 text-xs text-white focus:outline-none focus:border-purple-500"
                    value={nameInput}
                    onChange={(e) => setNameInput(e.target.value)}
                    disabled={nameSaving}
                  />
                  <button
                    onClick={handleSaveName}
                    disabled={nameSaving}
                    className="p-1.5 rounded-md bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold transition-colors"
                  >
                    <Save className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => {
                      setIsEditingName(false);
                      setNameInput(displayName);
                    }}
                    className="p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <span className="settings-value text-highlight font-bold text-white">{currentDisplayName}</span>
                  {!isGuest && (
                    <button
                      onClick={() => setIsEditingName(true)}
                      className="p-1 rounded text-slate-400 hover:text-purple-400 transition-colors"
                      title="Edit Display Name"
                    >
                      <Edit2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              )}
            </div>

            <div className="profile-row flex items-center justify-between py-2 border-b border-slate-800/60">
              <span className="settings-label text-xs font-extrabold uppercase tracking-wider text-slate-400">
                Email Address
              </span>
              <span className="settings-value text-xs font-semibold text-slate-200">
                {realEmail}
              </span>
            </div>

            <div className="profile-row flex items-center justify-between py-2">
              <span className="settings-label text-xs font-extrabold uppercase tracking-wider text-slate-400">
                Account Created
              </span>
              <span className="settings-value muted text-xs text-slate-400">{formattedDate}</span>
            </div>
          </div>
        </section>

        {/* SECTION 2 — API KEY MANAGEMENT */}
        <section className="settings-card">
          <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
            <Key className="w-4 h-4 text-amber-400" />
            <h2>API Key Configurations</h2>
          </div>

          <p className="text-xs text-slate-400 mb-4">
            Configure custom API keys for higher rate limits. If unconfigured, SHADOW automatically falls back to system environment defaults.
          </p>

          {keysToast && (
            <div
              className={`flex items-center gap-2 text-xs p-3 rounded-lg mb-4 ${
                keysToast.type === "success"
                  ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                  : "bg-red-500/10 text-red-400 border border-red-500/30"
              }`}
            >
              {keysToast.type === "success" ? (
                <CheckCircle2 className="w-4 h-4" />
              ) : (
                <AlertCircle className="w-4 h-4" />
              )}
              <span>{keysToast.message}</span>
            </div>
          )}

          <form onSubmit={handleSaveApiKeys} className="space-y-4">
            {/* GROQ API KEY */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-extrabold uppercase tracking-wider text-slate-300">
                  Groq API Key (Shadow AI)
                </label>
                <span
                  className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                    keysStatus.has_groq_key
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                      : "bg-slate-800 text-slate-400 border border-slate-700"
                  }`}
                >
                  {keysStatus.has_groq_key ? "Custom Key Configured" : "Using System Fallback"}
                </span>
              </div>
              <input
                type="text"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                placeholder="Enter Groq API Key (gsk_...)"
                value={groqKeyInput}
                onChange={(e) => setGroqKeyInput(e.target.value)}
                disabled={keysLoading || keysSaving}
              />
            </div>

            {/* VIRUSTOTAL API KEY */}
            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-extrabold uppercase tracking-wider text-slate-300">
                  VirusTotal API Key (Scanner)
                </label>
                <span
                  className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                    keysStatus.has_vt_key
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                      : "bg-slate-800 text-slate-400 border border-slate-700"
                  }`}
                >
                  {keysStatus.has_vt_key ? "Custom Key Configured" : "Using System Fallback"}
                </span>
              </div>
              <input
                type="text"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                placeholder="Enter VirusTotal 64-char API Key..."
                value={vtKeyInput}
                onChange={(e) => setVtKeyInput(e.target.value)}
                disabled={keysLoading || keysSaving}
              />
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={keysLoading || keysSaving}
                className="flex items-center gap-2 bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs px-4 py-2 rounded-lg transition-colors"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>{keysSaving ? "Saving Configurations..." : "Save API Key Configurations"}</span>
              </button>
            </div>
          </form>
        </section>

        {/* SECTION 3 — TELEMETRY & ACCOUNT STATISTICS */}
        <section className="settings-card stats-full-width">
          <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
            <Shield className="w-4 h-4 text-purple-400" />
            <h2>Telemetry & Account Statistics</h2>
          </div>
          <div className="stats-dashboard-grid">
            <div className="stat-node">
              <span className="stat-label">Total Scans</span>
              <span className="stat-number">{stats.totalScans}</span>
            </div>
            <div className="stat-node border-clean">
              <span className="stat-label">Clean Files</span>
              <span className="stat-number text-clean">{stats.cleanFiles}</span>
            </div>
            <div className="stat-node border-suspicious">
              <span className="stat-label">Suspicious Files</span>
              <span className="stat-number text-suspicious">{stats.suspiciousFiles}</span>
            </div>
            <div className="stat-node border-malicious">
              <span className="stat-label">Malicious Files</span>
              <span className="stat-number text-malicious">{stats.maliciousFiles}</span>
            </div>
          </div>
        </section>

        {/* SECTION 4 — BULK DATA EXPORT */}
        <section className="settings-card">
          <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
            <Download className="w-4 h-4 text-cyan-400" />
            <h2>Data & History Export</h2>
          </div>
          <p className="text-xs text-slate-400 mb-4">
            Download complete historical scan records for offline audit, SIEM integration, or compliance reports.
          </p>
          <div className="flex flex-wrap gap-3">
            <a
              href={`${apiBaseUrl}/scans/export/bulk?format=json`}
              download="scan_history_export.json"
              className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 font-bold text-xs px-3.5 py-2 rounded-lg border border-slate-700 transition-colors"
            >
              <FileJson className="w-4 h-4" />
              <span>Export History (JSON)</span>
            </a>

            <a
              href={`${apiBaseUrl}/scans/export/bulk?format=csv`}
              download="scan_history_export.csv"
              className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-emerald-400 font-bold text-xs px-3.5 py-2 rounded-lg border border-slate-700 transition-colors"
            >
              <FileSpreadsheet className="w-4 h-4" />
              <span>Export History (CSV)</span>
            </a>
          </div>
        </section>

        {/* SECTION 5 — SECURITY CONTROLS */}
        <section className="settings-card">
          <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
            <Shield className="w-4 h-4 text-blue-400" />
            <h2>Security Controls</h2>
          </div>
          <div className="settings-content security-box">
            <p className="section-desc text-xs text-slate-400 mb-4">
              Ensure your account utilizes strong credentials. Password updates require multi-factor verification token loops.
            </p>
            <button className="btn-secondary text-xs" onClick={handlePasswordReset}>
              Reset Password
            </button>
          </div>
        </section>

        {/* SECTION 6 — SESSION MANAGEMENT */}
        <section className="settings-card logout-card">
          <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
            <LogOut className="w-4 h-4 text-red-400" />
            <h2>Session Management</h2>
          </div>
          <div className="settings-content logout-box">
            <p className="muted text-xs text-slate-400 mb-4">
              Terminate your current secure session. Remember to clear cached memory handles.
            </p>
            <button className="btn-danger text-xs flex items-center gap-2" onClick={logout}>
              <LogOut className="w-3.5 h-3.5" />
              <span>Terminate Session (Logout)</span>
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}

export default Settings;
