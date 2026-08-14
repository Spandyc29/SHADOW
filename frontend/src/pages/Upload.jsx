import { useState, useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import AnalysisResult from "../components/analysis/AnalysisResult";
import ErrorState from "../components/analysis/common/ErrorState";
import LoadingState from "../components/analysis/common/LoadingState";
import NotFoundState from "../components/analysis/common/NotFoundState";

import { uploadFile, analyzeHash, analyzeUrl } from "../services/api";
import { analyzeDomain } from "../services/domainApi";
import { analyzeIp } from "../services/ipApi";
import { useAuth } from "../context/AuthContext";
import "../styles/upload.css";

function joinList(value) {
  return Array.isArray(value) ? value.join(", ") : value;
}

function getAnalysisPayload(payload) {
  return payload?.result || payload?.analysis || payload?.vt_result || payload;
}

function getFileTypeName(value) {
  if (!value) {
    return undefined;
  }

  return typeof value === "object" ? value.type : value;
}

function Upload() {
  const location = useLocation();
  const navigate = useNavigate();
  const [analysisType, setAnalysisType] = useState("file");
  const [file, setFile] = useState(null);
  const [hash, setHash] = useState("");
  const [url, setUrl] = useState("");
  const [domain, setDomain] = useState("");
  const [ip, setIp] = useState("");
  const [submittedIndicator, setSubmittedIndicator] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [metadata, setMetadata] = useState({});
  const [state, setState] = useState({ type: "idle", message: "" });
  const {
    isGuest,
    user,
    guestScanCount,
    guestScanLimit,
    hasReachedGuestLimit,
    incrementGuestScanCount,
  } = useAuth();

  useEffect(() => {
    const restored = location.state?.result || location.state?.analysisResult;
    if (restored && !result) {
      setResult(restored);
      const ind = restored.indicator || restored.file_name || "";
      setSubmittedIndicator(ind);
      setMetadata({
        title: "File Intelligence Report",
        indicatorLabel: "File",
        indicatorValue: ind,
        indicatorType: restored.indicator_type || "File",
        scanId: restored.scan_id,
        scannedAt: restored.scanned_at,
      });
    }
  }, [location.state]);

  const resetResult = () => {
    setResult(null);
    setMetadata({});
    setState({ type: "idle", message: "" });
  };

  const resetInvestigation = () => {
    setFile(null);
    setHash("");
    setUrl("");
    setDomain("");
    setIp("");
    setSubmittedIndicator("");
    resetResult();
  };

  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
    resetResult();
  };

  const buildMetadata = (payload, analysis, submitted, type) => ({
    analysisType: type,
    title:
      type === "file"
        ? "File Intelligence Report"
        : type === "url"
          ? "URL Intelligence Report"
          : type === "domain"
            ? "Domain Intelligence Report"
            : type === "ip"
              ? "IP Intelligence Report"
              : "Hash Intelligence Report",
    indicatorLabel:
      type === "file"
        ? "File"
        : type === "url"
          ? "URL"
          : type === "domain"
            ? "Domain"
            : type === "ip"
              ? "IP"
              : "Hash",
    indicatorValue:
      type === "file"
        ? payload?.file_name || analysis?.file_name || submitted
        : type === "url"
          ? payload?.url || analysis?.url || analysis?.indicator || submitted
          : type === "domain"
            ? payload?.domain || analysis?.domain || analysis?.indicator || submitted
            : type === "ip"
              ? payload?.ip || analysis?.ip || analysis?.indicator || submitted
              : submitted || analysis?.indicator,
    indicatorType:
      type === "file"
        ? getFileTypeName(analysis?.file_type || payload?.file_type) || payload?.mime_type || "File"
        : type === "url"
          ? "URL"
          : type === "domain"
            ? "Domain"
            : type === "ip"
              ? "IP"
              : payload?.hash_type || analysis?.hash_type || analysis?.indicator_type,
    scanId: payload?.scan_id || payload?.id || analysis?.scan_id,
    scannedAt: payload?.scanned_at || payload?.created_at || analysis?.scanned_at || analysis?.created_at,
  });

  const buildBasicProperties = (payload, analysis, meta) => {
    if (meta.analysisType === "file") {
      return [
        { label: "File Name", value: payload?.file_name || analysis?.file_name || meta.indicatorValue },
        { label: "File Size", value: payload?.file_size || analysis?.file_size },
        { label: "File Type", value: getFileTypeName(analysis?.file_type || payload?.file_type) },
        { label: "MIME Type", value: analysis?.file_type?.mime || payload?.file_type?.mime || payload?.mime_type || analysis?.mime_type },
        { label: "MD5", value: payload?.hashes?.md5 || payload?.md5 || analysis?.md5 },
        { label: "SHA1", value: payload?.hashes?.sha1 || payload?.sha1 || analysis?.sha1 },
        { label: "SHA256", value: payload?.hashes?.sha256 || payload?.sha256 || analysis?.sha256 || analysis?.indicator },
      ];
    }

    if (meta.analysisType === "url") {
      const urlInfo = analysis?.url_info || {};

      return [
        { label: "URL", value: meta.indicatorValue || analysis?.indicator },
        { label: "Protocol", value: urlInfo.protocol },
        { label: "Host", value: urlInfo.host },
        { label: "Domain", value: urlInfo.domain },
        { label: "Path", value: urlInfo.path },
        { label: "Query", value: urlInfo.query },
        { label: "Fragment", value: urlInfo.fragment },
        { label: "Port", value: urlInfo.port },
        { label: "URL Length", value: urlInfo.url_length },
        { label: "Community Reputation", value: analysis?.community_reputation },
      ];
    }

    if (meta.analysisType === "ip") {
      const ipInfo = analysis?.ip_info || {};

      return [
        { label: "IP Address", value: meta.indicatorValue || analysis?.indicator },
        { label: "IP Version", value: ipInfo.version },
        { label: "ASN", value: ipInfo.asn },
        { label: "AS Owner", value: ipInfo.as_owner },
        { label: "Country", value: ipInfo.country },
        { label: "Network", value: ipInfo.network },
        { label: "Reverse DNS", value: ipInfo.reverse_dns },
      ];
    }

    return [
      { label: "Hash", value: meta.indicatorValue || analysis?.indicator },
      { label: "Hash Type", value: meta.indicatorType },
      { label: "Meaningful Name", value: analysis?.meaningful_name },
      { label: "Associated Names", value: joinList(analysis?.associated_names) },
      { label: "File Type", value: analysis?.file_type },
      { label: "File Size", value: analysis?.file_size },
    ];
  };

  const handleAnalysisResponse = (payload, submitted, type) => {
    const analysis = getAnalysisPayload(payload);
    const meta = buildMetadata(payload, analysis, submitted, type);
    const scanId = payload?.scan_id || payload?.id || analysis?.scan_id || meta.scanId;

    setMetadata({
      ...meta,
      basicProperties: buildBasicProperties(payload, analysis, meta),
    });

    if (type === "hash" && analysis?.status === "not_found") {
      setState({ type: "not_found", message: "" });
      return;
    }

    if (analysis?.status === "rate_limited") {
      setState({
        type: "rate_limited",
        message: "The intelligence provider rate limit was reached. Try again later.",
      });
      return;
    }

    if (analysis?.status === "error") {
      setState({
        type: "error",
        message: "The backend returned an analysis error status.",
      });
      return;
    }

    if (isGuest && incrementGuestScanCount) {
      incrementGuestScanCount();
    }

    if (scanId) {
      navigate(`/upload/result/${scanId}`);
    } else {
      setResult(analysis);
    }
  };

  const checkGuestLimit = () => {
    if (isGuest && hasReachedGuestLimit) {
      setState({
        type: "guest_limit",
        message: `Trial Scan Limit Reached (${guestScanCount} of ${guestScanLimit} scans used). Please sign in or create an account for full access.`,
      });
      return true;
    }
    return false;
  };

  const requestConfig = {
    headers: {
      "x-guest-mode": isGuest ? "true" : "false",
    },
  };

  const handleUpload = async () => {
    if (checkGuestLimit()) return;

    if (!file) {
      setState({ type: "error", message: "Please select a file first." });
      return;
    }

    setLoading(true);
    setResult(null);
    setMetadata({});
    setState({ type: "idle", message: "" });
    setSubmittedIndicator(file.name);

    try {
      const response = await uploadFile(file, requestConfig);
      handleAnalysisResponse(response.data, file.name, "file");
    } catch (error) {
      setState({
        type: error.response?.status === 429 ? "rate_limited" : "error",
        message: error.response?.data?.detail || error.message || "Upload failed. Please try again.",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleHashAnalysis = async () => {
    if (checkGuestLimit()) return;

    const hashValue = hash.trim();

    if (!hashValue) {
      setState({ type: "error", message: "Please enter a hash." });
      return;
    }

    setLoading(true);
    setResult(null);
    setMetadata({});
    setState({ type: "idle", message: "" });
    setSubmittedIndicator(hashValue);

    try {
      const response = await analyzeHash(hashValue, requestConfig);
      handleAnalysisResponse(response.data, hashValue, "hash");
    } catch (error) {
      setState({
        type: error.response?.status === 429 ? "rate_limited" : "error",
        message: error.response?.data?.detail || error.message || "Hash analysis failed.",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleUrlAnalysis = async () => {
    if (checkGuestLimit()) return;

    const urlValue = url.trim();

    if (!urlValue) {
      setState({ type: "error", message: "Please enter a URL." });
      return;
    }

    setLoading(true);
    setResult(null);
    setMetadata({});
    setState({ type: "idle", message: "" });
    setSubmittedIndicator(urlValue);

    try {
      const response = await analyzeUrl(urlValue, requestConfig);
      handleAnalysisResponse(response.data, urlValue, "url");
    } catch (error) {
      setState({
        type: error.response?.status === 429 ? "rate_limited" : "error",
        message: error.response?.data?.detail || error.message || "URL analysis failed.",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleDomainAnalysis = async () => {
    if (checkGuestLimit()) return;

    const domainValue = domain.trim();

    if (!domainValue) {
      setState({ type: "error", message: "Please enter a domain." });
      return;
    }

    setLoading(true);
    setResult(null);
    setMetadata({});
    setState({ type: "idle", message: "" });
    setSubmittedIndicator(domainValue);

    try {
      const response = await analyzeDomain(domainValue, requestConfig);
      handleAnalysisResponse(response.data, domainValue, "domain");
    } catch (error) {
      setState({
        type: error.response?.status === 429 ? "rate_limited" : "error",
        message: error.response?.data?.detail || error.message || "Domain analysis failed.",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleIpAnalysis = async () => {
    if (checkGuestLimit()) return;

    const ipValue = ip.trim();

    if (!ipValue) {
      setState({ type: "error", message: "Please enter an IP address." });
      return;
    }

    setLoading(true);
    setResult(null);
    setMetadata({});
    setState({ type: "idle", message: "" });
    setSubmittedIndicator(ipValue);

    try {
      const response = await analyzeIp(ipValue, requestConfig);
      handleAnalysisResponse(response.data, ipValue, "ip");
    } catch (error) {
      setState({
        type: error.response?.status === 429 ? "rate_limited" : "error",
        message: error.response?.data?.detail || error.message || "IP analysis failed.",
      });
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="upload-page result-page">
        <LoadingState message="Building investigation report..." />
      </div>
    );
  }

  if (result) {
    return (
      <div className="upload-page result-page">
        <AnalysisResult
          result={result}
          title={metadata.title}
          indicatorLabel={metadata.indicatorLabel}
          indicatorValue={metadata.indicatorValue}
          indicatorType={metadata.indicatorType}
          scanId={metadata.scanId}
          scannedAt={metadata.scannedAt}
          showScanId={Boolean(user)}
          basicProperties={metadata.basicProperties}
          onBack={resetResult}
          onNewScan={resetInvestigation}
        />
      </div>
    );
  }

  return (
    <div className="upload-page">
      {isGuest && (
        <div className="guest-alert-banner">
          <span className="banner-icon">⚡</span>
          <div className="banner-content">
            <strong>GUEST TRIAL SESSION ({guestScanCount} of {guestScanLimit} Scans Executed):</strong>{" "}
            {hasReachedGuestLimit
              ? "You've reached your 3 free trial scans limit. Please sign in or create a profile for unlimited scans."
              : "Temporary trial session active. Create an account for persistent scan history and profile access."}
          </div>
        </div>
      )}

      {state.type === "guest_limit" && (
        <div className="banner-error" style={{ background: "rgba(139, 92, 246, 0.15)", border: "1px solid rgba(139, 92, 246, 0.4)", color: "#ffffff", padding: "20px", borderRadius: "12px", margin: "20px 0", textAlign: "center" }}>
          <h3 style={{ margin: "0 0 8px 0", fontSize: "1.1rem", color: "#22d3ee" }}>⚡ Trial Scan Limit Reached ({guestScanCount} of {guestScanLimit})</h3>
          <p style={{ margin: "0 0 16px 0", fontSize: "0.9rem", color: "#94a3b8" }}>
            You've used all {guestScanLimit} free trial scans for this guest session. Create a profile or sign in to unlock unlimited scans and persistent history.
          </p>
          <div style={{ display: "flex", justifyContent: "center", gap: "12px" }}>
            <button
              type="button"
              onClick={() => navigate("/login")}
              className="btn-primary"
              style={{ padding: "8px 18px", fontSize: "0.85rem" }}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => navigate("/register")}
              className="btn-guest-access"
              style={{ width: "auto", padding: "8px 18px", fontSize: "0.85rem" }}
            >
              Create Profile
            </button>
          </div>
        </div>
      )}

      <header className="upload-header">
        <div className="header-title-group">
          <h1>Upload Scan</h1>
          <span className="system-badge">SHADOW ENGINE v2.4</span>
        </div>
        <p>Start an investigation by uploading a file, cryptographic hash, URL, domain, or IP address.</p>
      </header>

      <section className="investigation-input-panel">
        <div className="analysis-tabs">
          <button
            type="button"
            className={`analysis-tab ${analysisType === "file" ? "active" : ""}`}
            onClick={() => {
              setAnalysisType("file");
              resetResult();
            }}
          >
            File Analysis
          </button>

          <button
            type="button"
            className={`analysis-tab ${analysisType === "hash" ? "active" : ""}`}
            onClick={() => {
              setAnalysisType("hash");
              resetResult();
            }}
          >
            Hash Analysis
          </button>

          <button
            type="button"
            className={`analysis-tab ${analysisType === "url" ? "active" : ""}`}
            onClick={() => {
              setAnalysisType("url");
              resetResult();
            }}
          >
            URL Analysis
          </button>

          <button
            type="button"
            className={`analysis-tab ${analysisType === "domain" ? "active" : ""}`}
            onClick={() => {
              setAnalysisType("domain");
              resetResult();
            }}
          >
            Domain Analysis
          </button>

          <button
            type="button"
            className={`analysis-tab ${analysisType === "ip" ? "active" : ""}`}
            onClick={() => {
              setAnalysisType("ip");
              resetResult();
            }}
          >
            IP Analysis
          </button>
        </div>

        {analysisType === "file" && (
          <div className="upload-card">
            <div className="upload-dropzone">
              <input type="file" onChange={handleFileChange} id="file-input-field" />
              <label htmlFor="file-input-field" className="dropzone-label">
                <div className="upload-icon-wrapper">
                  <span className="upload-icon">+</span>
                </div>
                <h3>Drop file here or click to inspect</h3>
                <p className="dropzone-subtext">
                  Supports binary, executable, script, and compressed formats up to 64MB.
                </p>
                {file && (
                  <div className="file-selected-badge">
                    <span className="file-icon">File</span>
                    <span className="file-name">{file.name}</span>
                  </div>
                )}
              </label>
            </div>

            <div className="action-bar">
              <button className="upload-btn" onClick={handleUpload} disabled={loading || !file}>
                {loading ? (
                  <span className="btn-loading">
                    <span className="spinner"></span> Executing Analysis...
                  </span>
                ) : (
                  "Analyze File"
                )}
              </button>
            </div>
          </div>
        )}

        {analysisType === "hash" && (
          <div className="upload-card">
            <div className="hash-card">
              <div className="hash-header">
                <div className="upload-icon-wrapper">
                  <span className="upload-icon">#</span>
                </div>
                <div className="hash-header-text">
                  <h3>Hash Analysis</h3>
                  <p>Query SHADOW Threat Intelligence for legacy and active file signatures.</p>
                </div>
              </div>

              <div className="hash-input-group">
                <label className="hash-label">Cryptographic Hash</label>
                <input
                  type="text"
                  className="hash-input"
                  placeholder="Paste MD5, SHA1, or SHA256 string..."
                  value={hash}
                  onChange={(event) => {
                    setHash(event.target.value);
                    resetResult();
                  }}
                />
              </div>

              <div className="hash-info">
                <span className="info-title">Supported Formats:</span>
                <div className="hash-chips">
                  <span className="chip">MD5</span>
                  <span className="chip">SHA1</span>
                  <span className="chip">SHA256</span>
                </div>
              </div>
            </div>

            <div className="action-bar">
              <button className="upload-btn" onClick={handleHashAnalysis} disabled={loading || !hash.trim()}>
                {loading ? (
                  <span className="btn-loading">
                    <span className="spinner"></span> Querying Intelligence...
                  </span>
                ) : (
                  "Analyze Hash"
                )}
              </button>
            </div>
          </div>
        )}

        {analysisType === "url" && (
          <div className="upload-card">
            <div className="hash-card">
              <div className="hash-header">
                <div className="upload-icon-wrapper">
                  <span className="upload-icon">URL</span>
                </div>
                <div className="hash-header-text">
                  <h3>URL Analysis</h3>
                  <p>Query SHADOW Threat Intelligence for suspicious links and web indicators.</p>
                </div>
              </div>

              <div className="hash-input-group">
                <label className="hash-label">URL</label>
                <input
                  type="text"
                  className="hash-input"
                  placeholder="https://example.com/login"
                  value={url}
                  onChange={(event) => {
                    setUrl(event.target.value);
                    resetResult();
                  }}
                />
              </div>

              <div className="hash-info">
                <span className="info-title">Normalization:</span>
                <div className="hash-chips">
                  <span className="chip">google.com -&gt; https://google.com</span>
                </div>
              </div>
            </div>

            <div className="action-bar">
              <button className="upload-btn" onClick={handleUrlAnalysis} disabled={loading || !url.trim()}>
                {loading ? (
                  <span className="btn-loading">
                    <span className="spinner"></span> Querying Intelligence...
                  </span>
                ) : (
                  "Analyze URL"
                )}
              </button>
            </div>
          </div>
        )}

        {analysisType === "domain" && (
          <div className="upload-card">
            <div className="hash-card">
              <div className="hash-header">
                <div className="upload-icon-wrapper">
                  <span className="upload-icon">Domain</span>
                </div>
                <div className="hash-header-text">
                  <h3>Domain Analysis</h3>
                  <p>Query SHADOW Threat Intelligence for WHOIS, DNS, and domain metadata.</p>
                </div>
              </div>

              <div className="hash-input-group">
                <label className="hash-label">Domain Name</label>
                <input
                  type="text"
                  className="hash-input"
                  placeholder="example.com"
                  value={domain}
                  onChange={(event) => {
                    setDomain(event.target.value);
                    resetResult();
                  }}
                />
              </div>

              <div className="hash-info">
                <span className="info-title">Examples:</span>
                <div className="hash-chips">
                  <span className="chip">google.com</span>
                  <span className="chip">example.org</span>
                </div>
              </div>
            </div>

            <div className="action-bar">
              <button className="upload-btn" onClick={handleDomainAnalysis} disabled={loading || !domain.trim()}>
                {loading ? (
                  <span className="btn-loading">
                    <span className="spinner"></span> Querying Intelligence...
                  </span>
                ) : (
                  "Analyze Domain"
                )}
              </button>
            </div>
          </div>
        )}

        {analysisType === "ip" && (
          <div className="upload-card">
            <div className="hash-card">
              <div className="hash-header">
                <div className="upload-icon-wrapper">
                  <span className="upload-icon">IP</span>
                </div>
                <div className="hash-header-text">
                  <h3>IP Intelligence</h3>
                  <p>Query SHADOW Threat Intelligence for reverse DNS, geolocation, and IP metadata.</p>
                </div>
              </div>

              <div className="hash-input-group">
                <label className="hash-label">IP Address</label>
                <input
                  type="text"
                  className="hash-input"
                  placeholder="8.8.8.8"
                  value={ip}
                  onChange={(event) => {
                    setIp(event.target.value);
                    resetResult();
                  }}
                />
              </div>

              <div className="hash-info">
                <span className="info-title">Examples:</span>
                <div className="hash-chips">
                  <span className="chip">8.8.8.8</span>
                  <span className="chip">1.1.1.1</span>
                  <span className="chip">2001:4860:4860::8888</span>
                </div>
              </div>
            </div>

            <div className="action-bar">
              <button className="upload-btn" onClick={handleIpAnalysis} disabled={loading || !ip.trim()}>
                {loading ? (
                  <span className="btn-loading">
                    <span className="spinner"></span> Querying Intelligence...
                  </span>
                ) : (
                  "Analyze IP"
                )}
              </button>
            </div>
          </div>
        )}
      </section>

      <div className="investigation-result-area">
        {!loading && state.type === "not_found" && <NotFoundState hash={submittedIndicator} />}

        {!loading && state.type === "rate_limited" && (
          <ErrorState title="Rate Limited" message={state.message} />
        )}

        {!loading && state.type === "error" && (
          <ErrorState title="Unable to analyze indicator" message={state.message} />
        )}
      </div>
    </div>
  );
}

export default Upload;
