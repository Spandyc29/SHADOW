import { useEffect, useState } from "react";
import { getScans, exportScan } from "../services/api";
import { useNavigate } from "react-router-dom";
import {
  Search,
  Filter,
  Calendar,
  ShieldCheck,
  ShieldAlert,
  FileText,
  Globe,
  Hash,
  MapPin,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
  Download,
  Eye,
  Activity,
  Crosshair,
  FileQuestion,
  RotateCcw,
} from "lucide-react";
import "../styles/history.css";

function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copiedHash, setCopiedHash] = useState(null);

  // Search, Filter & Pagination states
  const [searchQuery, setSearchQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("ALL");
  const [dateFilter, setDateFilter] = useState("ALL_TIME");
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);

  const navigate = useNavigate();

  const fetchScans = () => {
    setLoading(true);
    setError(null);
    getScans()
      .then((res) => {
        setScans(res.data.scans || []);
        setLoading(false);
      })
      .catch(() => {
        setError("Failed to load scan history.");
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const getVerdict = (scan) => {
    if (scan.vt_status === "not_found") return "Unknown";
    if (scan.vt_detections === 0) return "Clean";
    if (scan.vt_detections <= 5) return "Suspicious";
    return "Malicious";
  };

  const getVerdictBadge = (verdict) => {
    switch (verdict) {
      case "Clean":
        return (
          <span className="verdict-badge verdict-clean">
            <Check size={12} /> Clean
          </span>
        );
      case "Suspicious":
        return (
          <span className="verdict-badge verdict-suspicious">
            <ShieldAlert size={12} /> Suspicious
          </span>
        );
      case "Malicious":
        return (
          <span className="verdict-badge verdict-malicious">
            <ShieldAlert size={12} /> Malicious
          </span>
        );
      default:
        return (
          <span className="verdict-badge verdict-unknown">
            <FileQuestion size={12} /> Not Found
          </span>
        );
    }
  };

  const getTargetMeta = (targetName) => {
    if (!targetName) return { type: "HASH", Icon: Hash };
    const str = targetName.trim();
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(str)) {
      return { type: "IP ADDRESS", Icon: MapPin };
    }
    if (str.includes(".") || str.startsWith("http")) {
      return { type: "DOMAIN", Icon: Globe };
    }
    if (/^[a-fA-F0-9]{32,64}$/.test(str)) {
      return { type: "HASH", Icon: Hash };
    }
    return { type: "FILE", Icon: FileText };
  };

  const formatDateTime = (dateStr) => {
    if (!dateStr) return { date: "—", time: "" };
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return { date: dateStr, time: "" };

    const today = new Date();
    const isToday = d.toDateString() === today.toDateString();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    const isYesterday = d.toDateString() === yesterday.toDateString();

    let datePart = d.toLocaleDateString();
    if (isToday) datePart = "Today";
    else if (isYesterday) datePart = "Yesterday";

    const timePart = d.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });

    return { date: datePart, time: timePart };
  };

  const handleExport = async (id) => {
    try {
      const res = await exportScan(id);
      const blob = new Blob([JSON.stringify(res.data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scan_${id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert("Export failed.");
    }
  };

  const handleCopyHash = (hashStr) => {
    if (!hashStr) return;
    navigator.clipboard.writeText(hashStr);
    setCopiedHash(hashStr);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Dynamic Metrics Calculation from Real Data
  const totalScans = scans.length;
  const cleanFilesCount = scans.filter((s) => getVerdict(s) === "Clean").length;
  const threatsDetectedCount = scans.filter(
    (s) => getVerdict(s) === "Suspicious" || getVerdict(s) === "Malicious"
  ).length;
  const notFoundCount = scans.filter((s) => getVerdict(s) === "Unknown").length;

  // Filtered Scans
  const filteredScans = scans.filter((scan) => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      (scan.file_name && scan.file_name.toLowerCase().includes(q)) ||
      (scan.sha256 && scan.sha256.toLowerCase().includes(q)) ||
      (getVerdict(scan) && getVerdict(scan).toLowerCase().includes(q));

    const verdict = getVerdict(scan);
    let matchesVerdict = true;
    if (verdictFilter === "CLEAN") matchesVerdict = verdict === "Clean";
    else if (verdictFilter === "SUSPICIOUS") matchesVerdict = verdict === "Suspicious";
    else if (verdictFilter === "MALICIOUS") matchesVerdict = verdict === "Malicious";
    else if (verdictFilter === "NOT_FOUND") matchesVerdict = verdict === "Unknown";

    let matchesDate = true;
    if (dateFilter !== "ALL_TIME" && scan.created_at) {
      const scanDate = new Date(scan.created_at);
      const now = new Date();
      if (dateFilter === "TODAY") {
        matchesDate = scanDate.toDateString() === now.toDateString();
      } else if (dateFilter === "LAST_7_DAYS") {
        const sevenAgo = new Date();
        sevenAgo.setDate(now.getDate() - 7);
        matchesDate = scanDate >= sevenAgo;
      } else if (dateFilter === "LAST_30_DAYS") {
        const thirtyAgo = new Date();
        thirtyAgo.setDate(now.getDate() - 30);
        matchesDate = scanDate >= thirtyAgo;
      }
    }

    return matchesSearch && matchesVerdict && matchesDate;
  });

  // Reset pagination on filter change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, verdictFilter, dateFilter, rowsPerPage]);

  // Pagination Math
  const totalPages = Math.ceil(filteredScans.length / rowsPerPage) || 1;
  const validCurrentPage = Math.min(currentPage, totalPages);
  const startIndex = (validCurrentPage - 1) * rowsPerPage;
  const paginatedScans = filteredScans.slice(
    startIndex,
    startIndex + rowsPerPage
  );

  if (loading) {
    return (
      <div className="history-page">
        <div className="history-loading-container">
          <div className="spinner-ring" />
          <p className="loading-text">INTERCEPTING SCAN LOGS MATRIX...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="history-page">
        <div className="history-error-card">
          <ShieldAlert size={40} className="error-icon" />
          <h3>SCAN MATRIX UNREACHABLE</h3>
          <p>{error}</p>
          <button className="btn-retry" onClick={fetchScans}>
            <RotateCcw size={16} /> RECONNECT MATRIX
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="history-page">
      {/* HEADER SECTION */}
      <div className="history-header">
        <div className="header-title-container">
          <div className="title-row">
            <h1>SCAN HISTORY</h1>
            <Activity size={22} className="pulse-icon" />
          </div>
          <p className="subtitle">All your previous file scans and analysis results.</p>
        </div>

        {/* CONTROLS */}
        <div className="header-controls">
          <div className="search-bar-wrapper">
            <Search size={16} className="search-icon" />
            <input
              type="text"
              placeholder="Search scans..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div className="filter-dropdown-wrapper">
            <Filter size={16} className="filter-icon" />
            <select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              className="filter-select"
            >
              <option value="ALL">All Verdicts</option>
              <option value="CLEAN">Clean Only</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="MALICIOUS">Malicious</option>
              <option value="NOT_FOUND">Not Found</option>
            </select>
          </div>

          <div className="date-dropdown-wrapper">
            <Calendar size={16} className="calendar-icon" />
            <select
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value)}
              className="date-select"
            >
              <option value="ALL_TIME">All Time</option>
              <option value="TODAY">Today</option>
              <option value="LAST_7_DAYS">Last 7 Days</option>
              <option value="LAST_30_DAYS">Last 30 Days</option>
            </select>
          </div>
        </div>
      </div>

      {/* SUMMARY STATS GRID */}
      <div className="history-stats-grid">
        <div className="stat-card purple-card">
          <div className="stat-icon-badge purple-badge">
            <Crosshair size={22} />
          </div>
          <div className="stat-content">
            <span className="stat-label">TOTAL SCANS</span>
            <span className="stat-value">{totalScans}</span>
            <span className="stat-trend trend-purple">↗ Active scan log matrix</span>
          </div>
        </div>

        <div className="stat-card green-card">
          <div className="stat-icon-badge green-badge">
            <ShieldCheck size={22} />
          </div>
          <div className="stat-content">
            <span className="stat-label">CLEAN FILES</span>
            <span className="stat-value">{cleanFilesCount}</span>
            <span className="stat-trend trend-green">✓ Verified clear payloads</span>
          </div>
        </div>

        <div className="stat-card red-card">
          <div className="stat-icon-badge red-badge">
            <ShieldAlert size={22} />
          </div>
          <div className="stat-content">
            <span className="stat-label">THREATS DETECTED</span>
            <span className="stat-value">{threatsDetectedCount}</span>
            <span className="stat-trend trend-red">⚠ High-risk flags</span>
          </div>
        </div>

        <div className="stat-card blue-card">
          <div className="stat-icon-badge blue-badge">
            <FileQuestion size={22} />
          </div>
          <div className="stat-content">
            <span className="stat-label">NOT FOUND</span>
            <span className="stat-value">{notFoundCount}</span>
            <span className="stat-trend trend-blue">? Unindexed targets</span>
          </div>
        </div>
      </div>

      {/* DATA TABLE CONTAINER */}
      <div className="history-table-card">
        {filteredScans.length === 0 ? (
          <div className="empty-state-panel">
            <FileQuestion size={48} className="empty-icon" />
            {scans.length === 0 ? (
              <>
                <h3>NO SCAN RECORDS FOUND</h3>
                <p>Upload a file or analyze a target hash/domain to populate your history.</p>
                <button
                  className="btn-primary-action"
                  onClick={() => navigate("/upload")}
                >
                  START NEW SCAN
                </button>
              </>
            ) : (
              <>
                <h3>NO MATCHING SCANS FOUND</h3>
                <p>Try adjusting your search criteria or filter parameters.</p>
                <button
                  className="btn-secondary-action"
                  onClick={() => {
                    setSearchQuery("");
                    setVerdictFilter("ALL");
                    setDateFilter("ALL_TIME");
                  }}
                >
                  RESET FILTERS
                </button>
              </>
            )}
          </div>
        ) : (
          <>
            <div className="table-responsive-wrapper">
              <table className="scan-data-table">
                <thead>
                  <tr>
                    <th>FILE / TARGET</th>
                    <th>VERDICT</th>
                    <th>DETECTIONS</th>
                    <th>SHA256</th>
                    <th>DATE</th>
                    <th className="text-center">EXPORT</th>
                    <th className="text-center">ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedScans.map((scan) => {
                    const verdict = getVerdict(scan);
                    const { type, Icon } = getTargetMeta(scan.file_name);
                    const { date, time } = formatDateTime(scan.created_at);
                    const hasDetections = (scan.vt_detections ?? 0) > 0;

                    return (
                      <tr key={scan.id} className="table-row">
                        {/* FILE / TARGET */}
                        <td className="target-cell">
                          <div className="target-icon-box">
                            <Icon size={18} />
                          </div>
                          <div className="target-info">
                            <span className="target-name" title={scan.file_name}>
                              {scan.file_name}
                            </span>
                            <span className="target-type-tag">{type}</span>
                          </div>
                        </td>

                        {/* VERDICT */}
                        <td>{getVerdictBadge(verdict)}</td>

                        {/* DETECTIONS */}
                        <td className="detections-cell">
                          <span
                            className={
                              hasDetections
                                ? "detection-count threat"
                                : "detection-count clean"
                            }
                          >
                            {scan.vt_detections ?? 0}
                          </span>
                          <span className="detection-total">
                            / {scan.vt_total_engines ?? 75}
                          </span>
                        </td>

                        {/* SHA256 */}
                        <td className="hash-cell">
                          {scan.sha256 ? (
                            <div className="hash-copy-wrapper">
                              <span className="hash-text">
                                {scan.sha256.slice(0, 16)}...
                              </span>
                              <button
                                className="btn-copy-hash"
                                onClick={() => handleCopyHash(scan.sha256)}
                                title="Copy full SHA256"
                              >
                                {copiedHash === scan.sha256 ? (
                                  <Check size={14} className="copied-icon" />
                                ) : (
                                  <Copy size={14} />
                                )}
                              </button>
                            </div>
                          ) : (
                            <span className="no-hash">—</span>
                          )}
                        </td>

                        {/* DATE */}
                        <td className="date-cell">
                          <span className="date-main">{date}</span>
                          {time && <span className="time-sub">{time}</span>}
                        </td>

                        {/* EXPORT */}
                        <td className="text-center">
                          <button
                            className="btn-export-json"
                            onClick={() => handleExport(scan.id)}
                            title="Export JSON payload"
                          >
                            <Download size={14} />
                            <span>JSON</span>
                          </button>
                        </td>

                        {/* ACTION */}
                        <td className="text-center">
                          <button
                            className="btn-view-scan"
                            onClick={() =>
                              navigate(`/upload/result/${scan.id}`)
                            }
                            title="View complete analysis report"
                          >
                            <Eye size={14} />
                            <span>View</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* PAGINATION FOOTER */}
            <div className="history-pagination-bar">
              <div className="pagination-info">
                Showing{" "}
                <span className="highlight">
                  {filteredScans.length === 0 ? 0 : startIndex + 1}
                </span>{" "}
                to{" "}
                <span className="highlight">
                  {Math.min(startIndex + rowsPerPage, filteredScans.length)}
                </span>{" "}
                of <span className="highlight">{filteredScans.length}</span>{" "}
                results
              </div>

              <div className="pagination-controls">
                <button
                  className="page-nav-btn"
                  disabled={validCurrentPage <= 1}
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  aria-label="Previous Page"
                >
                  <ChevronLeft size={16} />
                </button>

                {Array.from({ length: totalPages }, (_, i) => i + 1)
                  .filter((page) => {
                    if (totalPages <= 7) return true;
                    if (page === 1 || page === totalPages) return true;
                    if (Math.abs(page - validCurrentPage) <= 1) return true;
                    return false;
                  })
                  .reduce((acc, page, idx, arr) => {
                    if (idx > 0 && page - arr[idx - 1] > 1) {
                      acc.push("...");
                    }
                    acc.push(page);
                    return acc;
                  }, [])
                  .map((item, index) =>
                    item === "..." ? (
                      <span key={`ellipsis-${index}`} className="page-ellipsis">
                        ...
                      </span>
                    ) : (
                      <button
                        key={item}
                        className={`page-num-btn ${
                          item === validCurrentPage ? "active" : ""
                        }`}
                        onClick={() => setCurrentPage(item)}
                      >
                        {item}
                      </button>
                    )
                  )}

                <button
                  className="page-nav-btn"
                  disabled={validCurrentPage >= totalPages}
                  onClick={() =>
                    setCurrentPage((p) => Math.min(totalPages, p + 1))
                  }
                  aria-label="Next Page"
                >
                  <ChevronRight size={16} />
                </button>
              </div>

              <div className="rows-per-page-wrapper">
                <span>Rows per page:</span>
                <select
                  value={rowsPerPage}
                  onChange={(e) => setRowsPerPage(Number(e.target.value))}
                  className="rows-select"
                >
                  <option value={5}>5</option>
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                </select>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default ScanHistory;