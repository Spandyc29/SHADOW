import React from "react";

const VirusTotalCard = ({ scan }) => {
  const detections = scan?.vt_detections || 0;
  const totalEngines = scan?.vt_total_engines || 0;
  const vtLink = scan?.vt_permalink;
  const status = scan?.vt_status || "Unknown";

  return (
    <div className="vt-card">

      <div className="vt-header">
        <h2>VirusTotal Analysis</h2>

        <span className={`vt-status ${status}`}>
          {status}
        </span>
      </div>

      <div className="vt-grid">

        <div className="vt-item">
          <h3>Detections</h3>
          <p>{detections}</p>
        </div>

        <div className="vt-item">
          <h3>Total Engines</h3>
          <p>{totalEngines}</p>
        </div>

        <div className="vt-item">
          <h3>Detection Ratio</h3>
          <p>
            {detections} / {totalEngines}
          </p>
        </div>

      </div>

      {vtLink && (
        <div className="vt-footer">
          <a
            href={vtLink}
            target="_blank"
            rel="noopener noreferrer"
            className="vt-btn"
          >
            Open in VirusTotal
          </a>
        </div>
      )}

    </div>
  );
};

export default VirusTotalCard;