import React from "react";
import { ArrowLeft } from "lucide-react";
import { getRiskLevel, getRiskColor, formatDate } from "../../utils/risk";

const ScanHeader = ({ scan, onBack }) => {
  const detections = scan?.vt_detections || 0;

  const riskLevel = getRiskLevel(detections);
  const riskColor = getRiskColor(detections);

  return (
    <div className="scan-header">

      <div className="scan-header-left">

        <button className="back-btn" onClick={onBack}>
          <ArrowLeft size={18} />
          Back
        </button>

        <div className="scan-title">
          <h1>{scan?.file_name || "Unknown File"}</h1>

          <p>
            Scanned on {formatDate(scan?.created_at)}
          </p>
        </div>

      </div>

      <div className={`risk-badge ${riskColor}`}>
        {riskLevel}
      </div>

    </div>
  );
};

export default ScanHeader;