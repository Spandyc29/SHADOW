import React from "react";
import { getRiskLevel, getRiskColor } from "../../utils/risk";

const RiskSummaryCard = ({ scan }) => {
  const detections = scan?.vt_detections || 0;
  const totalEngines = scan?.vt_total_engines || 0;

  const riskLevel = getRiskLevel(detections);
  const riskColor = getRiskColor(detections);

  return (
    <div className="risk-summary-card">

      <div className="risk-summary-header">
        <h2>Risk Summary</h2>

        <span className={`risk-status ${riskColor}`}>
          {riskLevel}
        </span>
      </div>

      <div className="risk-summary-grid">

        <div className="risk-item">
          <h3>Detections</h3>
          <p>{detections}</p>
        </div>

        <div className="risk-item">
          <h3>Total Engines</h3>
          <p>{totalEngines}</p>
        </div>

        <div className="risk-item">
          <h3>Detection Ratio</h3>
          <p>
            {detections} / {totalEngines}
          </p>
        </div>

      </div>

    </div>
  );
};

export default RiskSummaryCard;