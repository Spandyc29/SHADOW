import React from "react";
import { formatDate } from "../../utils/risk";

const MetadataCard = ({ scan }) => {
  return (
    <div className="metadata-card">

      <h2>File Metadata</h2>

      <div className="metadata-grid">

        <div className="metadata-item">
          <span>File Type</span>
          <strong>{scan?.file_type || "N/A"}</strong>
        </div>

        <div className="metadata-item">
          <span>MIME Type</span>
          <strong>{scan?.mime_type || "N/A"}</strong>
        </div>

        <div className="metadata-item">
          <span>Extension</span>
          <strong>{scan?.extension || "N/A"}</strong>
        </div>

        <div className="metadata-item">
          <span>Entropy</span>
          <strong>{scan?.entropy ?? "N/A"}</strong>
        </div>

        <div className="metadata-item">
          <span>Uploaded At</span>
          <strong>{formatDate(scan?.created_at)}</strong>
        </div>

        <div className="metadata-item">
          <span>Last Updated</span>
          <strong>{formatDate(scan?.updated_at)}</strong>
        </div>

      </div>

    </div>
  );
};

export default MetadataCard;