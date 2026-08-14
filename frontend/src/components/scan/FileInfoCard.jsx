import React from "react";
import { formatFileSize } from "../../utils/risk";

const FileInfoCard = ({ scan }) => {

  const copyToClipboard = (text) => {
    if (!text) return;

    navigator.clipboard.writeText(text);
    alert("Copied to clipboard!");
  };

  return (
    <div className="file-info-card">

      <h2>File Information</h2>

      <div className="file-info-grid">

        <div className="info-row">
          <span>File Name</span>
          <strong>{scan?.file_name || "N/A"}</strong>
        </div>

        <div className="info-row">
          <span>File Size</span>
          <strong>{formatFileSize(scan?.file_size)}</strong>
        </div>

        <div className="info-row">
          <span>File Type</span>
          <strong>{scan?.file_type || "Unknown"}</strong>
        </div>

        <div className="info-row hash-row">
          <span>MD5</span>

          <div className="hash-value">
            <code>{scan?.md5 || "N/A"}</code>

            <button onClick={() => copyToClipboard(scan?.md5)}>
              Copy
            </button>
          </div>
        </div>

        <div className="info-row hash-row">
          <span>SHA1</span>

          <div className="hash-value">
            <code>{scan?.sha1 || "N/A"}</code>

            <button onClick={() => copyToClipboard(scan?.sha1)}>
              Copy
            </button>
          </div>
        </div>

        <div className="info-row hash-row">
          <span>SHA256</span>

          <div className="hash-value">
            <code>{scan?.sha256 || "N/A"}</code>

            <button onClick={() => copyToClipboard(scan?.sha256)}>
              Copy
            </button>
          </div>
        </div>

      </div>

    </div>
  );
};

export default FileInfoCard;