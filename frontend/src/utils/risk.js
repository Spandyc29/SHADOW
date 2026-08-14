// Returns risk level based on VirusTotal detections
export const getRiskLevel = (detections) => {
  if (detections === 0) return "Safe";
  if (detections <= 5) return "Suspicious";
  return "Malicious";
};

// Returns color class for badges/cards
export const getRiskColor = (detections) => {
  if (detections === 0) return "green";
  if (detections <= 5) return "yellow";
  return "red";
};

// Converts bytes into readable size
export const formatFileSize = (bytes) => {
  if (!bytes || bytes === 0) return "0 Bytes";

  const units = ["Bytes", "KB", "MB", "GB", "TB"];
  const index = Math.floor(Math.log(bytes) / Math.log(1024));

  return `${(bytes / Math.pow(1024, index)).toFixed(2)} ${units[index]}`;
};

// Formats ISO date into readable format
export const formatDate = (dateString) => {
  if (!dateString) return "N/A";

  return new Date(dateString).toLocaleString();
};