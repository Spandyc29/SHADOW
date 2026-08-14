import React from "react";

const LoadingState = ({ message = "Loading..." }) => {
  return (
    <div className="loading-state">
      <div className="loading-spinner"></div>

      <h2>{message}</h2>

      <p>Please wait while we fetch the scan details.</p>
    </div>
  );
};

export default LoadingState;