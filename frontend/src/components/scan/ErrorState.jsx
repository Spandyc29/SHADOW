import React from "react";

const ErrorState = ({
  title = "Something went wrong",
  message = "We couldn't load the requested data.",
  onRetry,
}) => {
  return (
    <div className="error-state">
      <div className="error-icon">⚠️</div>

      <h2>{title}</h2>

      <p>{message}</p>

      {onRetry && (
        <button className="retry-btn" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
};

export default ErrorState;