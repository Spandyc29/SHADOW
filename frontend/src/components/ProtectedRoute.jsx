import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

function ProtectedRoute({ children }) {
  const { user, isGuest } = useAuth();
  const location = useLocation();

  // If unauthorized entirely (neither authenticated nor guest), route back to Login
  if (!user && !isGuest) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Account-only persistent routes that guests cannot access
  const accountOnlyPaths = ["/history", "/settings"];
  const isAccountOnlyRoute = accountOnlyPaths.some((path) =>
    location.pathname.startsWith(path)
  );

  if (isGuest && isAccountOnlyRoute) {
    return <Navigate to="/access-denied" replace />;
  }

  return children;
}

export default ProtectedRoute;
