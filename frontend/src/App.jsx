import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import ProtectedRoute from "./components/ProtectedRoute";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import Register from "./pages/Register";
import ScanHistory from "./pages/ScanHistory";
import Upload from "./pages/Upload";
import ScanResult from "./pages/ScanResult";
import ScanDetails from "./pages/ScanDetails";
import Settings from "./pages/Settings";
import AccessDenied from "./pages/AccessDenied";
import HashAnalysis from "./pages/HashAnalysis";
import URLAnalysis from "./pages/URLAnalysis";
import DomainAnalysis from "./pages/DomainAnalysis";
import IPAnalysis from "./pages/IPAnalysis";
import ReportPreview from "./pages/ReportPreview";
import { ScanContextProvider } from "./context/ScanContext";

function App() {
  
  return (
    <ScanContextProvider>
      <BrowserRouter>
        <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/access-denied" element={<AccessDenied />} />
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
           <Route path="/scan/:id" element={<ScanDetails />} />
           <Route path="settings" element={<Settings />} />
         
          <Route
            path="dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="upload"
            element={
              <ProtectedRoute>
                <Upload />
              </ProtectedRoute>
            }
          />
          <Route
            path="upload/result/:scanId"
            element={
              <ProtectedRoute>
                <ScanResult />
              </ProtectedRoute>
            }
          />
          <Route
            path="hash-analysis"
            element={
              <ProtectedRoute>
                <HashAnalysis />
              </ProtectedRoute>
            }
          />
          <Route
            path="url-analysis"
            element={
              <ProtectedRoute>
                <URLAnalysis />
              </ProtectedRoute>
            }
          />
          <Route
            path="domain-analysis"
            element={
              <ProtectedRoute>
                <DomainAnalysis />
              </ProtectedRoute>
            }
          />
          <Route
            path="ip-analysis"
            element={
              <ProtectedRoute>
                <IPAnalysis />
              </ProtectedRoute>
            }
          />
          <Route
            path="report-preview"
            element={
              <ProtectedRoute>
                <ReportPreview />
              </ProtectedRoute>
            }
          />

          <Route
  path="history"  // "scans" → "history"
  element={
    <ProtectedRoute>
      <ScanHistory />
    </ProtectedRoute>
  }
/>
        </Route>
      </Routes>
    </BrowserRouter>
  </ScanContextProvider>
);
}




export default App;
