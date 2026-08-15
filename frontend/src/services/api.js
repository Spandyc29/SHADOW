import axios from "axios";
import { supabase } from "../supabaseClient";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "https://shadow-581b.onrender.com",
});

// Har request mein token automatically add hoga
api.interceptors.request.use(async (config) => {
  try {
    const { data } = await supabase.auth.getSession();
    const token = data?.session?.access_token;
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  } catch (error) {
    console.error("Error retrieving Supabase session token:", error);
  }
  return config;
});

// Auth APIs
export const registerUser = (email, password) =>
  api.post("/auth/register", { email, password });

export const loginUser = (email, password) =>
  api.post("/auth/login", { email, password });

export const logoutUser = () =>
  api.post("/auth/logout");

// File APIs (Injected with runtime config parameters for Guest interception)
export const uploadFile = (file, config = {}) => {
  const formData = new FormData();
  formData.append("file", file);

  return api.post("/files/upload", formData, {
    ...config, // Spreads parent configs safely over core axios requests
    headers: {
      "Content-Type": "multipart/form-data",
      ...config.headers, // Merges custom headers map like 'x-guest-mode' safely
    },
  });
};

// Hash Analysis API
export const analyzeHash = (hash, config = {}) => {
  return api.post(
    "/hash/analyze",
    { hash },
    {
      ...config,
      headers: {
        ...config.headers,
      },
    }
  );
};

// URL Analysis API
export const analyzeUrl = (url, config = {}) => {
  return api.post(
    "/url/analyze",
    { url },
    {
      ...config,
      headers: {
        ...config.headers,
      },
    }
  );
};

// IP Analysis API
export const analyzeIp = (ip, config = {}) => {
  return api.post(
    "/ip/analyze",
    { ip },
    {
      ...config,
      headers: {
        ...config.headers,
      },
    }
  );
};


// Scan APIs
export const getScans = () => api.get("/scans/");
export const getScan = (id) => api.get(`/scans/${id}`);
export const exportScan = (id) => api.get(`/scans/${id}/export`);

// Dashboard APIs
export const getDashboardStats = () => api.get("/dashboard/stats");

// Report Engine API
export const renderReport = (analysisResult, format = "html", config = {}) => {
  return api.post(
    "/reports/render",
    {
      analysis_result: analysisResult,
      format,
    },
    {
      ...config,
      headers: {
        ...config.headers,
      },
    }
  );
};

// Settings APIs
export const getSettingsApiKeys = () => api.get("/settings/api-keys");
export const updateSettingsApiKeys = (keys) => api.put("/settings/api-keys", keys);

export default api;
