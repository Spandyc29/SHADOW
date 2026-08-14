import api from "./api";

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
