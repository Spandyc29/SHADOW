import api from "./api";

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
