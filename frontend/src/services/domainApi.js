import api from "./api";

export const analyzeDomain = (domain, config = {}) => {
  return api.post(
    "/domain/analyze",
    { domain },
    {
      ...config,
      headers: {
        ...config.headers,
      },
    }
  );
};
