let accessToken = null;

export const getAccessToken = () => accessToken;

export const setAccessToken = (token) => {
  accessToken = token || null;
};

export const setAuthTokens = ({ access_token }) => {
  if (typeof access_token !== "undefined") {
    setAccessToken(access_token);
  }
};

export const clearAuthTokens = () => {
  accessToken = null;
};
