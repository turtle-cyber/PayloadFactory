import axios from "axios";

// Auto-detect the API base URL based on current hostname
// This automatically works with localhost, LAN IPs, or any deployed environment
const getApiBaseUrl = () => {
  // If VITE_API_BASE is explicitly set, use it
  if (import.meta.env.VITE_API_BASE) {
    return import.meta.env.VITE_API_BASE;
  }

  // Auto-detect based on current hostname
  const hostname = window.location.hostname;
  const protocol = window.location.protocol;

  // Use current hostname with port 5000
  return `${protocol}//${hostname}:5000/api`;
};

// Set the base URL for axios requests
axios.defaults.baseURL = getApiBaseUrl();

export const http = {
  get: axios.get,
  post: axios.post,
  put: axios.put,
  delete: axios.delete,
  patch: axios.patch,
};
