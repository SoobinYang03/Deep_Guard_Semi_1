import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// ==================== Leaks API ====================
export const getLeaks = (params = {}) => {
  return api.get('/api/leaks', { params });
};

export const getLeakByIndex = (indexName) => {
  return api.get(`/api/leaks/by-index/${indexName}`);
};

// ==================== Search API ====================
export const searchPersonalInfo = (query, size = 100) => {
  return api.get('/api/search/personal-info', {
    params: { query, size }
  });
};

// ==================== Sources API ====================
export const getSources = () => {
  return api.get('/api/sources').then(res => res.data);
};

// ==================== Upload API ====================
export const uploadLeakFile = (formData) => {
  return axios.post(`${API_BASE_URL}/api/upload`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data'
    }
  }).then(res => res.data);
};

// ==================== Status Update API ====================
export const updateLeakStatus = (leakId, status) => {
  return api.patch(`/api/leaks/${leakId}/status`, null, {
    params: { status }
  }).then(res => res.data);
};

export default api;
