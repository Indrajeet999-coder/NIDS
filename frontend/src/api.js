/**
 * frontend/src/api.js — REST API Client for NIDS Inference Service
 * =================================================================
 * Uses native `fetch` (zero external dependencies) to communicate
 * with the FastAPI backend running on http://127.0.0.1:8000.
 */

const BASE_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '');

/**
 * Internal helper to perform fetch requests with error handling.
 */
async function apiRequest(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  try {
    const response = await fetch(url, options);

    // If response is not OK (status not in 200-299 range)
    if (!response.ok) {
      let errorMessage = `HTTP Error ${response.status}: ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData.detail) {
          if (typeof errorData.detail === 'string') {
            errorMessage = errorData.detail;
          } else if (errorData.detail.error) {
            errorMessage = errorData.detail.error;
            if (errorData.detail.missing_features) {
              errorMessage += `: ${errorData.detail.missing_features.slice(0, 5).join(', ')}...`;
            }
          } else {
            errorMessage = JSON.stringify(errorData.detail);
          }
        }
      } catch {
        // Fallback to text if JSON parse fails
        const text = await response.text();
        if (text) errorMessage = text;
      }
      throw new Error(errorMessage);
    }

    return await response.json();
  } catch (error) {
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      throw new Error(
        `Backend API unreachable at ${BASE_URL}. Ensure uvicorn is running: uvicorn backend.main:app --reload`
      );
    }
    throw error;
  }
}

/**
 * Checks API health status, loaded model name, and expected features count.
 * GET /health
 */
export async function getHealth() {
  return await apiRequest('/health', {
    method: 'GET',
    headers: { 'Accept': 'application/json' },
  });
}

/**
 * Retrieves benchmark metrics for all 4 models, confusion matrix, and feature importances.
 * GET /metrics
 */
export async function getMetrics() {
  return await apiRequest('/metrics', {
    method: 'GET',
    headers: { 'Accept': 'application/json' },
  });
}

/**
 * Fetches the 25 required feature names and preset simulator samples (normal and attack).
 * GET /features
 */
export async function getFeatures() {
  return await apiRequest('/features', {
    method: 'GET',
    headers: { 'Accept': 'application/json' },
  });
}

/**
 * Submits a single network flow for real-time XGBoost inference.
 * POST /predict/single
 * @param {Record<string, number>} features - Dictionary of 25 flow features
 */
export async function predictSingle(features) {
  return await apiRequest('/predict/single', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({ features }),
  });
}

/**
 * Uploads a CSV file containing network flows for high-throughput batch inference.
 * POST /predict/csv
 * @param {File} file - CSV file
 */
export async function predictCsv(file) {
  const formData = new FormData();
  formData.append('file', file);

  return await apiRequest('/predict/csv', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      // Note: Do not set Content-Type header when sending FormData; browser sets it with boundary
    },
    body: formData,
  });
}

/**
 * Retrieves recent detection audit records from the SQLite database.
 * GET /history?limit=N
 * @param {number} limit - Maximum log records to return (default 50)
 */
export async function getHistory(limit = 50) {
  return await apiRequest(`/history?limit=${limit}`, {
    method: 'GET',
    headers: { 'Accept': 'application/json' },
  });
}

/**
 * Clears all detection audit logs from the SQLite database.
 * DELETE /history
 */
export async function deleteHistory() {
  return await apiRequest('/history', {
    method: 'DELETE',
    headers: { 'Accept': 'application/json' },
  });
}

/**
 * Lists the 5 sample CSV scenarios in dataset/samples/.
 * GET /samples
 */
export async function getSamples() {
  return await apiRequest('/samples', {
    method: 'GET',
    headers: { 'Accept': 'application/json' },
  });
}

/**
 * Runs full XGBoost inference on a named sample CSV file.
 * POST /predict/sample/{filename}
 */
export async function predictSample(filename) {
  return await apiRequest(`/predict/sample/${encodeURIComponent(filename)}`, {
    method: 'POST',
    headers: { 'Accept': 'application/json' },
  });
}

/**
 * Fetches live telemetry data for the Overview and Traffic Analysis dashboards.
 * GET /dashboard/telemetry
 */
export async function getDashboardTelemetry() {
  return await apiRequest('/dashboard/telemetry', {
    method: 'GET',
    headers: { 'Accept': 'application/json' },
  });
}

/**
 * Formats duration smartly: if durationSec >= 0.1, show e.g. '1.24 s';
 * otherwise show milliseconds (e.g. '14.5 ms') so it never displays a flat '0'
 * unless the raw value is truly zero.
 *
 * @param {number|null|undefined} durationSec - Flow duration in seconds
 * @param {number|null|undefined} durationMs - Flow duration in milliseconds
 * @returns {string} Human-friendly formatted duration string
 */
export function formatDuration(durationSec, durationMs) {
  if (durationSec === null || durationSec === undefined) {
    if (durationMs !== null && durationMs !== undefined) {
      const ms = Number(durationMs);
      if (ms === 0) return '0 s';
      if (ms >= 100) return `${(ms / 1000).toFixed(2)} s`;
      return `${Number(ms.toFixed(2))} ms`;
    }
    return '0 s';
  }
  const sec = Number(durationSec);
  if (sec === 0 && (!durationMs || Number(durationMs) === 0)) {
    return '0 s';
  }
  if (sec >= 0.1) {
    return `${sec >= 10 ? sec.toFixed(1) : sec.toFixed(2)} s`;
  }
  const ms = durationMs !== null && durationMs !== undefined ? Number(durationMs) : sec * 1000;
  if (ms <= 0) return '0 s';
  return `${ms >= 10 ? ms.toFixed(1) : ms.toFixed(2)} ms`;
}

export { BASE_URL };

