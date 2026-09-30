// src/api/client.js — thin client for the Sentinel analysis backend.
// Calls are same-origin (/api/*) and proxied to FastAPI by vite.config.js in dev.

const BASE = import.meta.env.VITE_API_BASE || '';

/**
 * Upload a flow-log CSV for analysis.
 * @param {File} file
 * @returns {Promise<{ok: boolean, status: number, data?: object, error?: string, coverage?: object}>}
 *   ok=true  -> data is { scenario, coverage, warnings, meta }
 *   ok=false -> error is a human message; coverage present on a 422 refusal.
 */
export async function analyzeLogs(file) {
  const form = new FormData();
  form.append('file', file);

  let res;
  try {
    res = await fetch(`${BASE}/api/analyze`, { method: 'POST', body: form });
  } catch {
    return { ok: false, status: 0, error: 'Could not reach the backend. Is it running on :8000?' };
  }

  let body = null;
  try { body = await res.json(); } catch { /* non-JSON error */ }

  if (res.ok) return { ok: true, status: res.status, data: body };

  // FastAPI puts our payload in `detail` (object for 422/503, string for 400).
  const detail = body && body.detail;
  if (detail && typeof detail === 'object') {
    return { ok: false, status: res.status, error: detail.message || 'Analysis failed.', coverage: detail.coverage };
  }
  return { ok: false, status: res.status, error: (typeof detail === 'string' ? detail : `Request failed (${res.status}).`) };
}

export async function backendHealth() {
  try {
    const r = await fetch(`${BASE}/health`);
    return r.ok;
  } catch {
    return false;
  }
}
