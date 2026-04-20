async function parseError(response) {
  try {
    return await response.json();
  } catch {
    return { error: await response.text() };
  }
}

export async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  if (!response.ok) {
    const payload = await parseError(response);
    const error = new Error(payload.error || `HTTP ${response.status}`);
    error.payload = payload;
    error.status = response.status;
    throw error;
  }
  return response.json();
}

export function fetchWorkspaces() {
  return api('/api/workspaces');
}

export function fetchScans() {
  return api('/api/scans');
}

export function fetchScan(scanId) {
  return api(`/api/scans/${scanId}`);
}

export function fetchScanEvents(scanId) {
  return api(`/api/scans/${scanId}/events?format=json&after=0`);
}

export async function fetchScanReport(scanId, format = 'markdown') {
  const response = await fetch(`/api/scans/${scanId}/report?format=${format}`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.text();
}

export function fetchScanReportJson(scanId) {
  return api(`/api/scans/${scanId}/report?format=json`);
}

export function createScan(payload) {
  return api('/api/scans', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function cancelScanRequest(scanId) {
  return api(`/api/scans/${scanId}/cancel`, {
    method: 'POST',
    body: '{}',
  });
}

export function deleteScanRequest(scanId) {
  return api(`/api/scans/${scanId}`, {
    method: 'DELETE',
  });
}

export function purgeTerminalScansRequest() {
  return api('/api/scans/purge-terminal', {
    method: 'POST',
    body: '{}',
  });
}
