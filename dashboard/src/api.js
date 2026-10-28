export const API_BASE = 'http://127.0.0.1:8000';

export async function fetchStatus() {
  const res = await fetch(`${API_BASE}/api/status`);
  if (!res.ok) throw new Error('Failed to fetch status');
  return res.json();
}

export async function toggleWatcher(enable) {
  const endpoint = enable ? 'start' : 'stop';
  const res = await fetch(`${API_BASE}/api/watcher/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  });
  if (!res.ok) throw new Error('Failed to toggle watcher');
  return res.json();
}

export async function startScan(targetPath, scanType = 'custom') {
  const res = await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_path: targetPath, scan_type: scanType })
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || 'Scan request failed');
  }
  return res.json();
}

export async function getScanStatus(scanId) {
  const res = await fetch(`${API_BASE}/api/scan/${scanId}`);
  if (!res.ok) throw new Error('Failed to fetch scan progress');
  return res.json();
}

export async function fetchHistory() {
  const res = await fetch(`${API_BASE}/api/history`);
  if (!res.ok) throw new Error('Failed to fetch scan history');
  return res.json();
}

export async function fetchQuarantine() {
  const res = await fetch(`${API_BASE}/api/quarantine`);
  if (!res.ok) throw new Error('Failed to fetch quarantine vault');
  return res.json();
}

export async function restoreQuarantined(itemId) {
  const res = await fetch(`${API_BASE}/api/quarantine/${itemId}/restore`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error('Failed to restore file');
  return res.json();
}

export async function deleteQuarantined(itemId) {
  const res = await fetch(`${API_BASE}/api/quarantine/${itemId}`, {
    method: 'DELETE'
  });
  if (!res.ok) throw new Error('Failed to delete file');
  return res.json();
}

export const restoreQuarantineFile = restoreQuarantined;
export const deleteQuarantineFile = deleteQuarantined;