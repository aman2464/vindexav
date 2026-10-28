import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, FolderSearch, 
  Trash2, RotateCcw, Activity, History, Lock, CheckCircle2, Play
} from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('scan');
  const [status, setStatus] = useState({
    watcher_active: false,
    total_scans: 0,
    threats_found: 0,
    quarantined_files: 0
  });

  // Scan states
  const [targetPath, setTargetPath] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [activeScan, setActiveScan] = useState(null);
  const [detections, setDetections] = useState([]);

  // Quarantine & History
  const [quarantineItems, setQuarantineItems] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);

  const fetchStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/status`);
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (e) {}
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (activeTab === 'quarantine') loadQuarantine();
    if (activeTab === 'history') loadHistory();
  }, [activeTab]);

  const loadQuarantine = async () => {
    try {
      const res = await fetch(`${API_BASE}/quarantine`);
      if (res.ok) setQuarantineItems(await res.json());
    } catch (e) {}
  };

  const loadHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/history`);
      if (res.ok) setScanHistory(await res.json());
    } catch (e) {}
  };

  const toggleWatcher = async () => {
    const endpoint = status.watcher_active ? 'stop' : 'start';
    try {
      const res = await fetch(`${API_BASE}/watcher/${endpoint}`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setStatus(prev => ({ ...prev, watcher_active: data.watcher_active }));
      }
    } catch (e) {
      alert('Failed to connect to background shield.');
    }
  };

  const handleSelectFile = async () => {
    if (window.electronAPI?.openFile) {
      const filePath = await window.electronAPI.openFile();
      if (filePath) setTargetPath(filePath);
    }
  };

  const handleSelectFolder = async () => {
    if (window.electronAPI?.openDirectory) {
      const dirPath = await window.electronAPI.openDirectory();
      if (dirPath) setTargetPath(dirPath);
    }
  };

  const startScan = async () => {
    if (!targetPath) {
      alert('Select a file or folder to scan.');
      return;
    }

    setIsScanning(true);
    setDetections([]);
    setActiveScan({ files_scanned: 0, threats_found: 0, status: 'running' });

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_path: targetPath, scan_type: 'custom' })
      });

      if (!res.ok) throw new Error('Scan initiation failed.');
      const data = await res.json();
      pollScanProgress(data.scan_id);
    } catch (err) {
      alert(err.message);
      setIsScanning(false);
    }
  };

  const pollScanProgress = (scanId) => {
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/scan/${scanId}`);
        if (res.ok) {
          const scan = await res.json();
          setActiveScan(scan);
          if (scan.detections) setDetections(scan.detections);

          if (scan.status === 'completed' || scan.status === 'failed') {
            clearInterval(interval);
            setIsScanning(false);
            fetchStatus();
          }
        }
      } catch (e) {
        clearInterval(interval);
        setIsScanning(false);
      }
    }, 500);
  };

  const handleQuarantineFile = async (det) => {
    try {
      const res = await fetch(`${API_BASE}/quarantine/file`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          file_path: det.file_path,
          verdict: det.verdict,
          reasons: det.reasons,
          sha256: det.sha256
        })
      });
      if (res.ok) {
        setDetections(prev => prev.filter(d => d.file_path !== det.file_path));
        fetchStatus();
      } else {
        const err = await res.json();
        alert(`Quarantine failed: ${err.detail}`);
      }
    } catch (e) {
      alert('Error isolating file.');
    }
  };

  const handleRestoreQuarantine = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/quarantine/${id}/restore`, { method: 'POST' });
      if (res.ok) {
        loadQuarantine();
        fetchStatus();
      }
    } catch (e) {}
  };

  const handleDeleteQuarantine = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/quarantine/${id}`, { method: 'DELETE' });
      if (res.ok) {
        loadQuarantine();
        fetchStatus();
      }
    } catch (e) {}
  };

  return (
    <div className="flex h-screen bg-[#090D14] text-slate-200 font-sans select-none">
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-[#0e1420] border-r border-slate-800 flex flex-col">
        <div className="p-6 border-b border-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="font-bold text-base tracking-wide text-white">VindexAV</h1>
            <p className="text-xs text-slate-400">Endpoint Security Console</p>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          <button
            onClick={() => setActiveTab('scan')}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
              activeTab === 'scan' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
            }`}
          >
            <FolderSearch className="w-4 h-4" />
            Scanner
          </button>

          <button
            onClick={() => setActiveTab('quarantine')}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
              activeTab === 'quarantine' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
            }`}
          >
            <Lock className="w-4 h-4" />
            Quarantine Vault
            {status.quarantined_files > 0 && (
              <span className="ml-auto bg-amber-500/20 text-amber-300 text-xs px-2 py-0.5 rounded-full border border-amber-500/30">
                {status.quarantined_files}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('history')}
            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
              activeTab === 'history' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
            }`}
          >
            <History className="w-4 h-4" />
            Scan Logs
          </button>
        </nav>

        {/* Real-Time Protection Shield Widget */}
        <div className="p-4 m-3 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Real-Time Shield</span>
            <span className={`w-2 h-2 rounded-full ${status.watcher_active ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`} />
          </div>
          <button
            onClick={toggleWatcher}
            className={`w-full py-1.5 px-3 rounded text-xs font-medium transition border ${
              status.watcher_active
                ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800/50 hover:bg-emerald-900/40'
                : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
            }`}
          >
            {status.watcher_active ? 'Auto-Protect Active' : 'Shield Inactive (Enable)'}
          </button>
        </div>
      </aside>

      {/* Main Content View */}
      <main className="flex-1 flex flex-col overflow-y-auto">
        {/* Header Telemetry */}
        <header className="h-16 px-8 border-b border-slate-800 flex items-center justify-between bg-[#0e1420]/40 backdrop-blur">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              <span className="text-xs text-slate-400">Total Scans:</span>
              <span className="text-sm font-bold text-slate-200">{status.total_scans}</span>
            </div>
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <span className="text-xs text-slate-400">Threats Intercepted:</span>
              <span className="text-sm font-bold text-red-400">{status.threats_found}</span>
            </div>
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-amber-400" />
              <span className="text-xs text-slate-400">Quarantined:</span>
              <span className="text-sm font-bold text-amber-400">{status.quarantined_files}</span>
            </div>
          </div>
        </header>

        <div className="p-8 flex-1">
          {/* TAB 1: SCANNER */}
          {activeTab === 'scan' && (
            <div className="space-y-6 max-w-4xl">
              {/* Scan Configuration */}
              <div className="bg-[#121927] border border-slate-800 rounded-xl p-6">
                <h2 className="text-base font-semibold text-white mb-1">Target Inspection</h2>
                <p className="text-xs text-slate-400 mb-4">Select an executable, document, or directory to evaluate threat profiles.</p>

                <div className="flex gap-2">
                  <input
                    type="text"
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                    placeholder="Select target file or enter absolute directory path..."
                    className="flex-1 bg-slate-900 border border-slate-700/80 rounded-lg px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  />
                  <button
                    onClick={handleSelectFile}
                    className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 transition"
                  >
                    Select File
                  </button>
                  <button
                    onClick={handleSelectFolder}
                    className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg border border-slate-700 transition"
                  >
                    Select Folder
                  </button>
                  <button
                    onClick={startScan}
                    disabled={isScanning}
                    className={`px-6 py-2.5 rounded-lg text-xs font-bold flex items-center gap-2 text-white shadow-lg transition ${
                      isScanning ? 'bg-blue-800 cursor-not-allowed opacity-60' : 'bg-blue-600 hover:bg-blue-500'
                    }`}
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    {isScanning ? 'Scanning...' : 'Scan Target'}
                  </button>
                </div>

                {/* Live Progress Bar */}
                {activeScan && (
                  <div className="mt-4 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs">
                    <span className="text-slate-400">
                      Scanned: <strong className="text-white">{activeScan.files_scanned}</strong> files
                    </span>
                    <span className="text-slate-400">
                      Threats Found:{' '}
                      <strong className={activeScan.threats_found > 0 ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                        {activeScan.threats_found}
                      </strong>
                    </span>
                    <span className="uppercase text-[11px] font-semibold text-blue-400">
                      Status: {activeScan.status}
                    </span>
                  </div>
                )}
              </div>

              {/* Inspection Findings: 
                  - Score < 21: Green / Safe
                  - Score 21 to 45: Yellow / Suspicious (with Quarantine action)
                  - Score > 45: Red / Malicious (with Quarantine action)
              */}
              <div className="bg-[#121927] border border-slate-800 rounded-xl p-6">
                <h3 className="text-sm font-semibold text-white mb-4">Inspection Findings</h3>

                {detections.length === 0 ? (
                  <div className="py-12 text-center text-slate-500">
                    <CheckCircle2 className="w-8 h-8 mx-auto text-emerald-500/40 mb-2" />
                    <p className="text-sm">No threats or suspicious artifacts flagged.</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {detections.map((det, idx) => {
                      const isMalicious = det.score > 45;
                      const isSuspicious = det.score >= 21 && det.score <= 45;
                      const isClean = det.score < 21;

                      // Theme dynamic styling
                      let cardBorder = 'bg-emerald-950/20 border-emerald-900/40';
                      let badgeStyle = 'bg-emerald-900/30 text-emerald-300 border-emerald-800/50';
                      let textColor = 'text-emerald-200';
                      let descColor = 'text-emerald-400/90';
                      let btnStyle = 'bg-amber-600 hover:bg-amber-500';

                      if (isMalicious) {
                        cardBorder = 'bg-red-950/20 border-red-900/50';
                        badgeStyle = 'bg-red-900/40 text-red-300 border-red-800/60';
                        textColor = 'text-red-200';
                        descColor = 'text-red-400/90';
                        btnStyle = 'bg-red-600 hover:bg-red-500';
                      } else if (isSuspicious) {
                        cardBorder = 'bg-amber-950/20 border-amber-900/50';
                        badgeStyle = 'bg-amber-900/40 text-amber-300 border-amber-800/60';
                        textColor = 'text-amber-200';
                        descColor = 'text-amber-400/90';
                        btnStyle = 'bg-amber-600 hover:bg-amber-500';
                      }

                      return (
                        <div
                          key={idx}
                          className={`rounded-lg p-4 flex items-center justify-between gap-4 border ${cardBorder}`}
                        >
                          <div className="space-y-1 overflow-hidden">
                            <div className="flex items-center gap-2">
                              {isClean ? (
                                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                              ) : isSuspicious ? (
                                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                              ) : (
                                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                              )}

                              <span className={`font-semibold text-sm truncate ${textColor}`}>
                                {det.file_name}
                              </span>

                              <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded border ${badgeStyle}`}>
                                {isClean 
                                  ? `SAFE (Score ${det.score})` 
                                  : isSuspicious 
                                    ? `SUSPICIOUS (Score ${det.score})` 
                                    : `MALICIOUS (Score ${det.score})`}
                              </span>
                            </div>

                            <p className="text-xs text-slate-400 truncate">{det.file_path}</p>
                            <p className={`text-xs ${descColor}`}>{det.reasons}</p>
                          </div>

                          {!isClean && (
                            <button
                              onClick={() => handleQuarantineFile(det)}
                              className={`shrink-0 px-3.5 py-1.5 text-white rounded text-xs font-semibold shadow transition ${btnStyle}`}
                            >
                              Quarantine
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: QUARANTINE VAULT */}
          {activeTab === 'quarantine' && (
            <div className="bg-[#121927] border border-slate-800 rounded-xl p-6 max-w-4xl">
              <h2 className="text-base font-semibold text-white mb-1">Encrypted Quarantine Vault</h2>
              <p className="text-xs text-slate-400 mb-4">
                Neutralized artifacts isolated in AES-Fernet encrypted storage. Permissions revoked.
              </p>

              {quarantineItems.length === 0 ? (
                <div className="py-12 text-center text-slate-500 text-sm">
                  Quarantine vault is empty. No isolated threats.
                </div>
              ) : (
                <div className="divide-y divide-slate-800">
                  {quarantineItems.map((item) => (
                    <div key={item.id} className="py-3 flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-slate-200">{item.original_path}</p>
                        <p className="text-xs text-slate-500">Vault ID: {item.vault_filename}</p>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleRestoreQuarantine(item.id)}
                          className="flex items-center gap-1.5 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-xs font-medium rounded border border-slate-700 text-slate-300 transition"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
                          Restore
                        </button>
                        <button
                          onClick={() => handleDeleteQuarantine(item.id)}
                          className="flex items-center gap-1.5 px-3 py-1 bg-red-950/40 hover:bg-red-900/60 text-xs font-medium rounded border border-red-800/40 text-red-300 transition"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          Delete
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: SCAN LOGS */}
          {activeTab === 'history' && (
            <div className="bg-[#121927] border border-slate-800 rounded-xl p-6 max-w-4xl">
              <h2 className="text-base font-semibold text-white mb-4">Scan Activity Logs</h2>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-400">
                  <thead className="text-[11px] uppercase tracking-wider text-slate-500 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5">Scan ID</th>
                      <th className="py-2.5">Target Path</th>
                      <th className="py-2.5">Files Scanned</th>
                      <th className="py-2.5">Threats Flagged</th>
                      <th className="py-2.5">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {scanHistory.map((h) => (
                      <tr key={h.id} className="hover:bg-slate-800/30">
                        <td className="py-2.5 text-blue-400">{h.id}</td>
                        <td className="py-2.5 font-sans truncate max-w-xs">{h.target_path}</td>
                        <td className="py-2.5 text-slate-200">{h.files_scanned}</td>
                        <td className="py-2.5">
                          <span className={h.threats_found > 0 ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                            {h.threats_found}
                          </span>
                        </td>
                        <td className="py-2.5 font-sans uppercase text-[10px] text-slate-300">{h.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}