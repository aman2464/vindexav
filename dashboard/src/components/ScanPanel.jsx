import React, { useState } from 'react';
import { Play, Loader2, FolderOpen } from 'lucide-react';

export default function ScanPanel({ onStartScan, scanning, progress }) {
  const [scanType, setScanType] = useState('custom');
  const [targetPath, setTargetPath] = useState('test_folder');

  const handleBrowse = async () => {
    if (window.electronAPI) {
      const selected = await window.electronAPI.selectFolder();
      if (selected) {
        setTargetPath(selected);
      }
    } else {
      alert("Running in browser mode. Enter the target folder path directly or launch the VindexAV desktop application.");
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!targetPath.trim() || scanning) return;
    onStartScan(targetPath, scanType);
  };

  return (
    <div className="bg-darkcard border border-darkborder p-6 rounded-xl space-y-6">
      <div className="flex gap-4">
        {[
          { id: 'quick', title: 'Quick Scan', desc: 'Scan target directory shallowly' },
          { id: 'full', title: 'Full Scan', desc: 'Recursive deep heuristic pass' },
          { id: 'custom', title: 'Custom Path', desc: 'Explicit folder or file inspection' },
        ].map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => {
              setScanType(tab.id);
              if (tab.id === 'quick') setTargetPath('test_folder');
            }}
            className={`flex-1 p-3 rounded-lg border text-left transition-all ${
              scanType === tab.id
                ? 'border-blue-500 bg-blue-500/10 text-white'
                : 'border-darkborder bg-gray-900/40 text-gray-400 hover:border-gray-700'
            }`}
          >
            <div className="font-semibold text-sm">{tab.title}</div>
            <div className="text-xs text-gray-500 mt-1">{tab.desc}</div>
          </button>
        ))}
      </div>

      <form onSubmit={handleSubmit} className="flex gap-3">
        <input
          type="text"
          value={targetPath}
          onChange={(e) => setTargetPath(e.target.value)}
          placeholder="/path/to/scan (e.g. /home/user/Downloads)"
          disabled={scanning}
          className="flex-1 bg-gray-900 border border-darkborder rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />

        <button
          type="button"
          onClick={handleBrowse}
          disabled={scanning}
          className="bg-gray-800 hover:bg-gray-700 text-gray-200 border border-darkborder px-4 py-2.5 rounded-lg text-sm flex items-center gap-2 transition"
          title="Browse Folder"
        >
          <FolderOpen className="w-4 h-4 text-cyan-400" />
          <span>Browse...</span>
        </button>

        <button
          type="submit"
          disabled={scanning}
          className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white px-5 py-2.5 rounded-lg text-sm font-semibold flex items-center gap-2 transition"
        >
          {scanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              Scan Now
            </>
          )}
        </button>
      </form>

      {scanning && (
        <div className="space-y-2">
          <div className="flex justify-between text-xs text-gray-400">
            <span>Scan in execution...</span>
            <span>{progress.scanned} files inspected ({progress.threats} threats flagged)</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
            <div className="bg-blue-500 h-2 rounded-full animate-pulse w-full"></div>
          </div>
        </div>
      )}
    </div>
  );
}