import React from 'react';

export default function HistoryTable({ scans }) {
  if (!scans || scans.length === 0) {
    return (
      <div className="text-center py-12 bg-darkcard border border-darkborder rounded-xl">
        <p className="text-gray-400 text-sm">No historical scan entries recorded yet.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-darkborder bg-darkcard">
      <table className="w-full text-left text-sm text-gray-300">
        <thead className="bg-gray-900/80 text-xs uppercase text-gray-400 border-b border-darkborder">
          <tr>
            <th className="px-4 py-3">Scan ID</th>
            <th className="px-4 py-3">Target Path</th>
            <th className="px-4 py-3">Type</th>
            <th className="px-4 py-3">Status</th>
            <th className="px-4 py-3">Files Scanned</th>
            <th className="px-4 py-3">Threats Flagged</th>
            <th className="px-4 py-3">Started At</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-darkborder">
          {scans.map((s) => (
            <tr key={s.id} className="hover:bg-gray-800/30">
              <td className="px-4 py-3 font-mono text-xs text-blue-400">{s.id.substring(0, 8)}</td>
              <td className="px-4 py-3 text-white max-w-xs truncate" title={s.target_path}>{s.target_path}</td>
              <td className="px-4 py-3 capitalize">{s.scan_type}</td>
              <td className="px-4 py-3">
                <span className={`inline-block px-2 py-0.5 rounded text-xs uppercase font-bold ${
                  s.status === 'completed' ? 'text-emerald-400 bg-emerald-950/50' : 'text-blue-400 bg-blue-950/50 animate-pulse'
                }`}>
                  {s.status}
                </span>
              </td>
              <td className="px-4 py-3 font-mono">{s.files_scanned}</td>
              <td className="px-4 py-3 font-mono font-bold text-red-400">{s.threats_found}</td>
              <td className="px-4 py-3 text-xs text-gray-400">{s.started_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}