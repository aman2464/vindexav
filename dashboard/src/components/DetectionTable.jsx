import React from 'react';
import VerdictBadge from './VerdictBadge';

export default function DetectionTable({ detections }) {
  if (!detections || detections.length === 0) {
    return (
      <div className="text-center py-10 bg-darkcard border border-darkborder rounded-xl">
        <p className="text-gray-400 text-sm">No threats or suspicious artifacts flagged.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-darkborder bg-darkcard">
      <table className="w-full text-left text-sm text-gray-300">
        <thead className="bg-gray-900/80 text-xs uppercase text-gray-400 border-b border-darkborder">
          <tr>
            <th className="px-4 py-3">File Name</th>
            <th className="px-4 py-3">Verdict</th>
            <th className="px-4 py-3">Score</th>
            <th className="px-4 py-3">SHA-256</th>
            <th className="px-4 py-3">Analysis Findings</th>
            <th className="px-4 py-3 text-right">Quarantined</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-darkborder">
          {detections.map((d, index) => (
            <tr key={index} className="hover:bg-gray-800/30">
              <td className="px-4 py-3 font-medium text-white max-w-xs truncate" title={d.file_path}>
                {d.file_name}
              </td>
              <td className="px-4 py-3">
                <VerdictBadge verdict={d.verdict} />
              </td>
              <td className="px-4 py-3 font-mono font-semibold">{d.risk_score}/100</td>
              <td className="px-4 py-3 font-mono text-xs text-gray-400 max-w-[120px] truncate" title={d.sha256}>
                {d.sha256 ? `${d.sha256.substring(0, 10)}...` : 'N/A'}
              </td>
              <td className="px-4 py-3 text-xs text-gray-300 max-w-md">{d.reasons}</td>
              <td className="px-4 py-3 text-right">
                {d.quarantined ? (
                  <span className="text-xs text-emerald-400 font-semibold">Yes</span>
                ) : (
                  <span className="text-xs text-gray-500">No</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}