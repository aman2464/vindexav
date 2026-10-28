import React from 'react';

export default function VerdictBadge({ verdict }) {
  const v = (verdict || 'clean').toLowerCase();
  
  if (v === 'malicious') {
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-950 text-red-400 border border-red-800">
        Malicious
      </span>
    );
  }
  if (v === 'suspicious') {
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950 text-amber-400 border border-amber-800">
        Suspicious
      </span>
    );
  }
  return (
    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
      Clean
    </span>
  );
}