import React, { useState } from 'react';
import { RotateCcw, Trash2 } from 'lucide-react';
import VerdictBadge from './VerdictBadge';

export default function QuarantineTable({ items, onRestore, onDelete }) {
  const [deletingId, setDeletingId] = useState(null);

  if (!items || items.length === 0) {
    return (
      <div className="text-center py-12 bg-darkcard border border-darkborder rounded-xl">
        <p className="text-gray-400 text-sm">Quarantine vault is empty. No files isolated.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-darkborder bg-darkcard">
      <table className="w-full text-left text-sm text-gray-300">
        <thead className="bg-gray-900/80 text-xs uppercase text-gray-400 border-b border-darkborder">
          <tr>
            <th className="px-4 py-3">Original File Path</th>
            <th className="px-4 py-3">Vault Identifier</th>
            <th className="px-4 py-3">Verdict</th>
            <th className="px-4 py-3">Quarantined At</th>
            <th className="px-4 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-darkborder">
          {items.map((item) => (
            <tr key={item.id} className="hover:bg-gray-800/30">
              <td className="px-4 py-3 font-medium text-white max-w-sm truncate" title={item.original_path}>
                {item.original_path}
              </td>
              <td className="px-4 py-3 font-mono text-xs text-gray-400">{item.vault_filename}</td>
              <td className="px-4 py-3">
                <VerdictBadge verdict={item.verdict} />
              </td>
              <td className="px-4 py-3 text-xs text-gray-400">{item.quarantined_at}</td>
              <td className="px-4 py-3 text-right">
                <div className="flex justify-end items-center gap-2">
                  <button
                    onClick={() => onRestore(item.id)}
                    className="p-1.5 hover:bg-gray-800 text-gray-300 hover:text-white rounded border border-darkborder"
                    title="Decrypt and Restore"
                  >
                    <RotateCcw className="w-4 h-4" />
                  </button>

                  {deletingId === item.id ? (
                    <div className="flex items-center gap-1 bg-red-950/60 p-1 rounded border border-red-800">
                      <span className="text-[10px] text-red-300 px-1">Purge?</span>
                      <button
                        onClick={() => {
                          onDelete(item.id);
                          setDeletingId(null);
                        }}
                        className="px-1.5 py-0.5 bg-red-600 text-white text-[10px] rounded font-bold"
                      >
                        Yes
                      </button>
                      <button
                        onClick={() => setDeletingId(null)}
                        className="px-1.5 py-0.5 bg-gray-700 text-white text-[10px] rounded"
                      >
                        No
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => setDeletingId(item.id)}
                      className="p-1.5 hover:bg-red-950 text-red-400 rounded border border-darkborder hover:border-red-800"
                      title="Permanently Shred"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}