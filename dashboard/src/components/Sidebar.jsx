import React from 'react';
import { Shield, Radio, ShieldAlert, History } from 'lucide-react';

export default function Sidebar({ currentTab, setCurrentTab }) {
  const items = [
    { id: 'overview', label: 'Overview', icon: Shield },
    { id: 'scan', label: 'Threat Scan', icon: Radio },
    { id: 'quarantine', label: 'Quarantine Vault', icon: ShieldAlert },
    { id: 'history', label: 'Scan History', icon: History },
  ];

  return (
    <aside className="w-64 bg-darkcard border-r border-darkborder flex flex-col justify-between p-4 min-h-screen">
      <div>
        <div className="flex items-center gap-3 px-3 py-4 mb-6">
          <Shield className="w-8 h-8 text-blue-500" />
          <div>
            <h1 className="font-bold text-lg tracking-wider text-white">VindexAV</h1>
            <p className="text-xs text-gray-500 font-mono">EDR & THREAT ENGINE</p>
          </div>
        </div>

        <nav className="space-y-1">
          {items.map((item) => {
            const Icon = item.icon;
            const active = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  active
                    ? 'bg-blue-600/10 text-blue-400 border border-blue-500/30'
                    : 'text-gray-400 hover:bg-gray-800/50 hover:text-gray-200'
                }`}
              >
                <Icon className={`w-5 h-5 ${active ? 'text-blue-400' : 'text-gray-400'}`} />
                {item.label}
              </button>
            );
          })}
        </nav>
      </div>

      <div className="p-3 bg-gray-900/60 rounded-lg border border-darkborder">
        <div className="text-xs text-gray-400 font-mono">Host Environment</div>
        <div className="text-xs font-semibold text-gray-200 mt-1">Kali Linux / Unix Hybrid</div>
        <div className="text-[10px] text-gray-500 mt-1">127.0.0.1 Binding Active</div>
      </div>
    </aside>
  );
}