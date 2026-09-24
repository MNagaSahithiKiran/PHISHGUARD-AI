import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  SearchCode,
  History,
  Radio,
  BarChart3,
  Cpu,
  GitCompare,
  ShieldCheck,
  Info,
  Settings as SettingsIcon,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export const Sidebar: React.FC = () => {
  const { isAdmin } = useAuth();

  const NAV_ITEMS = [
    { path: '/', label: 'SOC Dashboard', icon: LayoutDashboard },
    { path: '/scanner', label: 'Website Scanner', icon: SearchCode },
    { path: '/history', label: 'Scan History', icon: History },
    { path: '/threat-intel', label: 'Threat Intel', icon: Radio },
    { path: '/analytics', label: 'Analytics', icon: BarChart3 },
    { path: '/models', label: 'AI Model Cards', icon: Cpu },
    { path: '/admin/reproducibility', label: 'Reproducibility Audit', icon: GitCompare },
    ...(isAdmin ? [{ path: '/admin', label: 'Admin Portal', icon: ShieldCheck }] : []),
    { path: '/about', label: 'About & Architecture', icon: Info },
    { path: '/settings', label: 'Settings', icon: SettingsIcon },
  ];

  return (
    <aside className="w-64 border-r border-cyber-border bg-cyber-900/60 backdrop-blur-md flex flex-col justify-between shrink-0 h-[calc(100vh-4rem)] sticky top-16">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-[11px] font-mono uppercase tracking-wider text-slate-400">
          Cyber Defense Center
        </div>
        <nav className="space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-950'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-800/60 border border-transparent'
                  }`
                }
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Security Engine State Box */}
      <div className="p-4 m-3 rounded-xl border border-cyber-border bg-cyber-950/70">
        <div className="flex items-center gap-2 mb-2">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-semibold text-slate-200">Defensive Mode</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
          SSRF protection, private subnet rejection, and multi-modal fusion active.
        </p>
        <div className="w-full bg-cyber-900 rounded-full h-1.5 overflow-hidden">
          <div className="bg-cyan-500 h-full w-full animate-pulse" />
        </div>
      </div>
    </aside>
  );
};
