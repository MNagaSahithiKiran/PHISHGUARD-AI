import React, { useEffect, useState, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Activity,
  Terminal,
  ExternalLink,
  Bell,
  User as UserIcon,
  LogOut,
  LogIn,
  CheckCheck,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { api } from '../../services/api';
import { useAuth } from '../../context/AuthContext';
import { AppNotification } from '../../types/scan';

export const Navbar: React.FC = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const [isHealthy, setIsHealthy] = useState<boolean | null>(null);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [showNotifications, setShowNotifications] = useState(false);
  const notifyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.checkHealth()
      .then((res) => setIsHealthy(res.database_connected))
      .catch(() => setIsHealthy(false));
  }, []);

  const fetchNotifications = async () => {
    if (isAuthenticated) {
      try {
        const notifs = await api.getNotifications(10);
        setNotifications(notifs);
      } catch (err) {
        // Silent catch for background polling
      }
    }
  };

  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 15000); // 15s poll
    return () => clearInterval(interval);
  }, [isAuthenticated]);

  // Click outside listener for notifications
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notifyRef.current && !notifyRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const unreadCount = notifications.filter((n) => !n.is_read).length;

  const handleMarkAllRead = async () => {
    try {
      await api.markAllNotificationsRead();
      setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })));
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <header className="h-16 border-b border-cyber-border bg-cyber-900/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
      <Link to="/" className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold tracking-wider text-base text-white">
                PHISHGUARD <span className="text-cyan-400">AI</span>
              </span>
              <span className="text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 px-1.5 py-0.5 rounded">
                v1.0-SOC
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono tracking-wide">
              Detect. Explain. Protect.
            </p>
          </div>
        </div>
      </Link>

      <div className="flex items-center gap-3 sm:gap-4">
        {/* Backend health indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg border border-cyber-border bg-cyber-950/60 text-xs">
          <Activity className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-400 font-mono text-[11px]">API ENGINE:</span>
          {!api.isConfigured() ? (
            <span className="flex items-center gap-1.5 text-amber-400 font-mono font-medium text-[11px]">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              API CONFIGURATION REQUIRED
            </span>
          ) : isHealthy === null ? (
            <span className="text-slate-500 text-[11px]">CONNECTING...</span>
          ) : isHealthy ? (
            <span className="flex items-center gap-1.5 text-emerald-400 font-mono font-medium text-[11px]">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              ONLINE
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-rose-400 font-mono font-medium text-[11px]">
              <span className="w-2 h-2 rounded-full bg-rose-400" />
              OFFLINE
            </span>
          )}
        </div>

        {/* Notifications Bell */}
        {isAuthenticated && (
          <div className="relative" ref={notifyRef}>
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-2 rounded-lg border border-cyber-border hover:bg-cyber-800 text-slate-300 transition-colors cursor-pointer"
              title="Notifications"
            >
              <Bell className="w-4 h-4" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-[9px] font-bold text-white flex items-center justify-center animate-pulse">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>

            {/* Flyout Panel */}
            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-2xl border border-cyber-border bg-cyber-900/95 backdrop-blur-xl shadow-2xl p-4 space-y-3 z-50">
                <div className="flex items-center justify-between border-b border-cyber-border pb-2.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-white">SECURITY NOTIFICATIONS</span>
                    {unreadCount > 0 && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-400 border border-rose-800">
                        {unreadCount} unread
                      </span>
                    )}
                  </div>
                  {unreadCount > 0 && (
                    <button
                      onClick={handleMarkAllRead}
                      className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer font-mono"
                    >
                      <CheckCheck className="w-3.5 h-3.5" /> Mark all read
                    </button>
                  )}
                </div>

                <div className="max-h-64 overflow-y-auto space-y-2 divide-y divide-cyber-border/40">
                  {notifications.length === 0 ? (
                    <div className="text-center py-6 text-xs text-slate-500 font-mono">
                      No security notifications recorded.
                    </div>
                  ) : (
                    notifications.map((n) => (
                      <div
                        key={n.id}
                        className={`pt-2 first:pt-0 text-xs space-y-1 ${
                          !n.is_read ? 'bg-cyan-950/20 p-2 rounded-lg' : ''
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span
                            className={`font-semibold text-[11px] font-mono flex items-center gap-1.5 ${
                              n.severity === 'critical' ? 'text-rose-400' : 'text-amber-400'
                            }`}
                          >
                            <AlertTriangle className="w-3 h-3" />
                            {n.title}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono">
                            {new Date(n.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-300 leading-tight">{n.message}</p>
                        {n.link && (
                          <Link
                            to={n.link}
                            onClick={() => setShowNotifications(false)}
                            className="inline-block text-[10px] text-cyan-400 hover:underline font-mono mt-0.5"
                          >
                            Investigate Target &rarr;
                          </Link>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* User Account Controls */}
        {isAuthenticated && user ? (
          <div className="flex items-center gap-2 pl-2 border-l border-cyber-border">
            <div className="hidden sm:block text-right">
              <div className="text-xs font-semibold text-slate-100 font-mono truncate max-w-[120px]">
                {user.full_name || user.email.split('@')[0]}
              </div>
              <div className="flex items-center justify-end gap-1">
                <span
                  className={`text-[9px] font-mono uppercase font-bold px-1.5 py-0.2 rounded ${
                    user.role === 'admin'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  }`}
                >
                  {user.role}
                </span>
              </div>
            </div>

            <button
              onClick={logout}
              title="Sign Out"
              className="p-2 rounded-lg border border-cyber-border hover:bg-rose-950/40 hover:border-rose-500/40 text-slate-400 hover:text-rose-300 transition-colors cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <Link
            to="/login"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/40 bg-cyan-950/40 hover:bg-cyan-900/60 text-cyan-300 text-xs font-mono transition-colors"
          >
            <LogIn className="w-3.5 h-3.5" />
            <span>Sign In</span>
          </Link>
        )}
      </div>
    </header>
  );
};
