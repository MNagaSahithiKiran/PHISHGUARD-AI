import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { DashboardLayout } from './layouts/DashboardLayout';
import { Dashboard } from './pages/Dashboard';
import { Scanner } from './pages/Scanner';
import { ScanResult } from './pages/ScanResult';
import { ScanHistory } from './pages/ScanHistory';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { Analytics } from './pages/Analytics';
import { ModelTransparency } from './pages/ModelTransparency';
import { AdminDashboard } from './pages/AdminDashboard';
import { ReproducibilityAudit } from './pages/ReproducibilityAudit';
import { About } from './pages/About';
import { Settings } from './pages/Settings';
import { Login } from './pages/Login';
import { Register } from './pages/Register';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<DashboardLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="scanner" element={<Scanner />} />
            <Route path="scans/:scanId" element={<ScanResult />} />
            <Route path="history" element={<ScanHistory />} />
            <Route path="threat-intel" element={<ThreatIntelligence />} />
            <Route path="analytics" element={<Analytics />} />
            <Route path="models" element={<ModelTransparency />} />
            <Route path="admin" element={<AdminDashboard />} />
            <Route path="admin/reproducibility" element={<ReproducibilityAudit />} />
            <Route path="reproducibility" element={<ReproducibilityAudit />} />
            <Route path="about" element={<About />} />
            <Route path="settings" element={<Settings />} />
            <Route path="login" element={<Login />} />
            <Route path="register" element={<Register />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;
