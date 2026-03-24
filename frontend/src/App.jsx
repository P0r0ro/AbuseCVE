import React from 'react';
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import {
    LayoutDashboard,
    Filter,
    BellDot,
    Database,
    BookOpen,
    Terminal,
    Webhook,
    Network,
    ShieldCheck,
} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import Filters from './pages/Filters';
import Alerts from './pages/Alerts';
import CVEDatabase from './pages/CVEDatabase';
import KnowledgeArticles from './pages/KnowledgeArticles';
import TestPage from './pages/TestPage';
import HealthReports from './pages/HealthReports';
import Logs from './pages/Logs';
import Integrations from './pages/Integrations';

const navItems = [
    { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/filters', icon: Filter, label: 'Filters & Tags' },
    { path: '/alerts', icon: BellDot, label: 'Alerts' },
    { path: '/cves', icon: Database, label: 'CVE Database' },
    { path: '/knowledge', icon: BookOpen, label: 'Knowledge Articles' },
    { path: '/logs', icon: Terminal, label: 'Logs' },
    { path: '/integrations', icon: Webhook, label: 'Integrations' },
    { path: '/test', icon: Network, label: 'Test Chain' },
    { path: '/health', icon: ShieldCheck, label: 'Health Reports' },
];

export default function App() {
    return (
        <BrowserRouter basename="/cve">
            <div className="app-layout">
                {/* Sidebar */}
                <aside className="sidebar">
                    <div className="sidebar-logo">
                        <div className="logo-icon-wrap">
                            <ShieldCheck size={28} className="logo-shield-icon" />
                        </div>
                        <h1>AbuseCVE</h1>
                        <span className="logo-face">(&#8790;_&#8790; )</span>
                    </div>
                    <nav className="sidebar-nav">
                        {navItems.map(item => (
                            <NavLink
                                key={item.path}
                                to={item.path}
                                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                            >
                                <item.icon size={18} className="nav-icon-svg" />
                                {item.label}
                            </NavLink>
                        ))}
                    </nav>
                    <div className="sidebar-footer">
                        AbuseCVE v1.0.0 &middot; CTI Platform
                    </div>
                </aside>

                {/* Main Content */}
                <div className="main-area">
                    <Routes>
                        <Route path="/" element={<Navigate to="/dashboard" replace />} />
                        <Route path="/dashboard" element={<Dashboard />} />
                        <Route path="/filters" element={<Filters />} />
                        <Route path="/alerts" element={<Alerts />} />
                        <Route path="/cves" element={<CVEDatabase />} />
                        <Route path="/knowledge" element={<KnowledgeArticles />} />
                        <Route path="/logs" element={<Logs />} />
                        <Route path="/integrations" element={<Integrations />} />
                        <Route path="/test" element={<TestPage />} />
                        <Route path="/health" element={<HealthReports />} />
                    </Routes>
                </div>
            </div>
        </BrowserRouter>
    );
}
