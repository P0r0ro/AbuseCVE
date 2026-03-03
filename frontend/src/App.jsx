import React from 'react';
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Filters from './pages/Filters';
import Alerts from './pages/Alerts';
import CVEDatabase from './pages/CVEDatabase';
import KnowledgeArticles from './pages/KnowledgeArticles';
import TestPage from './pages/TestPage';
import HealthReports from './pages/HealthReports';
import Integrations from './pages/Integrations';

const navItems = [
    { path: '/dashboard', icon: '📊', label: 'Dashboard' },
    { path: '/filters', icon: '🔍', label: 'Filters & Tags' },
    { path: '/alerts', icon: '🔔', label: 'Alerts' },
    { path: '/cves', icon: '🗄️', label: 'CVE Database' },
    { path: '/knowledge', icon: '📝', label: 'Knowledge Articles' },
    { path: '/integrations', icon: '🔗', label: 'Integrations' },
    { path: '/test', icon: '🧪', label: 'Test Chain' },
    { path: '/health', icon: '💊', label: 'Health Reports' },
];

export default function App() {
    return (
        <BrowserRouter>
            <div className="app-layout">
                {/* Sidebar */}
                <aside className="sidebar">
                    <div className="sidebar-logo">
                        <span className="logo-shield">🛡️</span>
                        <h1>AbuseCVE</h1>
                        <span className="logo-face">(≖_≖ )</span>
                    </div>
                    <nav className="sidebar-nav">
                        {navItems.map(item => (
                            <NavLink
                                key={item.path}
                                to={item.path}
                                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                            >
                                <span className="nav-icon">{item.icon}</span>
                                {item.label}
                            </NavLink>
                        ))}
                    </nav>
                    <div className="sidebar-footer">
                        AbuseCVE v1.0.0 • CTI Platform
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
                        <Route path="/integrations" element={<Integrations />} />
                        <Route path="/test" element={<TestPage />} />
                        <Route path="/health" element={<HealthReports />} />
                    </Routes>
                </div>
            </div>
        </BrowserRouter>
    );
}
