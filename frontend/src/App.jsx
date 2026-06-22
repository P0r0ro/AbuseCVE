import React from 'react';
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import {
    LayoutDashboard,
    ListFilter,
    BellDot,
    Database,
    BookOpen,
    Terminal,
    Webhook,
    Network,
    ShieldCheck,
    UserCog,
    LogOut,
} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import RulesManager from './pages/RulesManager';
import Alerts from './pages/Alerts';
import CVEDatabase from './pages/CVEDatabase';
import KnowledgeArticles from './pages/KnowledgeArticles';
import TestPage from './pages/TestPage';
import HealthReports from './pages/HealthReports';
import Logs from './pages/Logs';
import Integrations from './pages/Integrations';
import Login from './pages/Login';
import AdminToggles from './pages/AdminToggles';
import { PermissionsProvider, usePermissions } from './permissions';

// ── Nav items with permission guards ──────────
// `component` keys match the admin-toggle keys so SOC users see
// disabled suite surfaces greyed out or hidden entirely.
const navItems = [
    { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard', component: 'dashboard' },
    { path: '/filters', icon: ListFilter, label: 'Rules Manager', component: 'rules_manager' },
    { path: '/alerts', icon: BellDot, label: 'Alerts', component: 'alerts' },
    { path: '/cves', icon: Database, label: 'CVE Database', component: 'cve_database' },
    { path: '/knowledge', icon: BookOpen, label: 'Knowledge Articles', component: 'knowledge' },
    { path: '/logs', icon: Terminal, label: 'Logs', component: 'logs' },
    { path: '/integrations', icon: Webhook, label: 'Integrations', component: 'integrations', adminOnly: true },
    { path: '/test', icon: Network, label: 'Test Chain', component: 'test', adminOnly: true },
    { path: '/health', icon: ShieldCheck, label: 'Health Reports', component: 'health' },
    { path: '/access', icon: UserCog, label: 'Access Control', component: 'admin_toggles', adminOnly: true },
];

function AppShell() {
    const { isAuthenticated, loading, user, logout, isAdmin, canAccess } = usePermissions();

    if (loading) {
        return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading…</div></div>;
    }

    if (!isAuthenticated) {
        return <Login />;
    }

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
                        {navItems.map(item => {
                            const allowed = canAccess(item.component);
                            if (item.adminOnly && !isAdmin) return null;
                            return (
                                <NavLink
                                    key={item.path}
                                    to={item.path}
                                    className={({ isActive }) => `nav-item ${isActive ? 'active' : ''} ${allowed ? '' : 'is-disabled'}`}
                                    onClick={(e) => { if (!allowed) e.preventDefault(); }}
                                    style={!allowed ? { opacity: 0.4, pointerEvents: 'none' } : undefined}
                                    title={allowed ? undefined : 'Disabled for your role'}
                                >
                                    <item.icon size={18} className="nav-icon-svg" />
                                    {item.label}
                                </NavLink>
                            );
                        })}
                    </nav>
                    <div className="sidebar-footer" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        <div className="text-xs text-muted">
                            Signed in as <strong style={{ color: 'var(--purple-400)' }}>{user?.full_name || user?.username}</strong>
                            <span style={{ marginLeft: 4 }}>({user?.role})</span>
                            {user?.full_name && user?.username && (
                                <div className="text-xs" style={{ color: 'var(--text-muted)', opacity: 0.7 }}>
                                    @{user.username}
                                </div>
                            )}
                        </div>
                        <button className="btn btn-secondary btn-sm" onClick={logout} style={{ fontSize: 11, padding: '4px 10px' }}>
                            <LogOut size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Sign out
                        </button>
                        <div className="text-xs text-muted">AbuseCVE v3.3.0 · CTI Platform</div>
                    </div>
                </aside>

                {/* Main Content */}
                <div className="main-area">
                    <Routes>
                        <Route path="/" element={<Navigate to="/dashboard" replace />} />
                        <Route path="/dashboard" element={<Dashboard />} />
                        <Route path="/filters" element={<RulesManager />} />
                        <Route path="/alerts" element={<Alerts />} />
                        <Route path="/cves" element={<CVEDatabase />} />
                        <Route path="/knowledge" element={<KnowledgeArticles />} />
                        <Route path="/logs" element={<Logs />} />
                        <Route path="/integrations" element={isAdmin ? <Integrations /> : <Navigate to="/dashboard" replace />} />
                        <Route path="/test" element={isAdmin ? <TestPage /> : <Navigate to="/dashboard" replace />} />
                        <Route path="/health" element={<HealthReports />} />
                        <Route path="/access" element={isAdmin ? <AdminToggles /> : <Navigate to="/dashboard" replace />} />
                    </Routes>
                </div>
            </div>
        </BrowserRouter>
    );
}

export default function App() {
    return (
        <PermissionsProvider>
            <AppShell />
        </PermissionsProvider>
    );
}
