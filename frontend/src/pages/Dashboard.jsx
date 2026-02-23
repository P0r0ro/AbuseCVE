import React, { useState, useEffect } from 'react';
import { getDashboardOverview, triggerScan, initializeDB, getTaskStatus } from '../api';

const severityColors = {
    CRITICAL: 'var(--critical)',
    HIGH: 'var(--high)',
    MEDIUM: 'var(--medium)',
    LOW: 'var(--low)',
    UNKNOWN: 'var(--text-muted)',
};

export default function Dashboard() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [scanStatus, setScanStatus] = useState('');
    const [initVendor, setInitVendor] = useState('');

    const fetchData = async () => {
        try {
            const overview = await getDashboardOverview();
            setData(overview);
        } catch (e) {
            console.error('Dashboard fetch error:', e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchData(); }, []);

    const handleScan = async () => {
        setScanStatus('Triggering scan...');
        try {
            const result = await triggerScan();
            setScanStatus(`Scan started (Task: ${result.task_id})`);
        } catch (e) {
            setScanStatus(`Error: ${e.message}`);
        }
    };

    const handleInitDB = async () => {
        setScanStatus('Initializing database...');
        try {
            const result = await initializeDB(initVendor);
            setScanStatus(`DB init started: ${result.message}`);
        } catch (e) {
            setScanStatus(`Error: ${e.message}`);
        }
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading dashboard...</div></div>;

    const sev = data?.severity_distribution || {};
    const maxSev = Math.max(...Object.values(sev), 1);

    return (
        <div className="main-content animate-in">
            <div className="header" style={{ marginBottom: 24, padding: 0, background: 'transparent', border: 'none', height: 'auto' }}>
                <div>
                    <h1 className="header-title">Dashboard</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Real-time CVE monitoring overview</p>
                </div>
                <div className="header-actions">
                    <button className="btn btn-primary" onClick={handleScan}>🔍 Trigger Scan</button>
                    <button className="btn btn-secondary" onClick={fetchData}>↻ Refresh</button>
                </div>
            </div>

            {scanStatus && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: 'var(--border-accent)' }}>
                    <span className="text-sm">{scanStatus}</span>
                </div>
            )}

            {/* Stats Grid */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-icon">🗄️</div>
                    <div className="stat-value">{data?.total_cves?.toLocaleString() || 0}</div>
                    <div className="stat-label">Total CVEs in Database</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">🔔</div>
                    <div className="stat-value">{data?.today_alerts || 0}</div>
                    <div className="stat-label">Today's Alerts</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">🔍</div>
                    <div className="stat-value">{data?.active_filters || 0}</div>
                    <div className="stat-label">Active Filters</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">⚠️</div>
                    <div className="stat-value">{data?.kev_count || 0}</div>
                    <div className="stat-label">Known Exploited (KEV)</div>
                </div>
            </div>

            <div className="grid-2 mb-24">
                {/* Severity Distribution */}
                <div className="card">
                    <div className="card-header">
                        <div className="card-title">Severity Distribution</div>
                    </div>
                    <div className="severity-chart">
                        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(level => (
                            <div key={level} className="severity-bar-row">
                                <div className="severity-bar-label" style={{ color: severityColors[level] }}>{level}</div>
                                <div className="severity-bar-track">
                                    <div className="severity-bar-fill"
                                        style={{
                                            width: `${((sev[level] || 0) / maxSev) * 100}%`,
                                            background: severityColors[level],
                                        }}
                                    />
                                </div>
                                <div className="severity-bar-count">{sev[level] || 0}</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* DB Initialize */}
                <div className="card">
                    <div className="card-header">
                        <div className="card-title">Database Initialization</div>
                    </div>
                    <p className="text-sm text-muted mb-16">Pull all past CVEs for a vendor into the database for tracking.</p>
                    <div className="form-group">
                        <label className="form-label">Vendor Keyword (optional)</label>
                        <input className="form-input" placeholder="e.g., fortinet, microsoft..."
                            value={initVendor} onChange={e => setInitVendor(e.target.value)} />
                    </div>
                    <button className="btn btn-primary" onClick={handleInitDB}>🗄️ Initialize Database</button>
                </div>
            </div>

            {/* Recent CVEs */}
            <div className="card mb-24">
                <div className="card-header">
                    <div className="card-title">Recent CVEs</div>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Vendor</th>
                                <th>Product</th>
                                <th>Severity</th>
                                <th>CVSS</th>
                                <th>KEV</th>
                                <th>First Seen</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(data?.recent_cves || []).map(cve => (
                                <tr key={cve.cve_id}>
                                    <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{cve.cve_id}</td>
                                    <td>{cve.vendor || '—'}</td>
                                    <td>{cve.product || '—'}</td>
                                    <td><span className={`badge badge-${(cve.severity || 'unknown').toLowerCase()}`}>{cve.severity || 'N/A'}</span></td>
                                    <td className="text-mono">{cve.cvss_score ?? '—'}</td>
                                    <td>{cve.kev_flag ? <span className="badge badge-kev">⚠ KEV</span> : '—'}</td>
                                    <td className="text-sm text-muted">{cve.first_seen ? new Date(cve.first_seen).toLocaleDateString() : '—'}</td>
                                </tr>
                            ))}
                            {(!data?.recent_cves || data.recent_cves.length === 0) && (
                                <tr><td colSpan="7" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>No CVEs yet. Create filters and run a scan to get started.</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Recent Alerts */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">Recent Alerts</div>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr><th>CVE ID</th><th>Status</th><th>Sent At</th><th>Recipient</th></tr>
                        </thead>
                        <tbody>
                            {(data?.recent_alerts || []).map(alert => (
                                <tr key={alert.id}>
                                    <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{alert.cve_id}</td>
                                    <td><span className={`badge ${alert.status === 'sent' ? 'badge-success' : 'badge-error'}`}>{alert.status}</span></td>
                                    <td className="text-sm text-muted">{alert.sent_at ? new Date(alert.sent_at).toLocaleString() : '—'}</td>
                                    <td className="text-sm">{alert.recipient || '—'}</td>
                                </tr>
                            ))}
                            {(!data?.recent_alerts || data.recent_alerts.length === 0) && (
                                <tr><td colSpan="4" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>No alerts yet.</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
