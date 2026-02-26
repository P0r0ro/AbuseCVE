import React, { useState, useEffect } from 'react';
import { getDashboardOverview, triggerScan, initializeDB, initializeDBLocal, getTaskStatus } from '../api';

const severityColors = {
    CRITICAL: 'var(--critical)',
    HIGH: 'var(--high)',
    MEDIUM: 'var(--medium)',
    LOW: 'var(--low)',
    UNKNOWN: 'var(--text-muted)',
};

const sourceColors = {
    NVD: '#6366F1',
    MITRE: '#F97316',
    CISA_KEV: '#EF4444',
    REDHAT: '#DC2626',
};

export default function Dashboard() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [scanStatus, setScanStatus] = useState('');
    const [initMode, setInitMode] = useState('api'); // 'api' or 'local'
    const [mitreDir, setMitreDir] = useState('');

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
        setScanStatus('Initializing database (full mirror from all sources)...');
        try {
            if (initMode === 'local' && mitreDir) {
                const result = await initializeDBLocal(mitreDir);
                setScanStatus(`Local DB init started: ${result.message}`);
            } else {
                const result = await initializeDB();
                setScanStatus(`DB init started: ${result.message}`);
            }
        } catch (e) {
            setScanStatus(`Error: ${e.message}`);
        }
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading dashboard...</div></div>;

    const sev = data?.severity_distribution || {};
    const maxSev = Math.max(...Object.values(sev), 1);
    const sourceDist = data?.source_distribution || {};

    return (
        <div className="main-content animate-in">
            <div className="header" style={{ marginBottom: 24, padding: 0, background: 'transparent', border: 'none', height: 'auto' }}>
                <div>
                    <h1 className="header-title">Dashboard</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Real-time CVE monitoring overview — 4 sources active</p>
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
                                <div className="severity-bar-count">{(sev[level] || 0).toLocaleString()}</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* DB Initialize */}
                <div className="card">
                    <div className="card-header">
                        <div className="card-title">Database Initialization</div>
                    </div>
                    <p className="text-sm text-muted mb-16">
                        Pull ALL past CVEs from NVD, MITRE, CISA KEV, and RedHat into the database.
                    </p>

                    <div className="form-group" style={{ marginBottom: 12 }}>
                        <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                                <input type="radio" name="initMode" checked={initMode === 'api'} onChange={() => setInitMode('api')} />
                                <span className="text-sm">Via API (slow)</span>
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                                <input type="radio" name="initMode" checked={initMode === 'local'} onChange={() => setInitMode('local')} />
                                <span className="text-sm">Local Directory (fast)</span>
                            </label>
                        </div>

                        {initMode === 'local' && (
                            <div className="form-group">
                                <label className="form-label">MITRE cvelistV5 Path</label>
                                <input className="form-input" placeholder="/path/to/cvelistV5/cves"
                                    value={mitreDir} onChange={e => setMitreDir(e.target.value)} />
                                <p className="text-sm text-muted" style={{ marginTop: 4 }}>
                                    git clone https://github.com/CVEProject/cvelistV5.git
                                </p>
                            </div>
                        )}
                    </div>

                    <button className="btn btn-primary" onClick={handleInitDB}>🗄️ Initialize Full Database</button>
                </div>
            </div>

            {/* Source Distribution */}
            {Object.keys(sourceDist).length > 0 && (
                <div className="card mb-24">
                    <div className="card-header">
                        <div className="card-title">CVEs by Source</div>
                    </div>
                    <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', padding: '0 20px 20px' }}>
                        {Object.entries(sourceDist).map(([source, count]) => (
                            <div key={source} style={{
                                padding: '12px 20px', borderRadius: 8,
                                background: 'rgba(124,58,237,0.1)',
                                border: `1px solid ${sourceColors[source] || '#666'}40`,
                            }}>
                                <div style={{ color: sourceColors[source] || '#888', fontWeight: 'bold', fontSize: 14 }}>{source}</div>
                                <div className="text-mono" style={{ fontSize: 20, fontWeight: 700 }}>{count.toLocaleString()}</div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

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
                                <th>Source</th>
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
                                    <td>
                                        <span style={{
                                            fontSize: 11, padding: '2px 6px', borderRadius: 4,
                                            background: `${sourceColors[cve.source] || '#666'}20`,
                                            color: sourceColors[cve.source] || '#888',
                                        }}>
                                            {cve.source || '—'}
                                        </span>
                                    </td>
                                    <td>{cve.kev_flag ? <span className="badge badge-kev">⚠ KEV</span> : '—'}</td>
                                    <td className="text-sm text-muted">{cve.first_seen ? new Date(cve.first_seen).toLocaleDateString() : '—'}</td>
                                </tr>
                            ))}
                            {(!data?.recent_cves || data.recent_cves.length === 0) && (
                                <tr><td colSpan="8" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>No CVEs yet. Initialize the database to get started.</td></tr>
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
