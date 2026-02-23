import React, { useState, useEffect } from 'react';
import { getAlerts, getAlertStats } from '../api';

export default function Alerts() {
    const [alerts, setAlerts] = useState([]);
    const [stats, setStats] = useState({});
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [loading, setLoading] = useState(true);

    const fetchAlerts = async () => {
        try {
            const [data, s] = await Promise.all([
                getAlerts({ page, per_page: 30 }),
                getAlertStats(),
            ]);
            setAlerts(data.items);
            setTotal(data.total);
            setStats(s);
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    };

    useEffect(() => { fetchAlerts(); }, [page]);

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading alerts...</div></div>;

    return (
        <div className="main-content animate-in">
            <div style={{ marginBottom: 24 }}>
                <h1 className="header-title">Alerts</h1>
                <p className="text-sm text-muted" style={{ marginTop: 4 }}>CVE alert history and notifications</p>
            </div>

            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
                <div className="stat-card">
                    <div className="stat-icon">📨</div>
                    <div className="stat-value">{stats.total || 0}</div>
                    <div className="stat-label">Total Alerts</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">✅</div>
                    <div className="stat-value" style={{ color: 'var(--success)' }}>{stats.sent || 0}</div>
                    <div className="stat-label">Sent Successfully</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">❌</div>
                    <div className="stat-value" style={{ color: 'var(--error)' }}>{stats.failed || 0}</div>
                    <div className="stat-label">Failed</div>
                </div>
            </div>

            <div className="card">
                <div className="card-header">
                    <div className="card-title">Alert History ({total})</div>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Status</th>
                                <th>Sent At</th>
                                <th>Recipient</th>
                                <th>Error</th>
                            </tr>
                        </thead>
                        <tbody>
                            {alerts.map(a => (
                                <tr key={a.id}>
                                    <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{a.cve_id}</td>
                                    <td><span className={`badge ${a.status === 'sent' ? 'badge-success' : 'badge-error'}`}>{a.status}</span></td>
                                    <td className="text-sm text-muted">{a.sent_at ? new Date(a.sent_at).toLocaleString() : '—'}</td>
                                    <td className="text-sm">{a.recipient || '—'}</td>
                                    <td className="text-sm text-muted">{a.error_message || '—'}</td>
                                </tr>
                            ))}
                            {alerts.length === 0 && (
                                <tr><td colSpan="5" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>No alerts sent yet.</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
                {total > 30 && (
                    <div className="pagination">
                        <button className="pagination-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
                        <span className="text-sm text-muted">Page {page} of {Math.ceil(total / 30)}</span>
                        <button className="pagination-btn" disabled={page >= Math.ceil(total / 30)} onClick={() => setPage(p => p + 1)}>Next →</button>
                    </div>
                )}
            </div>
        </div>
    );
}
