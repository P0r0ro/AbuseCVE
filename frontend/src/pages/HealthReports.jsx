import React, { useState, useEffect } from 'react';
import { getHealthReports, getComponentStatus, generateHealthReport, sendHealthReport } from '../api';

export default function HealthReports() {
    const [reports, setReports] = useState([]);
    const [status, setStatus] = useState({});
    const [loading, setLoading] = useState(true);
    const [actionMsg, setActionMsg] = useState('');
    const [selected, setSelected] = useState(null);

    const fetchData = async () => {
        try {
            const [r, s] = await Promise.all([getHealthReports(), getComponentStatus()]);
            setReports(r);
            setStatus(s);
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    };

    useEffect(() => { fetchData(); }, []);

    const handleGenerate = async () => {
        setActionMsg('Generating report...');
        try {
            await generateHealthReport();
            setActionMsg('✅ Report generated');
            fetchData();
        } catch (e) { setActionMsg(`❌ ${e.message}`); }
    };

    const handleSend = async () => {
        setActionMsg('Generating and sending report...');
        try {
            const result = await sendHealthReport();
            setActionMsg(result.email?.status === 'sent' ? '✅ Report sent!' : `⚠️ Email: ${result.email?.error || 'unknown'}`);
            fetchData();
        } catch (e) { setActionMsg(`❌ ${e.message}`); }
    };

    const statusColor = (val) => {
        if (val === 'ok' || val === 'configured' || val === 'key_configured') return 'var(--success)';
        if (val === 'not_configured' || val === 'keyless_mode') return 'var(--warning)';
        return 'var(--error)';
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading...</div></div>;

    return (
        <div className="main-content animate-in">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <div>
                    <h1 className="header-title">Health Reports</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>System health monitoring and daily reports</p>
                </div>
                <div className="flex gap-8">
                    <button className="btn btn-secondary" onClick={handleGenerate}>📊 Generate Report</button>
                    <button className="btn btn-primary" onClick={handleSend}>📧 Generate & Send</button>
                </div>
            </div>

            {actionMsg && (
                <div className="card mb-20" style={{ padding: '12px 20px' }}>
                    <span className="text-sm">{actionMsg}</span>
                </div>
            )}

            {/* Live Component Status */}
            <div className="card mb-24">
                <div className="card-header"><div className="card-title">🟢 Live Component Status</div></div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
                    {Object.entries(status).map(([comp, val]) => (
                        <div key={comp} style={{
                            padding: 16, background: 'var(--bg-secondary)', borderRadius: 'var(--radius-md)',
                            border: `1px solid ${statusColor(val)}33`,
                        }}>
                            <div className="text-xs text-muted" style={{ textTransform: 'uppercase', marginBottom: 4 }}>{comp}</div>
                            <div style={{ color: statusColor(val), fontWeight: 700, fontSize: 14 }}>{val}</div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Report History */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">Report History</div>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>New Alerted</th>
                                <th>Existing Seen</th>
                                <th>Total CVEs</th>
                                <th>Filters</th>
                                <th>Errors</th>
                                <th>Sent</th>
                            </tr>
                        </thead>
                        <tbody>
                            {reports.map(r => (
                                <tr key={r.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(r)}>
                                    <td className="text-sm">{r.report_date ? new Date(r.report_date).toLocaleString() : '—'}</td>
                                    <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{r.new_cves_alerted}</td>
                                    <td className="text-mono">{r.existing_cves_seen}</td>
                                    <td className="text-mono">{r.total_cves_in_db}</td>
                                    <td className="text-mono">{r.active_filters}</td>
                                    <td>
                                        {(r.errors?.length || 0) > 0
                                            ? <span className="badge badge-error">{r.errors.length} errors</span>
                                            : <span className="badge badge-success">None</span>
                                        }
                                    </td>
                                    <td>{r.sent ? <span className="badge badge-success">✓ Sent</span> : <span className="badge badge-info">Local</span>}</td>
                                </tr>
                            ))}
                            {reports.length === 0 && (
                                <tr><td colSpan="7" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>No health reports yet. Generate one to get started.</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Detail Modal */}
            {selected && (
                <div className="modal-overlay" onClick={() => setSelected(null)}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h2 className="modal-title">Health Report</h2>
                            <button className="modal-close" onClick={() => setSelected(null)}>✕</button>
                        </div>
                        <div className="text-sm text-muted mb-16">{new Date(selected.report_date).toLocaleString()}</div>
                        <div className="grid-2 mb-16">
                            <div><span className="text-xs text-muted">New CVEs Alerted</span><p className="text-mono font-bold">{selected.new_cves_alerted}</p></div>
                            <div><span className="text-xs text-muted">Existing CVEs Seen</span><p className="text-mono">{selected.existing_cves_seen}</p></div>
                            <div><span className="text-xs text-muted">Total CVEs in DB</span><p className="text-mono">{selected.total_cves_in_db}</p></div>
                            <div><span className="text-xs text-muted">Active Filters</span><p className="text-mono">{selected.active_filters}</p></div>
                        </div>
                        {selected.components_status && (
                            <div className="mb-16">
                                <h4 className="mb-8">Components</h4>
                                {Object.entries(selected.components_status).map(([k, v]) => (
                                    <div key={k} className="flex justify-between" style={{ padding: '4px 0' }}>
                                        <span className="text-sm">{k}</span>
                                        <span className="text-sm" style={{ color: statusColor(v), fontWeight: 600 }}>{v}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                        {selected.errors?.length > 0 && (
                            <div>
                                <h4 className="mb-8" style={{ color: 'var(--error)' }}>Errors</h4>
                                {selected.errors.map((e, i) => (
                                    <p key={i} className="text-sm" style={{ color: 'var(--error)' }}>{e.cve_id}: {e.error}</p>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
