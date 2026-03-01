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
            setReports(r || []);
            setStatus(s || {});
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

    // Colour the status badge — now handles richer strings like "ok (145,312 CVEs)"
    const statusColor = (val) => {
        if (typeof val !== 'string') return 'var(--text-muted)';
        const v = val.toLowerCase();
        if (v.startsWith('ok') || v === 'configured' || v === 'key_configured') return 'var(--success)';
        if (v === 'not_configured' || v === 'keyless_mode') return 'var(--warning)';
        if (v.startsWith('error')) return 'var(--error)';
        return 'var(--text-muted)';
    };

    // Format a status value for display — skip objects, format strings nicely
    const formatVal = (val) => {
        if (val === null || val === undefined) return '—';
        if (typeof val === 'object') return null; // skip nested objects (like redis_details)
        return String(val);
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading...</div></div>;

    return (
        <div className="main-content animate-in">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <div>
                    <h1 className="header-title">🏥 Health Reports</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>System health monitoring and daily reports</p>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn btn-secondary" onClick={handleGenerate}>📊 Generate Report</button>
                    <button className="btn btn-primary" onClick={handleSend}>📧 Generate &amp; Send</button>
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
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, padding: '8px 20px 20px' }}>
                    {Object.entries(status).map(([comp, val]) => {
                        const display = formatVal(val);
                        if (display === null) return null; // skip redis_details object
                        return (
                            <div key={comp} style={{
                                padding: 16, background: 'var(--bg-secondary)', borderRadius: 'var(--radius-md)',
                                border: `1px solid ${statusColor(display)}33`,
                            }}>
                                <div className="text-xs text-muted" style={{ textTransform: 'uppercase', marginBottom: 4 }}>{comp}</div>
                                <div style={{ color: statusColor(display), fontWeight: 700, fontSize: 13, wordBreak: 'break-word' }}>{display}</div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Report History */}
            <div className="card">
                <div className="card-header"><div className="card-title">📋 Report History</div></div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>New Alerted</th>
                                <th>Existing Seen</th>
                                <th>Total CVEs</th>
                                <th>Active Filters</th>
                                <th>Errors</th>
                                <th>Sent</th>
                            </tr>
                        </thead>
                        <tbody>
                            {reports.map(r => (
                                <tr key={r.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(r)}>
                                    <td className="text-sm">{r.report_date ? new Date(r.report_date).toLocaleString() : '—'}</td>
                                    <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{r.new_cves_alerted ?? '—'}</td>
                                    <td className="text-mono">{r.existing_cves_seen ?? '—'}</td>
                                    <td className="text-mono">{(r.total_cves_in_db ?? 0).toLocaleString()}</td>
                                    <td className="text-mono">{r.active_filters ?? '—'}</td>
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
                    <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 700, maxHeight: '85vh', overflowY: 'auto' }}>
                        <div className="modal-header">
                            <h2 className="modal-title">Health Report Details</h2>
                            <button className="modal-close" onClick={() => setSelected(null)}>✕</button>
                        </div>
                        <div className="text-sm text-muted mb-16">{new Date(selected.report_date).toLocaleString()}</div>

                        {/* Stats row */}
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12, marginBottom: 20 }}>
                            <div><span className="text-xs text-muted">New CVEs Alerted</span><p className="text-mono" style={{ fontWeight: 700 }}>{selected.new_cves_alerted}</p></div>
                            <div><span className="text-xs text-muted">Existing CVEs Seen</span><p className="text-mono">{selected.existing_cves_seen}</p></div>
                            <div><span className="text-xs text-muted">Total CVEs in DB</span><p className="text-mono">{(selected.total_cves_in_db || 0).toLocaleString()}</p></div>
                            <div><span className="text-xs text-muted">Active Filters</span><p className="text-mono">{selected.active_filters}</p></div>
                        </div>

                        {/* Warnings */}
                        {(selected.warnings?.length > 0) && (
                            <div className="mb-16">
                                <h4 className="mb-8" style={{ color: 'var(--warning)' }}>⚠️ Warnings</h4>
                                {selected.warnings.map((w, i) => (
                                    <p key={i} className="text-sm" style={{ color: 'var(--warning)', marginBottom: 4 }}>• {w}</p>
                                ))}
                            </div>
                        )}

                        {/* Components */}
                        {selected.components_status && (
                            <div className="mb-16">
                                <h4 className="mb-8">📡 Components</h4>
                                {Object.entries(selected.components_status).map(([k, v]) => {
                                    const display = formatVal(v);
                                    if (display === null) return null;
                                    return (
                                        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-color)' }}>
                                            <span className="text-sm" style={{ fontWeight: 600, textTransform: 'uppercase', fontSize: 11 }}>{k}</span>
                                            <span className="text-sm" style={{ color: statusColor(display), fontWeight: 600, maxWidth: '65%', textAlign: 'right', wordBreak: 'break-all' }}>{display}</span>
                                        </div>
                                    );
                                })}
                            </div>
                        )}

                        {/* Redis details */}
                        {selected.components_status?.redis_details && typeof selected.components_status.redis_details === 'object' && (
                            <div className="mb-16">
                                <h4 className="mb-8">🔴 Redis Detail</h4>
                                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                                    {Object.entries(selected.components_status.redis_details).map(([k, v]) => (
                                        <div key={k} style={{ padding: '8px 12px', background: 'var(--bg-secondary)', borderRadius: 6 }}>
                                            <div className="text-xs text-muted">{k.replace(/_/g, ' ')}</div>
                                            <div className="text-sm" style={{ fontWeight: 600 }}>{String(v)}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Per-filter test results */}
                        {(selected.filter_test_results?.length > 0) && (
                            <div className="mb-16">
                                <h4 className="mb-8">🔍 Filter Test Results <span className="text-xs text-muted">(vs last 5000 CVEs)</span></h4>
                                <div className="table-container">
                                    <table>
                                        <thead><tr><th>Filter</th><th>Matches</th><th>Rate</th><th>Status</th></tr></thead>
                                        <tbody>
                                            {selected.filter_test_results.map(f => (
                                                <tr key={f.id}>
                                                    <td className="text-sm">{f.name}</td>
                                                    <td className="text-mono">{(f.matches || 0).toLocaleString()} / {(f.sample_size || 0).toLocaleString()}</td>
                                                    <td className="text-mono">{f.match_rate ?? 0}%</td>
                                                    <td>
                                                        <span className={`badge badge-${f.status === 'matching' ? 'success' : 'warning'}`}>
                                                            {f.status === 'matching' ? '✓ Matching' : '⚠ No matches'}
                                                        </span>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}

                        {/* Errors */}
                        {selected.errors?.length > 0 && (
                            <div>
                                <h4 className="mb-8" style={{ color: 'var(--error)' }}>❌ Errors</h4>
                                {selected.errors.map((e, i) => (
                                    <p key={i} className="text-sm" style={{ color: 'var(--error)', marginBottom: 4 }}>
                                        {e.cve_id}: {e.error}
                                    </p>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
