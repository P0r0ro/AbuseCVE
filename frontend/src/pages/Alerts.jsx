import React, { useState, useEffect, useRef, useCallback } from 'react';
import { getAlerts, getAlertStats, getCVE } from '../api';

const STATUS_COLORS = {
    sent: 'var(--success)',
    failed: 'var(--error)',
    stored: 'var(--text-muted)',
    unknown: 'var(--text-muted)',
};

const PERIOD_OPTIONS = [
    { value: '', label: 'All Time' },
    { value: 'today', label: 'Today' },
    { value: 'week', label: 'This Week' },
    { value: 'month', label: 'This Month' },
    { value: 'year', label: 'This Year' },
];

const STATUS_OPTIONS = [
    { value: '', label: 'All Statuses' },
    { value: 'sent', label: '✅ Sent' },
    { value: 'failed', label: '❌ Failed' },
    { value: 'stored', label: '📦 Stored (no match)' },
];

const ISNEW_OPTIONS = [
    { value: '', label: 'All CVEs' },
    { value: 'true', label: '🆕 New CVEs only' },
    { value: 'false', label: '🔄 Duplicate CVEs only' },
];

export default function Alerts() {
    const [alerts, setAlerts] = useState([]);
    const [stats, setStats] = useState({});
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [expandedCve, setExpandedCve] = useState(null);
    const [cveDetail, setCveDetail] = useState(null);
    const [loadingDetail, setLoadingDetail] = useState(false);

    // Filters
    const [period, setPeriod] = useState('');
    const [status, setStatus] = useState('');
    const [isNew, setIsNew] = useState('');
    const [pql, setPql] = useState('');
    const [pqlInput, setPqlInput] = useState('');

    const pollRef = useRef(null);
    const prevTotalRef = useRef(null);

    const buildParams = useCallback(() => {
        const p = { page, per_page: 30 };
        if (period) p.period = period;
        if (status) p.status = status;
        if (pql) p.pql = pql;
        if (isNew !== '') p.is_new = isNew;
        return p;
    }, [page, period, status, pql, isNew]);

    const fetchAlerts = useCallback(async (silent = false) => {
        if (!silent) setLoading(true); else setRefreshing(true);
        try {
            const [data, s] = await Promise.all([
                getAlerts(buildParams()),
                getAlertStats(),
            ]);
            setAlerts(data.items || []);
            setTotal(data.total || 0);
            setStats(s);
            // Reset page if total changed (new alerts arrived)
            if (prevTotalRef.current !== null && s.total !== prevTotalRef.current && page !== 1) {
                setPage(1);
            }
            prevTotalRef.current = s.total;
        } catch (e) { console.error(e); }
        finally { setLoading(false); setRefreshing(false); }
    }, [buildParams, page]);

    // Initial load + filter changes
    useEffect(() => { setPage(1); }, [period, status, isNew, pql]);
    useEffect(() => { fetchAlerts(); }, [page, period, status, isNew, pql]);

    // Auto-refresh every 30s (lightweight stats poll, full refresh if count changed)
    useEffect(() => {
        pollRef.current = setInterval(async () => {
            try {
                const s = await getAlertStats();
                if (s.total !== prevTotalRef.current) {
                    fetchAlerts(true);
                }
            } catch { /* silent */ }
        }, 30_000);
        return () => clearInterval(pollRef.current);
    }, [fetchAlerts]);

    const handlePqlSearch = (e) => {
        e.preventDefault();
        setPql(pqlInput.trim());
    };

    const handleCveClick = async (cveId) => {
        if (expandedCve === cveId) { setExpandedCve(null); setCveDetail(null); return; }
        setExpandedCve(cveId);
        setLoadingDetail(true);
        try { const d = await getCVE(cveId); setCveDetail(d); }
        catch (e) { setCveDetail({ error: e.message }); }
        finally { setLoadingDetail(false); }
    };

    const totalPages = Math.ceil(total / 30);

    const filterStyle = {
        display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center',
        padding: '14px 20px', background: 'rgba(124,58,237,0.06)',
        border: '1px solid rgba(124,58,237,0.2)', borderRadius: 10, marginBottom: 20,
    };
    const selectStyle = {
        background: 'var(--card-bg)', border: '1px solid var(--border)',
        color: 'var(--text-primary)', borderRadius: 6, padding: '6px 10px',
        fontSize: 13, cursor: 'pointer',
    };

    return (
        <div className="main-content animate-in">
            {/* Header */}
            <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h1 className="header-title">Alerts</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>CVE alert history, notifications, and scan results</p>
                </div>
                <button className="btn btn-secondary" onClick={() => fetchAlerts(true)} disabled={refreshing}>
                    {refreshing ? '↻ Refreshing...' : '↻ Refresh'}
                </button>
            </div>

            {/* Stats — 5 cards */}
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginBottom: 24 }}>
                <div className="stat-card">
                    <div className="stat-icon">📨</div>
                    <div className="stat-value">{stats.total || 0}</div>
                    <div className="stat-label">Total Alerts</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">✅</div>
                    <div className="stat-value" style={{ color: 'var(--success)' }}>{stats.sent || 0}</div>
                    <div className="stat-label">Sent</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">❌</div>
                    <div className="stat-value" style={{ color: 'var(--error)' }}>{stats.failed || 0}</div>
                    <div className="stat-label">Failed</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">🆕</div>
                    <div className="stat-value" style={{ color: 'var(--purple-400)' }}>{stats.new_cve_alerts || 0}</div>
                    <div className="stat-label">New CVE Alerts</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">📅</div>
                    <div className="stat-value">{stats.sent_today || 0}</div>
                    <div className="stat-label">Sent Today</div>
                </div>
            </div>

            {/* Filter Bar */}
            <div style={filterStyle}>
                {/* Period */}
                <select value={period} onChange={e => setPeriod(e.target.value)} style={selectStyle}>
                    {PERIOD_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>

                {/* Status */}
                <select value={status} onChange={e => setStatus(e.target.value)} style={selectStyle}>
                    {STATUS_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>

                {/* New vs Duplicate */}
                <select value={isNew} onChange={e => setIsNew(e.target.value)} style={selectStyle}>
                    {ISNEW_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>

                {/* PQL search */}
                <form onSubmit={handlePqlSearch} style={{ display: 'flex', gap: 6, flex: 1, minWidth: 220 }}>
                    <input
                        className="form-input"
                        style={{ flex: 1, padding: '6px 12px', fontSize: 13 }}
                        placeholder="Search CVE ID or rule name…"
                        value={pqlInput}
                        onChange={e => { setPqlInput(e.target.value); if (!e.target.value) setPql(''); }}
                    />
                    <button type="submit" className="btn btn-secondary" style={{ padding: '6px 14px', fontSize: 13 }}>
                        🔍
                    </button>
                </form>

                {/* Reset */}
                {(period || status || isNew || pql) && (
                    <button className="btn btn-secondary" style={{ fontSize: 12, padding: '5px 12px' }}
                        onClick={() => { setPeriod(''); setStatus(''); setIsNew(''); setPql(''); setPqlInput(''); }}>
                        ✕ Reset
                    </button>
                )}
            </div>

            {/* Table */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">
                        Alert History ({total.toLocaleString()})
                        {(period || status || isNew || pql) && (
                            <span className="text-xs text-muted" style={{ marginLeft: 8, fontWeight: 400 }}>— filtered</span>
                        )}
                    </div>
                </div>
                <div className="table-container">
                    {loading ? (
                        <div className="loading" style={{ padding: 40 }}>
                            <div className="loading-spinner" />Loading alerts...
                        </div>
                    ) : (
                        <table>
                            <thead>
                                <tr>
                                    <th>CVE ID</th>
                                    <th>Status</th>
                                    <th>Type</th>
                                    <th>Rule</th>
                                    <th>Sent At</th>
                                    <th>Recipient</th>
                                    <th>Error</th>
                                </tr>
                            </thead>
                            <tbody>
                                {alerts.map(a => (
                                    <React.Fragment key={a.id}>
                                        <tr style={{ cursor: 'pointer' }}
                                            className={expandedCve === a.cve_id ? 'row-expanded' : ''}>
                                            {/* CVE ID — clickable */}
                                            <td className="text-mono" style={{ color: 'var(--purple-400)' }}
                                                onClick={() => handleCveClick(a.cve_id)}>
                                                {a.cve_id}
                                            </td>

                                            {/* Status badge */}
                                            <td>
                                                <span style={{
                                                    fontSize: 11, padding: '2px 8px', borderRadius: 4, fontWeight: 600,
                                                    background: `${STATUS_COLORS[a.status] || 'var(--text-muted)'}20`,
                                                    color: STATUS_COLORS[a.status] || 'var(--text-muted)',
                                                }}>
                                                    {a.status === 'sent' ? '✅ sent' :
                                                        a.status === 'failed' ? '❌ failed' :
                                                            a.status === 'stored' ? '📦 stored' : a.status}
                                                </span>
                                            </td>

                                            {/* New vs duplicate */}
                                            <td>
                                                {a.is_new_cve === true ? (
                                                    <span style={{ fontSize: 11, color: 'var(--purple-400)', fontWeight: 600 }}>🆕 new</span>
                                                ) : a.is_new_cve === false ? (
                                                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>🔄 dup</span>
                                                ) : (
                                                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span>
                                                )}
                                            </td>

                                            {/* Rule */}
                                            <td className="text-sm text-muted">
                                                {a.rule_name || '—'}
                                            </td>

                                            <td className="text-sm text-muted">
                                                {a.sent_at ? new Date(a.sent_at).toLocaleString() : '—'}
                                            </td>
                                            <td className="text-sm">{a.recipient || '—'}</td>
                                            <td className="text-sm text-muted" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                                {a.error_message || '—'}
                                            </td>
                                        </tr>
                                        {/* CVE detail expand */}
                                        {expandedCve === a.cve_id && (
                                            <tr>
                                                <td colSpan="7" style={{ padding: 0, border: 'none' }}>
                                                    <div style={{ padding: '12px 24px', background: 'rgba(124,58,237,0.05)', borderLeft: '3px solid var(--purple-400)', animation: 'slideDown 0.2s ease' }}>
                                                        {loadingDetail ? (
                                                            <div className="loading"><div className="loading-spinner" style={{ width: 14, height: 14 }} />Loading...</div>
                                                        ) : cveDetail?.error ? (
                                                            <div className="text-sm" style={{ color: 'var(--error)' }}>{cveDetail.error}</div>
                                                        ) : cveDetail ? (
                                                            <div>
                                                                <div className="text-sm" style={{ marginBottom: 6 }}><strong>Description:</strong> {cveDetail.description || 'N/A'}</div>
                                                                <div className="text-xs text-muted">
                                                                    Severity: {cveDetail.severity || 'N/A'} | CVSS: {cveDetail.cvss_score ?? 'N/A'} | Source: {cveDetail.source || 'N/A'}
                                                                    {cveDetail.kev_flag && <span style={{ marginLeft: 8, color: 'var(--error)' }}>⚠ KEV</span>}
                                                                </div>
                                                                {cveDetail.references?.length > 0 && (
                                                                    <div style={{ marginTop: 6 }}>
                                                                        {cveDetail.references.slice(0, 3).map((r, i) => (
                                                                            <a key={i} href={r} target="_blank" rel="noopener" className="text-xs" style={{ display: 'block', color: 'var(--purple-400)' }}>{r}</a>
                                                                        ))}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        ) : null}
                                                    </div>
                                                </td>
                                            </tr>
                                        )}
                                    </React.Fragment>
                                ))}
                                {alerts.length === 0 && (
                                    <tr><td colSpan="7" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>
                                        {(period || status || isNew || pql) ? 'No alerts match the current filters.' : 'No alerts sent yet.'}
                                    </td></tr>
                                )}
                            </tbody>
                        </table>
                    )}
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                    <div className="pagination">
                        <button className="pagination-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
                        <span className="text-sm text-muted">Page {page} of {totalPages}</span>
                        <button className="pagination-btn" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
                    </div>
                )}
            </div>
        </div>
    );
}
