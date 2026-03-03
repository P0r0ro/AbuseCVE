import React, { useState, useEffect, useRef, useCallback } from 'react';
import { getAlerts, getAlertStats, getCVE, getQueryHelp } from '../api';

const STATUS_OPTIONS = [
    { value: '', label: 'All Statuses' },
    { value: 'sent', label: '✅ Sent' },
    { value: 'failed', label: '❌ Failed' },
    { value: 'stored', label: '💾 Stored (no rule match)' },
];

const PERIOD_OPTIONS = [
    { value: '', label: 'All Time' },
    { value: 'today', label: 'Today' },
    { value: 'week', label: 'This Week' },
    { value: 'month', label: 'This Month' },
    { value: 'year', label: 'This Year' },
];

const TYPE_OPTIONS = [
    { value: '', label: 'All Types' },
    { value: 'true', label: '🆕 New CVE' },
    { value: 'false', label: '🔁 Duplicate' },
];

const STATUS_BADGE = {
    sent: 'badge-success',
    failed: 'badge-error',
    stored: 'badge-stored',
};

export default function Alerts() {
    const [alerts, setAlerts] = useState([]);
    const [stats, setStats] = useState({});
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [loading, setLoading] = useState(true);
    const [lastUpdated, setLastUpdated] = useState(null);

    // Filters
    const [statusFilter, setStatusFilter] = useState('');
    const [periodFilter, setPeriodFilter] = useState('');
    const [typeFilter, setTypeFilter] = useState('');
    const [pqlQuery, setPqlQuery] = useState('');
    const [activePql, setActivePql] = useState('');  // only applies on Enter/Search
    const [showHelp, setShowHelp] = useState(false);
    const [queryHelp, setQueryHelp] = useState(null);

    // CVE detail expand
    const [expandedCve, setExpandedCve] = useState(null);
    const [cveDetail, setCveDetail] = useState(null);

    const pollRef = useRef(null);

    const fetchAlerts = useCallback(async (isPolling = false) => {
        if (!isPolling) setLoading(true);
        try {
            const params = { page, per_page: 30 };
            if (statusFilter) params.status = statusFilter;
            if (periodFilter) params.period = periodFilter;
            if (typeFilter) params.is_new = typeFilter;
            if (activePql) params.pql = activePql;

            const [data, s] = await Promise.all([
                getAlerts(params),
                getAlertStats(),
            ]);
            setAlerts(data.items);
            setTotal(data.total);
            setStats(s);
            setLastUpdated(new Date());
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    }, [page, statusFilter, periodFilter, typeFilter, activePql]);

    // Fetch on filter/page change
    useEffect(() => {
        setPage(1);
    }, [statusFilter, periodFilter, typeFilter]);

    useEffect(() => {
        fetchAlerts();
    }, [fetchAlerts]);

    // Auto-poll every 30s
    useEffect(() => {
        if (pollRef.current) clearInterval(pollRef.current);
        pollRef.current = setInterval(() => fetchAlerts(true), 30000);
        return () => clearInterval(pollRef.current);
    }, [fetchAlerts]);

    const handleCveClick = async (cveId) => {
        if (expandedCve === cveId) { setExpandedCve(null); setCveDetail(null); return; }
        setExpandedCve(cveId);
        try { const d = await getCVE(cveId); setCveDetail(d); } catch (e) { setCveDetail({ error: e.message }); }
    };

    const filterBtnStyle = (active) => ({
        padding: '5px 12px',
        borderRadius: 6,
        border: `1px solid ${active ? 'var(--purple-400)' : 'var(--border)'}`,
        background: active ? 'rgba(124,58,237,0.18)' : 'transparent',
        color: active ? 'var(--purple-400)' : 'var(--text-muted)',
        cursor: 'pointer',
        fontSize: 12,
        fontWeight: active ? 600 : 400,
        transition: 'all 0.15s ease',
    });

    const totalPages = Math.ceil(total / 30);

    return (
        <div className="main-content animate-in">
            {/* Header */}
            <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                <div>
                    <h1 className="header-title">Alerts</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>CVE alert history — auto-refreshes every 30s</p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    {lastUpdated && (
                        <span className="text-xs text-muted">
                            Updated {lastUpdated.toLocaleTimeString()}
                        </span>
                    )}
                    <button className="btn btn-secondary" onClick={() => fetchAlerts()}>↻ Refresh</button>
                </div>
            </div>

            {/* PQL Search Bar */}
            <div className="card mb-20">
                <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    <div style={{ flex: 1 }}>
                        <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            🔍 PQL Filter
                            <button className="btn btn-secondary btn-sm" style={{ fontSize: 11, padding: '2px 8px' }}
                                onClick={async () => {
                                    setShowHelp(true);
                                    if (!queryHelp) {
                                        try { const h = await getQueryHelp(); setQueryHelp(h); } catch (e) { setQueryHelp({ error: e.message }); }
                                    }
                                }}>? Help</button>
                        </label>
                        <input className="form-input" style={{ fontFamily: 'monospace', fontSize: 13 }}
                            placeholder='vendor:microsoft severity:HIGH,CRITICAL cvss:>7.0  OR  "buffer overflow"'
                            value={pqlQuery}
                            onChange={e => setPqlQuery(e.target.value)}
                            onKeyDown={e => { if (e.key === 'Enter') { setActivePql(pqlQuery); setPage(1); } }}
                        />
                        <span className="text-xs text-muted" style={{ marginTop: 4, display: 'block' }}>
                            Filters alerts by CVE attributes • Press Enter to apply • Supports: vendor:X severity:X cvss:&gt;N kev:true
                        </span>
                    </div>
                    <button className="btn btn-primary" style={{ alignSelf: 'flex-end', marginBottom: 20 }}
                        onClick={() => { setActivePql(pqlQuery); setPage(1); }}>🔎 Filter</button>
                    {activePql && (
                        <button className="btn btn-secondary" style={{ alignSelf: 'flex-end', marginBottom: 20 }}
                            onClick={() => { setPqlQuery(''); setActivePql(''); setPage(1); }}>✕ Clear</button>
                    )}
                </div>
                {activePql && (
                    <div className="text-xs" style={{ marginTop: 8, color: 'var(--purple-400)', fontFamily: 'monospace' }}>
                        Active filter: {activePql}
                    </div>
                )}
            </div>

            {/* Stats Cards */}
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginBottom: 24 }}>
                <div className="stat-card">
                    <div className="stat-icon">📨</div>
                    <div className="stat-value">{stats.total || 0}</div>
                    <div className="stat-label">Total</div>
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
                    <div className="stat-icon">💾</div>
                    <div className="stat-value" style={{ color: 'var(--text-muted)' }}>{stats.stored || 0}</div>
                    <div className="stat-label">Stored (no match)</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">🆕</div>
                    <div className="stat-value" style={{ color: 'var(--purple-400)' }}>{stats.new_cves || 0}</div>
                    <div className="stat-label">New CVEs</div>
                </div>
            </div>

            {/* Today's quick summary */}
            {(stats.today_sent > 0 || stats.today_failed > 0 || stats.today_stored > 0) && (
                <div className="card mb-20" style={{ padding: '12px 20px', display: 'flex', gap: 24, alignItems: 'center' }}>
                    <span className="text-sm" style={{ color: 'var(--text-muted)', marginRight: 4 }}>Today:</span>
                    {stats.today_sent > 0 && <span className="text-sm" style={{ color: 'var(--success)' }}>✅ {stats.today_sent} sent</span>}
                    {stats.today_failed > 0 && <span className="text-sm" style={{ color: 'var(--error)' }}>❌ {stats.today_failed} failed</span>}
                    {stats.today_stored > 0 && <span className="text-sm" style={{ color: 'var(--text-muted)' }}>💾 {stats.today_stored} stored (no match)</span>}
                </div>
            )}

            {/* Filter Bar */}
            <div className="card mb-20" style={{ padding: '12px 16px' }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, alignItems: 'center' }}>
                    {/* Period */}
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <span className="text-xs text-muted" style={{ marginRight: 4 }}>Period:</span>
                        {PERIOD_OPTIONS.map(o => (
                            <button key={o.value} style={filterBtnStyle(periodFilter === o.value)}
                                onClick={() => setPeriodFilter(o.value)}>{o.label}</button>
                        ))}
                    </div>
                    <div style={{ width: 1, height: 20, background: 'var(--border)' }} />
                    {/* Status */}
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <span className="text-xs text-muted" style={{ marginRight: 4 }}>Status:</span>
                        {STATUS_OPTIONS.map(o => (
                            <button key={o.value} style={filterBtnStyle(statusFilter === o.value)}
                                onClick={() => setStatusFilter(o.value)}>{o.label}</button>
                        ))}
                    </div>
                    <div style={{ width: 1, height: 20, background: 'var(--border)' }} />
                    {/* Type */}
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <span className="text-xs text-muted" style={{ marginRight: 4 }}>Type:</span>
                        {TYPE_OPTIONS.map(o => (
                            <button key={o.value} style={filterBtnStyle(typeFilter === o.value)}
                                onClick={() => setTypeFilter(o.value)}>{o.label}</button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Table */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">
                        Alert History ({total})
                        {loading && <span className="loading-spinner" style={{ width: 14, height: 14, borderWidth: 2, marginLeft: 10, display: 'inline-block' }} />}
                    </div>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Status</th>
                                <th>Type</th>
                                <th>Rule Matched</th>
                                <th>Sent At</th>
                                <th>Recipient</th>
                                <th>Error</th>
                            </tr>
                        </thead>
                        <tbody>
                            {alerts.map(a => (
                                <React.Fragment key={a.id}>
                                    <tr style={{ cursor: 'pointer' }} onClick={() => handleCveClick(a.cve_id)}
                                        className={expandedCve === a.cve_id ? 'row-expanded' : ''}>
                                        <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{a.cve_id}</td>
                                        <td>
                                            <span className={`badge ${STATUS_BADGE[a.status] || 'badge-error'}`}>
                                                {a.status === 'sent' ? '✅ sent' : a.status === 'failed' ? '❌ failed' : '💾 stored'}
                                            </span>
                                        </td>
                                        <td>
                                            <span style={{
                                                fontSize: 11, padding: '2px 6px', borderRadius: 4,
                                                background: a.is_new_cve ? 'rgba(124,58,237,0.15)' : 'rgba(255,255,255,0.05)',
                                                color: a.is_new_cve ? 'var(--purple-400)' : 'var(--text-muted)',
                                            }}>
                                                {a.is_new_cve ? '🆕 New' : '🔁 Dup'}
                                            </span>
                                        </td>
                                        <td className="text-sm text-muted">{a.rule_name || '—'}</td>
                                        <td className="text-sm text-muted">{a.sent_at ? new Date(a.sent_at).toLocaleString() : '—'}</td>
                                        <td className="text-sm">{a.recipient || '—'}</td>
                                        <td className="text-sm text-muted" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.error_message || '—'}</td>
                                    </tr>
                                    {expandedCve === a.cve_id && cveDetail && (
                                        <tr><td colSpan="7" style={{ padding: 0, border: 'none' }}>
                                            <div style={{ padding: '12px 24px', background: 'rgba(124,58,237,0.05)', borderLeft: '3px solid var(--purple-400)', animation: 'slideDown 0.2s ease' }}>
                                                {cveDetail.error ? (
                                                    <div className="text-sm" style={{ color: 'var(--error)' }}>{cveDetail.error}</div>
                                                ) : (
                                                    <div>
                                                        <div className="text-sm" style={{ marginBottom: 6 }}><strong>Description:</strong> {cveDetail.description || 'N/A'}</div>
                                                        <div className="text-xs text-muted">
                                                            Severity: {cveDetail.severity || 'N/A'} | CVSS: {cveDetail.cvss_score ?? 'N/A'} | Source: {cveDetail.source || 'N/A'}
                                                            {cveDetail.kev_flag && <span className="badge badge-kev" style={{ marginLeft: 8 }}>⚠ KEV</span>}
                                                        </div>
                                                        {cveDetail.references?.length > 0 && (
                                                            <div style={{ marginTop: 6 }}>
                                                                {cveDetail.references.slice(0, 3).map((r, i) => (
                                                                    <a key={i} href={r} target="_blank" rel="noopener" className="text-xs" style={{ display: 'block', color: 'var(--purple-400)' }}>{r}</a>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                        </td></tr>
                                    )}
                                </React.Fragment>
                            ))}
                            {alerts.length === 0 && !loading && (
                                <tr><td colSpan="7" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>
                                    No alerts match the current filters.
                                </td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
                {totalPages > 1 && (
                    <div className="pagination">
                        <button className="pagination-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
                        <span className="text-sm text-muted">Page {page} of {totalPages}</span>
                        <button className="pagination-btn" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
                    </div>
                )}
            </div>

            {/* PQL Help Modal */}
            {showHelp && (
                <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setShowHelp(false)}>
                    <div className="modal" style={{ maxWidth: 700 }}>
                        <div className="modal-header">
                            <h2 className="modal-title">📖 PQL Query Language Reference</h2>
                            <button className="modal-close" onClick={() => setShowHelp(false)}>×</button>
                        </div>
                        {queryHelp?.error ? (
                            <p className="text-sm" style={{ color: 'var(--error)' }}>{queryHelp.error}</p>
                        ) : queryHelp ? (
                            <div style={{ maxHeight: 500, overflow: 'auto' }}>
                                {queryHelp.fields && (
                                    <div className="mb-16">
                                        <h3 className="text-sm" style={{ fontWeight: 700, marginBottom: 8 }}>Available Fields</h3>
                                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                                            {queryHelp.fields.map(f => (
                                                <span key={f} className="badge badge-info" style={{ fontSize: 12 }}>{f}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                <div className="mb-16">
                                    <h3 className="text-sm" style={{ fontWeight: 700, marginBottom: 8 }}>PQL Quick Reference</h3>
                                    <pre style={{ background: 'var(--bg-secondary)', padding: 16, borderRadius: 8, fontSize: 12, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>{`# Search alerts for Microsoft CVEs with HIGH/CRITICAL severity
vendor:microsoft severity:CRITICAL,HIGH

# CVEs with CVSS score above 7.0
cvss:>7.0

# Known Exploited Vulnerabilities only
kev:true

# Combine conditions
vendor:fortinet AND severity:CRITICAL

# Description keyword
description:"remote code execution"`}</pre>
                                </div>
                            </div>
                        ) : (
                            <div className="loading"><div className="loading-spinner" /> Loading help...</div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
