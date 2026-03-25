import React, { useState, useEffect, useRef, useCallback } from 'react';
import { getAlerts, getAlertStats, getCVE, exportAlertsExcel } from '../api';
import RefineModal from '../components/RefineModal';
import { CheckCircle2, XCircle, Package, BadgePlus, RefreshCw, Download, ClipboardList, X, Send, Calendar, Search, AlertTriangle, ArrowRight } from 'lucide-react';

const STATUS_COLORS = {
    sent: 'var(--success)',
    failed: 'var(--error)',
    stored: 'var(--text-muted)',
    unknown: 'var(--text-muted)',
};

const STATUS_OPTIONS = [
    { value: '', label: 'All Statuses' },
    { value: 'sent', label: 'Sent' },
    { value: 'failed', label: 'Failed' },
    { value: 'stored', label: 'Stored (no match)' },
];

const ISNEW_OPTIONS = [
    { value: '', label: 'All CVEs' },
    { value: 'true', label: 'New CVEs only' },
    { value: 'false', label: 'Duplicate CVEs only' },
];

const QUICK_PERIODS = [
    { value: '1d', label: 'Today' },
    { value: '7d', label: 'Last 7d' },
    { value: '30d', label: 'Last 30d' },
    { value: '90d', label: 'Last 90d' },
];

function periodLabel(period, dateFrom, dateTo) {
    if (dateFrom || dateTo) {
        const from = dateFrom || '...';
        const to = dateTo || 'now';
        return `${from} → ${to}`;
    }
    if (!period) return 'All Time';
    if (period === '1d' || period === 'today') return 'Today';
    const match = period.match(/^(\d+)([dwmy])$/);
    if (match) {
        const n = match[1];
        const unitMap = { d: 'Day', w: 'Week', m: 'Month', y: 'Year' };
        const unit = unitMap[match[2]] || match[2];
        return `Last ${n} ${unit}${n > 1 ? 's' : ''}`;
    }
    const legacy = { week: 'Last 7 Days', month: 'Last 30 Days', year: 'Last Year' };
    return legacy[period] || period;
}

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
    const [showExportMenu, setShowExportMenu] = useState(false);
    const [exporting, setExporting] = useState(false);

    // Refine modal state
    const [refineAlert, setRefineAlert] = useState(null);
    const [refineCveDetail, setRefineCveDetail] = useState(null);

    // Filters
    const [period, setPeriod] = useState('1d');
    const [dateFrom, setDateFrom] = useState('');
    const [dateTo, setDateTo] = useState('');
    const [showCalendar, setShowCalendar] = useState(false);
    const [status, setStatus] = useState('');
    const [isNew, setIsNew] = useState('');
    const [pql, setPql] = useState('');
    const [pqlInput, setPqlInput] = useState('');

    const pollRef = useRef(null);
    const prevTotalRef = useRef(null);

    const buildParams = useCallback(() => {
        const p = { page, per_page: 30 };
        if (dateFrom || dateTo) {
            if (dateFrom) p.date_from = dateFrom;
            if (dateTo) p.date_to = dateTo;
        } else if (period) {
            p.period = period;
        }
        if (status) p.status = status;
        if (pql) p.pql = pql;
        if (isNew !== '') p.is_new = isNew;
        return p;
    }, [page, period, dateFrom, dateTo, status, pql, isNew]);

    const fetchAlerts = useCallback(async (silent = false) => {
        if (!silent) setLoading(true); else setRefreshing(true);
        const statsParams = {};
        if (dateFrom || dateTo) {
            if (dateFrom) statsParams.date_from = dateFrom;
            if (dateTo) statsParams.date_to = dateTo;
        } else if (period) {
            statsParams.period = period;
        }
        try {
            const [data, s] = await Promise.all([
                getAlerts(buildParams()),
                getAlertStats(statsParams),
            ]);
            setAlerts(data.items || []);
            setTotal(data.total || 0);
            setStats(s);
            if (prevTotalRef.current !== null && s.total !== prevTotalRef.current && page !== 1) {
                setPage(1);
            }
            prevTotalRef.current = s.total;
        } catch (e) { console.error(e); }
        finally { setLoading(false); setRefreshing(false); }
    }, [buildParams, page, period, dateFrom, dateTo]);

    // Initial load + filter changes
    useEffect(() => { setPage(1); }, [period, dateFrom, dateTo, status, isNew, pql]);
    useEffect(() => { fetchAlerts(); }, [page, period, dateFrom, dateTo, status, isNew, pql]);

    // Auto-refresh every 30s
    useEffect(() => {
        pollRef.current = setInterval(async () => {
            try {
                const sp = {};
                if (dateFrom || dateTo) {
                    if (dateFrom) sp.date_from = dateFrom;
                    if (dateTo) sp.date_to = dateTo;
                } else if (period) {
                    sp.period = period;
                }
                const s = await getAlertStats(sp);
                if (s.total !== prevTotalRef.current) {
                    fetchAlerts(true);
                }
            } catch { /* silent */ }
        }, 30_000);
        return () => clearInterval(pollRef.current);
    }, [fetchAlerts, period, dateFrom, dateTo]);

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

    const handleDateRange = () => {
        if (dateFrom || dateTo) {
            setPeriod('');
            setShowCalendar(false);
        }
    };

    const handleQuickPeriod = (val) => {
        setPeriod(val);
        setDateFrom('');
        setDateTo('');
        setShowCalendar(false);
    };

    const handleExport = async (mode) => {
        setExporting(true);
        setShowExportMenu(false);
        try {
            const p = { mode };
            if (mode === 'filtered') {
                if (dateFrom || dateTo) {
                    if (dateFrom) p.date_from = dateFrom;
                    if (dateTo) p.date_to = dateTo;
                } else if (period) {
                    p.period = period;
                }
                if (status) p.status = status;
                if (pql) p.pql = pql;
                if (isNew !== '') p.is_new = isNew;
            }
            await exportAlertsExcel(p);
        } catch (e) {
            alert('Export failed: ' + e.message);
        } finally {
            setExporting(false);
        }
    };

    const handleOpenRefine = async (a) => {
        setRefineAlert(a);
        try {
            const d = await getCVE(a.cve_id);
            setRefineCveDetail(d);
        } catch {
            setRefineCveDetail(null);
        }
    };

    // Resolve rule ID: use filter_rule_id if present, otherwise try to find by rule_name
    const getAlertRuleId = (a) => {
        if (a.filter_rule_id) return a.filter_rule_id;
        return null;
    };

    const totalPages = Math.ceil(total / 30);
    const currentPeriodLabel = periodLabel(period, dateFrom, dateTo);

    const filterStyle = {
        display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center',
        padding: '14px 20px', background: 'rgba(124,58,237,0.06)',
        border: '1px solid rgba(124,58,237,0.2)', borderRadius: 10, marginBottom: 20,
    };

    const dateInputStyle = {
        padding: '5px 10px', fontSize: 13, borderRadius: 6,
        background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)',
        color: 'var(--text-primary)', fontFamily: 'inherit',
    };

    return (
        <div className="main-content animate-in">
            {/* Header */}
            <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h1 className="header-title">Alerts</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>CVE alert history, notifications, and scan results</p>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                    <div style={{ position: 'relative' }}>
                        <button className="btn btn-secondary" onClick={() => setShowExportMenu(!showExportMenu)} disabled={exporting}>
                            {exporting ? '...Exporting' : <><Download size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Export Excel</>}
                        </button>
                        {showExportMenu && (
                            <div style={{
                                position: 'absolute', top: '100%', right: 0, marginTop: 4, zIndex: 100,
                                background: 'var(--card-bg)', border: '1px solid var(--border)',
                                borderRadius: 8, padding: 4, minWidth: 180, boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
                            }}>
                                <button style={{
                                    display: 'block', width: '100%', textAlign: 'left', padding: '8px 12px',
                                    background: 'none', border: 'none', color: 'var(--text-primary)',
                                    cursor: 'pointer', borderRadius: 6, fontSize: 13,
                                }} onMouseOver={e => e.target.style.background = 'rgba(124,58,237,0.1)'}
                                   onMouseOut={e => e.target.style.background = 'none'}
                                   onClick={() => handleExport('filtered')}>
                                    <ClipboardList size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Export Filtered
                                </button>
                                <button style={{
                                    display: 'block', width: '100%', textAlign: 'left', padding: '8px 12px',
                                    background: 'none', border: 'none', color: 'var(--text-primary)',
                                    cursor: 'pointer', borderRadius: 6, fontSize: 13,
                                }} onMouseOver={e => e.target.style.background = 'rgba(124,58,237,0.1)'}
                                   onMouseOut={e => e.target.style.background = 'none'}
                                   onClick={() => handleExport('all')}>
                                    <Package size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Export All
                                </button>
                            </div>
                        )}
                    </div>
                    <button className="btn btn-secondary" onClick={() => fetchAlerts(true)} disabled={refreshing}>
                        {refreshing ? <><RefreshCw size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Refreshing...</> : <><RefreshCw size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Refresh</>}
                    </button>
                </div>
            </div>

            {/* Time Filter */}
            <div style={{
                display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center',
                marginBottom: 16, padding: '10px 16px',
                background: 'rgba(124,58,237,0.04)', border: '1px solid rgba(124,58,237,0.15)',
                borderRadius: 10,
            }}>
                <span className="text-sm text-muted" style={{ marginRight: 4 }}>Time Range:</span>
                {QUICK_PERIODS.map(qp => (
                    <button key={qp.value}
                        className={period === qp.value && !dateFrom && !dateTo ? 'btn btn-primary' : 'btn btn-secondary'}
                        style={{ padding: '4px 12px', fontSize: 12 }}
                        onClick={() => handleQuickPeriod(qp.value)}>
                        {qp.label}
                    </button>
                ))}
                <span className="text-sm text-muted" style={{ margin: '0 4px' }}>|</span>
                <button
                    className={`btn ${showCalendar || dateFrom || dateTo ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ padding: '4px 12px', fontSize: 12 }}
                    onClick={() => setShowCalendar(!showCalendar)}>
                    <Calendar size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Custom Range
                </button>
                {(period || dateFrom || dateTo) && (
                    <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 11 }}
                        onClick={() => { setPeriod(''); setDateFrom(''); setDateTo(''); setShowCalendar(false); }}>
                        <X size={12} style={{ verticalAlign: 'middle', marginRight: 2 }} /> All Time
                    </button>
                )}
                <span className="text-xs text-muted" style={{ marginLeft: 'auto' }}>
                    Showing: {currentPeriodLabel}
                </span>
            </div>

            {/* Calendar Date Range Picker */}
            {showCalendar && (
                <div style={{
                    display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap',
                    marginBottom: 16, padding: '14px 20px',
                    background: 'var(--bg-card)', border: '1px solid var(--border-accent)',
                    borderRadius: 10,
                }}>
                    <span className="text-sm" style={{ fontWeight: 600 }}>From:</span>
                    <input
                        type="date"
                        value={dateFrom}
                        onChange={e => setDateFrom(e.target.value)}
                        style={dateInputStyle}
                    />
                    <ArrowRight size={14} style={{ color: 'var(--text-muted)' }} />
                    <span className="text-sm" style={{ fontWeight: 600 }}>To:</span>
                    <input
                        type="date"
                        value={dateTo}
                        onChange={e => setDateTo(e.target.value)}
                        style={dateInputStyle}
                    />
                    <button className="btn btn-primary" style={{ padding: '5px 16px', fontSize: 12 }}
                        onClick={handleDateRange} disabled={!dateFrom && !dateTo}>
                        Apply Range
                    </button>
                    {(dateFrom || dateTo) && (
                        <button className="btn btn-secondary" style={{ padding: '5px 12px', fontSize: 12 }}
                            onClick={() => { setDateFrom(''); setDateTo(''); setPeriod('1d'); }}>
                            <X size={12} style={{ verticalAlign: 'middle', marginRight: 2 }} /> Clear Dates
                        </button>
                    )}
                </div>
            )}

            {/* Stats — 5 cards (period-scoped) */}
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginBottom: 24 }}>
                <div className="stat-card">
                    <div className="stat-icon"><Send size={20} /></div>
                    <div className="stat-value">{stats.total || 0}</div>
                    <div className="stat-label">Total Alerts</div>
                    <div className="text-xs text-muted" style={{ marginTop: 2 }}>{currentPeriodLabel}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon"><CheckCircle2 size={20} /></div>
                    <div className="stat-value" style={{ color: 'var(--success)' }}>{stats.sent || 0}</div>
                    <div className="stat-label">Sent</div>
                    <div className="text-xs text-muted" style={{ marginTop: 2 }}>{currentPeriodLabel}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon"><XCircle size={20} /></div>
                    <div className="stat-value" style={{ color: 'var(--error)' }}>{stats.failed || 0}</div>
                    <div className="stat-label">Failed</div>
                    <div className="text-xs text-muted" style={{ marginTop: 2 }}>{currentPeriodLabel}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon"><BadgePlus size={20} /></div>
                    <div className="stat-value" style={{ color: 'var(--purple-400)' }}>{stats.new_cve_alerts || 0}</div>
                    <div className="stat-label">New CVE Alerts</div>
                    <div className="text-xs text-muted" style={{ marginTop: 2 }}>{currentPeriodLabel}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon"><Calendar size={20} /></div>
                    <div className="stat-value">{stats.sent_in_period || 0}</div>
                    <div className="stat-label">Sent ({currentPeriodLabel})</div>
                </div>
            </div>

            {/* Filter Bar */}
            <div style={filterStyle}>
                <select className="form-select" value={status} onChange={e => setStatus(e.target.value)} style={{ width: 150, padding: '6px 10px', fontSize: 13 }}>
                    {STATUS_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
                <select className="form-select" value={isNew} onChange={e => setIsNew(e.target.value)} style={{ width: 160, padding: '6px 10px', fontSize: 13 }}>
                    {ISNEW_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
                <form onSubmit={handlePqlSearch} style={{ display: 'flex', gap: 6, flex: 1, minWidth: 220 }}>
                    <input
                        className="form-input"
                        style={{ flex: 1, padding: '6px 12px', fontSize: 13 }}
                        placeholder="Search CVE ID or rule name..."
                        value={pqlInput}
                        onChange={e => { setPqlInput(e.target.value); if (!e.target.value) setPql(''); }}
                    />
                    <button type="submit" className="btn btn-secondary" style={{ padding: '6px 14px', fontSize: 13 }}>
                        <Search size={14} />
                    </button>
                </form>
                {(status || isNew || pql) && (
                    <button className="btn btn-secondary" style={{ fontSize: 12, padding: '5px 12px' }}
                        onClick={() => { setStatus(''); setIsNew(''); setPql(''); setPqlInput(''); }}>
                        <X size={12} style={{ verticalAlign: 'middle', marginRight: 2 }} /> Reset Filters
                    </button>
                )}
            </div>

            {/* Table */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">
                        Alert History ({total.toLocaleString()})
                        {(status || isNew || pql) && (
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
                                    <th style={{ width: 90 }}>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {alerts.map(a => (
                                    <React.Fragment key={a.id}>
                                        <tr style={{ cursor: 'pointer' }}
                                            className={expandedCve === a.cve_id ? 'row-expanded' : ''}>
                                            <td className="text-mono" style={{ color: 'var(--purple-400)' }}
                                                onClick={() => handleCveClick(a.cve_id)}>
                                                {a.cve_id}
                                            </td>
                                            <td>
                                                <span style={{
                                                    fontSize: 11, padding: '2px 8px', borderRadius: 4, fontWeight: 600,
                                                    background: `${STATUS_COLORS[a.status] || 'var(--text-muted)'}20`,
                                                    color: STATUS_COLORS[a.status] || 'var(--text-muted)',
                                                }}>
                                                    {a.status === 'sent' ? <><CheckCircle2 size={12} style={{ verticalAlign: 'middle', marginRight: 3 }} /> sent</> :
                                                        a.status === 'failed' ? <><XCircle size={12} style={{ verticalAlign: 'middle', marginRight: 3 }} /> failed</> :
                                                            a.status === 'stored' ? <><Package size={12} style={{ verticalAlign: 'middle', marginRight: 3 }} /> stored</> : a.status}
                                                </span>
                                            </td>
                                            <td>
                                                {a.is_new_cve === true ? (
                                                    <span style={{ fontSize: 11, color: 'var(--purple-400)', fontWeight: 600 }}><BadgePlus size={12} style={{ verticalAlign: 'middle', marginRight: 3 }} /> new</span>
                                                ) : a.is_new_cve === false ? (
                                                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}><RefreshCw size={12} style={{ verticalAlign: 'middle', marginRight: 3 }} /> dup</span>
                                                ) : (
                                                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span>
                                                )}
                                            </td>
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
                                            <td>
                                                {(a.filter_rule_id || a.rule_name) && (
                                                    <button
                                                        className="btn btn-secondary"
                                                        style={{ padding: '2px 8px', fontSize: 11 }}
                                                        onClick={(e) => { e.stopPropagation(); handleOpenRefine(a); }}
                                                        title="Refine this rule to reduce false positives"
                                                    >
                                                        Refine
                                                    </button>
                                                )}
                                            </td>
                                        </tr>
                                        {expandedCve === a.cve_id && (
                                            <tr>
                                                <td colSpan="8" style={{ padding: 0, border: 'none' }}>
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
                                                                    {cveDetail.kev_flag && <span style={{ marginLeft: 8, color: 'var(--error)' }}><AlertTriangle size={12} style={{ verticalAlign: 'middle', marginRight: 2 }} /> KEV</span>}
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
                                    <tr><td colSpan="8" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>
                                        {(status || isNew || pql) ? 'No alerts match the current filters.' : `No alerts for ${currentPeriodLabel.toLowerCase()}.`}
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

            {/* Refine Filter Modal */}
            {refineAlert && (
                <RefineModal
                    ruleId={refineAlert.filter_rule_id}
                    ruleName={refineAlert.rule_name}
                    cveId={refineAlert.cve_id}
                    cveDetail={refineCveDetail}
                    onClose={() => { setRefineAlert(null); setRefineCveDetail(null); }}
                    onSuccess={() => fetchAlerts(true)}
                />
            )}
        </div>
    );
}
