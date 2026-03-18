import React, { useState, useEffect, useRef, useCallback } from 'react';
import { getAlerts, getAlertStats, getCVE, exportAlertsExcel, getFilter, refineFilterRule } from '../api';

const STATUS_COLORS = {
    sent: 'var(--success)',
    failed: 'var(--error)',
    stored: 'var(--text-muted)',
    unknown: 'var(--text-muted)',
};

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

const QUICK_PERIODS = [
    { value: '1d', label: 'Today' },
    { value: '7d', label: 'Last 7d' },
    { value: '30d', label: 'Last 30d' },
    { value: '90d', label: 'Last 90d' },
];

const UNIT_OPTIONS = [
    { value: 'd', label: 'Days' },
    { value: 'w', label: 'Weeks' },
    { value: 'm', label: 'Months' },
    { value: 'y', label: 'Years' },
];

function periodLabel(period) {
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

// ── Refine Filter Modal ─────────────────────────────────
function RefineModal({ alert, cveDetail, onClose, onSuccess }) {
    const [ruleData, setRuleData] = useState(null);
    const [loadingRule, setLoadingRule] = useState(true);
    const [keyword, setKeyword] = useState('');
    const [productVal, setProductVal] = useState('');
    const [versionVal, setVersionVal] = useState('');
    const [cvssVal, setCvssVal] = useState('');
    const [useKeyword, setUseKeyword] = useState(false);
    const [useProduct, setUseProduct] = useState(false);
    const [useVersion, setUseVersion] = useState(false);
    const [useCvss, setUseCvss] = useState(false);
    const [preview, setPreview] = useState(null);
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);

    // Pre-fill product from CVE detail
    useEffect(() => {
        if (cveDetail?.product) setProductVal(cveDetail.product);
    }, [cveDetail]);

    // Load the rule that triggered this alert
    useEffect(() => {
        if (!alert?.filter_rule_id) {
            setLoadingRule(false);
            return;
        }
        (async () => {
            try {
                const r = await getFilter(alert.filter_rule_id);
                setRuleData(r);
            } catch (e) {
                setError(`Could not load rule: ${e.message}`);
            } finally {
                setLoadingRule(false);
            }
        })();
    }, [alert]);

    const buildNegations = () => {
        const negs = [];
        if (useKeyword && keyword.trim()) negs.push({ type: 'keyword', value: keyword.trim() });
        if (useProduct && productVal.trim()) negs.push({ type: 'product', value: productVal.trim() });
        if (useVersion && versionVal.trim()) negs.push({ type: 'version', value: versionVal.trim() });
        if (useCvss && cvssVal.trim()) negs.push({ type: 'cvss', value: cvssVal.trim() });
        return negs;
    };

    const handlePreview = async () => {
        const negations = buildNegations();
        if (!negations.length) { setError('Select at least one negation criterion.'); return; }
        setError(null);
        setSubmitting(true);
        try {
            const res = await refineFilterRule({
                rule_id: alert.filter_rule_id,
                negations,
                preview_only: true,
            });
            setPreview(res);
        } catch (e) {
            setError(e.message);
        } finally {
            setSubmitting(false);
        }
    };

    const handleApply = async () => {
        const negations = buildNegations();
        if (!negations.length) { setError('Select at least one negation criterion.'); return; }
        setError(null);
        setSubmitting(true);
        try {
            await refineFilterRule({
                rule_id: alert.filter_rule_id,
                negations,
                preview_only: false,
            });
            setSuccess(true);
            setTimeout(() => { onSuccess?.(); onClose(); }, 1500);
        } catch (e) {
            setError(e.message);
        } finally {
            setSubmitting(false);
        }
    };

    const overlayStyle = {
        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
        background: 'rgba(0,0,0,0.6)', zIndex: 1000,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
    };
    const modalStyle = {
        background: 'var(--card-bg)', border: '1px solid var(--border)',
        borderRadius: 12, padding: 24, width: '90%', maxWidth: 680,
        maxHeight: '85vh', overflowY: 'auto', boxShadow: '0 16px 48px rgba(0,0,0,0.5)',
    };
    const sectionStyle = {
        padding: '10px 14px', marginBottom: 10, borderRadius: 8,
        background: 'rgba(124,58,237,0.06)', border: '1px solid rgba(124,58,237,0.15)',
    };
    const checkRow = {
        display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8,
    };
    const inputStyle = {
        flex: 1, padding: '6px 10px', fontSize: 13,
        background: 'var(--card-bg)', border: '1px solid var(--border)',
        color: 'var(--text-primary)', borderRadius: 6,
    };

    return (
        <div style={overlayStyle} onClick={onClose}>
            <div style={modalStyle} onClick={e => e.stopPropagation()}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                    <h2 style={{ margin: 0, fontSize: 18 }}>Refine Filter — Reduce False Positives</h2>
                    <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 20, cursor: 'pointer' }}>✕</button>
                </div>

                {/* Target info */}
                <div style={sectionStyle}>
                    <div className="text-sm"><strong>Alert CVE:</strong> {alert.cve_id}</div>
                    <div className="text-sm"><strong>Triggered by Rule:</strong> {alert.rule_name || '—'} (ID: {alert.filter_rule_id || '—'})</div>
                    {cveDetail && (
                        <div className="text-xs text-muted" style={{ marginTop: 4 }}>
                            {(cveDetail.description || '').slice(0, 200)}{(cveDetail.description || '').length > 200 ? '...' : ''}
                        </div>
                    )}
                </div>

                {loadingRule ? (
                    <div className="loading" style={{ padding: 20 }}><div className="loading-spinner" />Loading rule...</div>
                ) : !alert.filter_rule_id ? (
                    <div className="text-sm text-muted" style={{ padding: 20, textAlign: 'center' }}>
                        This alert has no associated rule ID. Cannot refine.
                    </div>
                ) : (
                    <>
                        {/* Current PQL */}
                        {ruleData && (
                            <div style={{ ...sectionStyle, fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>
                                <div className="text-xs text-muted" style={{ marginBottom: 4 }}>Current PQL:</div>
                                {ruleData.pql || '(none)'}
                            </div>
                        )}

                        {/* Negation options */}
                        <div style={{ marginBottom: 16 }}>
                            <div className="text-sm" style={{ fontWeight: 600, marginBottom: 8 }}>Negation Criteria:</div>

                            <div style={checkRow}>
                                <input type="checkbox" checked={useKeyword} onChange={e => setUseKeyword(e.target.checked)} id="neg-kw" />
                                <label htmlFor="neg-kw" className="text-sm" style={{ whiteSpace: 'nowrap' }}>Exclude keyword in description:</label>
                                <input style={inputStyle} placeholder="e.g. print spooler, legacy version"
                                    value={keyword} onChange={e => setKeyword(e.target.value)} disabled={!useKeyword} />
                            </div>

                            <div style={checkRow}>
                                <input type="checkbox" checked={useProduct} onChange={e => setUseProduct(e.target.checked)} id="neg-prod" />
                                <label htmlFor="neg-prod" className="text-sm" style={{ whiteSpace: 'nowrap' }}>Exclude product:</label>
                                <input style={inputStyle} placeholder="e.g. FortiSwitch"
                                    value={productVal} onChange={e => setProductVal(e.target.value)} disabled={!useProduct} />
                            </div>

                            <div style={checkRow}>
                                <input type="checkbox" checked={useVersion} onChange={e => setUseVersion(e.target.checked)} id="neg-ver" />
                                <label htmlFor="neg-ver" className="text-sm" style={{ whiteSpace: 'nowrap' }}>Exclude version string:</label>
                                <input style={inputStyle} placeholder="e.g. 6.4.0, before 7.2"
                                    value={versionVal} onChange={e => setVersionVal(e.target.value)} disabled={!useVersion} />
                            </div>

                            <div style={checkRow}>
                                <input type="checkbox" checked={useCvss} onChange={e => setUseCvss(e.target.checked)} id="neg-cvss" />
                                <label htmlFor="neg-cvss" className="text-sm" style={{ whiteSpace: 'nowrap' }}>Only alert if CVSS &ge;:</label>
                                <input style={{ ...inputStyle, maxWidth: 80 }} type="number" step="0.1" min="0" max="10"
                                    placeholder="7.0" value={cvssVal} onChange={e => setCvssVal(e.target.value)} disabled={!useCvss} />
                            </div>
                        </div>

                        {/* Preview */}
                        {preview && (
                            <div style={{ marginBottom: 16 }}>
                                <div className="text-sm" style={{ fontWeight: 600, marginBottom: 6 }}>Before vs. After:</div>
                                <div style={{ ...sectionStyle, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
                                    <div className="text-xs text-muted" style={{ marginBottom: 2 }}>BEFORE:</div>
                                    <code style={{ fontSize: 11, wordBreak: 'break-all' }}>{preview.original_pql}</code>
                                </div>
                                <div style={{ ...sectionStyle, background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)' }}>
                                    <div className="text-xs text-muted" style={{ marginBottom: 2 }}>AFTER:</div>
                                    <code style={{ fontSize: 11, wordBreak: 'break-all' }}>{preview.refined_pql}</code>
                                </div>
                            </div>
                        )}

                        {/* Error / Success */}
                        {error && (
                            <div style={{ padding: '8px 12px', marginBottom: 12, borderRadius: 6, background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: 'var(--error)', fontSize: 13 }}>
                                {error}
                            </div>
                        )}
                        {success && (
                            <div style={{ padding: '8px 12px', marginBottom: 12, borderRadius: 6, background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', color: 'var(--success)', fontSize: 13 }}>
                                Rule refined successfully! Reloading...
                            </div>
                        )}

                        {/* Actions */}
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                            <button className="btn btn-secondary" onClick={onClose} disabled={submitting}>Cancel</button>
                            <button className="btn btn-secondary" onClick={handlePreview} disabled={submitting || success}>
                                {submitting && !preview ? 'Loading...' : 'Preview'}
                            </button>
                            <button className="btn btn-primary" onClick={handleApply}
                                disabled={submitting || success || !buildNegations().length}>
                                {submitting ? 'Applying...' : 'Apply Refinement'}
                            </button>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
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
    const [customNum, setCustomNum] = useState('');
    const [customUnit, setCustomUnit] = useState('d');
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
                getAlertStats(period),
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
    }, [buildParams, page, period]);

    // Initial load + filter changes
    useEffect(() => { setPage(1); }, [period, status, isNew, pql]);
    useEffect(() => { fetchAlerts(); }, [page, period, status, isNew, pql]);

    // Auto-refresh every 30s
    useEffect(() => {
        pollRef.current = setInterval(async () => {
            try {
                const s = await getAlertStats(period);
                if (s.total !== prevTotalRef.current) {
                    fetchAlerts(true);
                }
            } catch { /* silent */ }
        }, 30_000);
        return () => clearInterval(pollRef.current);
    }, [fetchAlerts, period]);

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

    const handleCustomPeriod = () => {
        const n = parseInt(customNum);
        if (n > 0 && customUnit) {
            setPeriod(`${n}${customUnit}`);
        }
    };

    const handleExport = async (mode) => {
        setExporting(true);
        setShowExportMenu(false);
        try {
            const p = { mode };
            if (mode === 'filtered') {
                if (period) p.period = period;
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
        // Load CVE detail for pre-filling the modal
        try {
            const d = await getCVE(a.cve_id);
            setRefineCveDetail(d);
        } catch {
            setRefineCveDetail(null);
        }
    };

    const totalPages = Math.ceil(total / 30);
    const currentPeriodLabel = periodLabel(period);

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
                <div style={{ display: 'flex', gap: 8 }}>
                    <div style={{ position: 'relative' }}>
                        <button className="btn btn-secondary" onClick={() => setShowExportMenu(!showExportMenu)} disabled={exporting}>
                            {exporting ? '...Exporting' : '📥 Export Excel'}
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
                                    📋 Export Filtered
                                </button>
                                <button style={{
                                    display: 'block', width: '100%', textAlign: 'left', padding: '8px 12px',
                                    background: 'none', border: 'none', color: 'var(--text-primary)',
                                    cursor: 'pointer', borderRadius: 6, fontSize: 13,
                                }} onMouseOver={e => e.target.style.background = 'rgba(124,58,237,0.1)'}
                                   onMouseOut={e => e.target.style.background = 'none'}
                                   onClick={() => handleExport('all')}>
                                    📦 Export All
                                </button>
                            </div>
                        )}
                    </div>
                    <button className="btn btn-secondary" onClick={() => fetchAlerts(true)} disabled={refreshing}>
                        {refreshing ? '↻ Refreshing...' : '↻ Refresh'}
                    </button>
                </div>
            </div>

            {/* Time Filter — Wazuh-style */}
            <div style={{
                display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center',
                marginBottom: 16, padding: '10px 16px',
                background: 'rgba(124,58,237,0.04)', border: '1px solid rgba(124,58,237,0.15)',
                borderRadius: 10,
            }}>
                <span className="text-sm text-muted" style={{ marginRight: 4 }}>Time Range:</span>
                {/* Quick presets */}
                {QUICK_PERIODS.map(qp => (
                    <button key={qp.value}
                        className={period === qp.value ? 'btn btn-primary' : 'btn btn-secondary'}
                        style={{ padding: '4px 12px', fontSize: 12 }}
                        onClick={() => { setPeriod(qp.value); setCustomNum(''); }}>
                        {qp.label}
                    </button>
                ))}
                <span className="text-sm text-muted" style={{ margin: '0 4px' }}>|</span>
                {/* Custom: number + unit */}
                <input
                    type="number" min="1" max="999" placeholder="#"
                    value={customNum}
                    onChange={e => setCustomNum(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') handleCustomPeriod(); }}
                    style={{
                        width: 50, padding: '4px 8px', fontSize: 13, textAlign: 'center',
                        background: 'var(--card-bg)', border: '1px solid var(--border)',
                        color: 'var(--text-primary)', borderRadius: 6,
                    }}
                />
                <select value={customUnit} onChange={e => setCustomUnit(e.target.value)} style={selectStyle}>
                    {UNIT_OPTIONS.map(u => (
                        <option key={u.value} value={u.value}>{u.label}</option>
                    ))}
                </select>
                <button className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: 12 }}
                    onClick={handleCustomPeriod} disabled={!customNum}>
                    Apply
                </button>
                {period && (
                    <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 11 }}
                        onClick={() => { setPeriod(''); setCustomNum(''); }}>
                        ✕ All Time
                    </button>
                )}
                <span className="text-xs text-muted" style={{ marginLeft: 'auto' }}>
                    Showing: {currentPeriodLabel}
                </span>
            </div>

            {/* Stats — 5 cards (period-scoped) */}
            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginBottom: 24 }}>
                <div className="stat-card">
                    <div className="stat-icon">📨</div>
                    <div className="stat-value">{stats.total || 0}</div>
                    <div className="stat-label">Total Alerts</div>
                    <div className="text-xs text-muted" style={{ marginTop: 2 }}>{currentPeriodLabel}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">✅</div>
                    <div className="stat-value" style={{ color: 'var(--success)' }}>{stats.sent || 0}</div>
                    <div className="stat-label">Sent</div>
                    <div className="text-xs text-muted" style={{ marginTop: 2 }}>{currentPeriodLabel}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">❌</div>
                    <div className="stat-value" style={{ color: 'var(--error)' }}>{stats.failed || 0}</div>
                    <div className="stat-label">Failed</div>
                    <div className="text-xs text-muted" style={{ marginTop: 2 }}>{currentPeriodLabel}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">🆕</div>
                    <div className="stat-value" style={{ color: 'var(--purple-400)' }}>{stats.new_cve_alerts || 0}</div>
                    <div className="stat-label">New CVE Alerts</div>
                    <div className="text-xs text-muted" style={{ marginTop: 2 }}>{currentPeriodLabel}</div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon">📅</div>
                    <div className="stat-value">{stats.sent_in_period || 0}</div>
                    <div className="stat-label">Sent ({currentPeriodLabel})</div>
                </div>
            </div>

            {/* Filter Bar */}
            <div style={filterStyle}>
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
                        placeholder="Search CVE ID or rule name..."
                        value={pqlInput}
                        onChange={e => { setPqlInput(e.target.value); if (!e.target.value) setPql(''); }}
                    />
                    <button type="submit" className="btn btn-secondary" style={{ padding: '6px 14px', fontSize: 13 }}>
                        🔍
                    </button>
                </form>

                {/* Reset */}
                {(status || isNew || pql) && (
                    <button className="btn btn-secondary" style={{ fontSize: 12, padding: '5px 12px' }}
                        onClick={() => { setStatus(''); setIsNew(''); setPql(''); setPqlInput(''); }}>
                        ✕ Reset Filters
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
                                                    {a.status === 'sent' ? '✅ sent' :
                                                        a.status === 'failed' ? '❌ failed' :
                                                            a.status === 'stored' ? '📦 stored' : a.status}
                                                </span>
                                            </td>
                                            <td>
                                                {a.is_new_cve === true ? (
                                                    <span style={{ fontSize: 11, color: 'var(--purple-400)', fontWeight: 600 }}>🆕 new</span>
                                                ) : a.is_new_cve === false ? (
                                                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>🔄 dup</span>
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
                                                {a.filter_rule_id && (
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
                    alert={refineAlert}
                    cveDetail={refineCveDetail}
                    onClose={() => { setRefineAlert(null); setRefineCveDetail(null); }}
                    onSuccess={() => fetchAlerts(true)}
                />
            )}
        </div>
    );
}
