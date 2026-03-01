import React, { useState, useEffect, useCallback } from 'react';
import { getLogs, getWorkerTypes, clearLogs, getRedisInfo } from '../api';

const LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR'];
const LEVEL_COLORS = {
    DEBUG: 'var(--text-muted)',
    INFO: 'var(--info)',
    WARNING: 'var(--warning)',
    ERROR: 'var(--error)',
};

export default function Logs() {
    const [activeTab, setActiveTab] = useState('logs'); // 'logs' | 'redis'
    const [logs, setLogs] = useState([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [loading, setLoading] = useState(true);
    const [workerTypes, setWorkerTypes] = useState([]);
    const [filters, setFilters] = useState({ worker_type: '', level: '', search: '' });
    const [autoRefresh, setAutoRefresh] = useState(false);

    // Redis state
    const [redisInfo, setRedisInfo] = useState(null);
    const [redisLoading, setRedisLoading] = useState(false);
    const [redisError, setRedisError] = useState(null);

    const fetchLogs = useCallback(async () => {
        try {
            const data = await getLogs({ ...filters, page, per_page: 50 });
            setLogs(data.items || []);
            setTotal(data.total || 0);
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    }, [filters, page]);

    const fetchTypes = async () => {
        try {
            const data = await getWorkerTypes();
            setWorkerTypes(data || []);
        } catch (e) { console.error(e); }
    };

    const fetchRedis = async () => {
        setRedisLoading(true);
        setRedisError(null);
        try {
            const data = await getRedisInfo();
            setRedisInfo(data);
        } catch (e) {
            setRedisError(e.message);
        } finally {
            setRedisLoading(false);
        }
    };

    useEffect(() => { fetchLogs(); fetchTypes(); }, [fetchLogs]);

    useEffect(() => {
        if (!autoRefresh) return;
        const interval = setInterval(fetchLogs, 5000);
        return () => clearInterval(interval);
    }, [autoRefresh, fetchLogs]);

    useEffect(() => {
        if (activeTab === 'redis') fetchRedis();
    }, [activeTab]);

    const handleClear = async (type) => {
        if (!confirm(`Clear ${type || 'all'} logs?`)) return;
        try {
            await clearLogs(type);
            fetchLogs();
            fetchTypes();
        } catch (e) { alert(e.message); }
    };

    const pages = Math.ceil(total / 50);

    return (
        <div className="main-content animate-in">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <div>
                    <h1 className="header-title">📜 Logs & Diagnostics</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Monitor worker activity and inspect the Redis pipeline pool</p>
                </div>
                {activeTab === 'logs' && (
                    <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                        <label className="toggle" title="Auto-refresh every 5s">
                            <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} />
                            <span className="toggle-slider" />
                        </label>
                        <span className="text-xs text-muted">Auto-refresh</span>
                        <button className="btn btn-danger btn-sm" onClick={() => handleClear(filters.worker_type)}>
                            🗑️ Clear {filters.worker_type || 'All'}
                        </button>
                    </div>
                )}
                {activeTab === 'redis' && (
                    <button className="btn btn-secondary btn-sm" onClick={fetchRedis} disabled={redisLoading}>
                        🔄 {redisLoading ? 'Refreshing…' : 'Refresh'}
                    </button>
                )}
            </div>

            {/* Tab switcher */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
                <button className={`btn btn-sm ${activeTab === 'logs' ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => setActiveTab('logs')}>📄 Worker Logs</button>
                <button className={`btn btn-sm ${activeTab === 'redis' ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => setActiveTab('redis')}>🔴 Redis Pool</button>
            </div>

            {/* ═══ LOGS TAB ═══ */}
            {activeTab === 'logs' && (
                <>
                    {/* Worker type chips */}
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 20 }}>
                        <button
                            className={`btn btn-sm ${!filters.worker_type ? 'btn-primary' : 'btn-secondary'}`}
                            onClick={() => { setFilters(f => ({ ...f, worker_type: '' })); setPage(1); }}
                        >All ({total})</button>
                        {workerTypes.map(wt => (
                            <button key={wt.type}
                                className={`btn btn-sm ${filters.worker_type === wt.type ? 'btn-primary' : 'btn-secondary'}`}
                                onClick={() => { setFilters(f => ({ ...f, worker_type: wt.type })); setPage(1); }}>
                                {wt.type} ({wt.count})
                            </button>
                        ))}
                    </div>

                    {/* Level + search filters */}
                    <div className="card mb-20" style={{ padding: '12px 20px' }}>
                        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                            <select className="form-select" style={{ width: 150 }}
                                value={filters.level}
                                onChange={e => { setFilters(f => ({ ...f, level: e.target.value })); setPage(1); }}>
                                <option value="">All Levels</option>
                                {LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
                            </select>
                            <input className="form-input" style={{ flex: 1, maxWidth: 400 }}
                                placeholder="Search logs..." value={filters.search}
                                onChange={e => setFilters(f => ({ ...f, search: e.target.value }))}
                                onKeyDown={e => e.key === 'Enter' && fetchLogs()} />
                            <button className="btn btn-secondary btn-sm" onClick={fetchLogs}>🔍 Search</button>
                        </div>
                    </div>

                    {loading ? <div className="loading"><div className="loading-spinner" /> Loading...</div> : (
                        <div className="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th style={{ width: 160 }}>Timestamp</th>
                                        <th style={{ width: 100 }}>Worker</th>
                                        <th style={{ width: 80 }}>Level</th>
                                        <th>Message</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {logs.length === 0 ? (
                                        <tr><td colSpan={4} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No logs found</td></tr>
                                    ) : logs.map(log => (
                                        <tr key={log.id}>
                                            <td className="text-xs" style={{ fontFamily: 'monospace' }}>
                                                {new Date(log.timestamp).toLocaleString()}
                                            </td>
                                            <td><span className="badge badge-info">{log.worker_type}</span></td>
                                            <td>
                                                <span style={{ color: LEVEL_COLORS[log.level] || 'var(--text-primary)', fontWeight: 600, fontSize: 12 }}>
                                                    {log.level}
                                                </span>
                                            </td>
                                            <td>
                                                <div className="text-sm">{log.message}</div>
                                                {log.details && (
                                                    <details style={{ marginTop: 4 }}>
                                                        <summary className="text-xs text-muted" style={{ cursor: 'pointer' }}>Details</summary>
                                                        <pre style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'pre-wrap', marginTop: 4, maxHeight: 200, overflow: 'auto' }}>
                                                            {log.details}
                                                        </pre>
                                                    </details>
                                                )}
                                                {log.task_id && (
                                                    <span className="text-xs text-muted" style={{ marginLeft: 8 }}>Task: {log.task_id}</span>
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {pages > 1 && (
                        <div className="pagination">
                            <button className="pagination-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
                            <span className="text-sm text-muted">Page {page} of {pages} ({total} logs)</span>
                            <button className="pagination-btn" disabled={page >= pages} onClick={() => setPage(p => p + 1)}>Next →</button>
                        </div>
                    )}
                </>
            )}

            {/* ═══ REDIS TAB ═══ */}
            {activeTab === 'redis' && (
                <div>
                    {redisLoading && <div className="loading"><div className="loading-spinner" /> Inspecting Redis...</div>}
                    {redisError && <div className="card" style={{ padding: 20, borderColor: 'var(--error)' }}>
                        <span style={{ color: 'var(--error)' }}>❌ Redis error: {redisError}</span>
                    </div>}
                    {redisInfo && (
                        <>
                            {/* Stats grid */}
                            <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 24 }}>
                                <div className="stat-card">
                                    <div className="stat-icon">🔴</div>
                                    <div className="stat-value" style={{ color: redisInfo.status === 'ok' ? 'var(--success)' : 'var(--error)' }}>
                                        {redisInfo.status === 'ok' ? 'Online' : 'Error'}
                                    </div>
                                    <div className="stat-label">Redis Status</div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-icon">🗝️</div>
                                    <div className="stat-value">{(redisInfo.total_keys || 0).toLocaleString()}</div>
                                    <div className="stat-label">Total Keys</div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-icon">🛡️</div>
                                    <div className="stat-value" style={{ color: redisInfo.cve_keys_found > 0 ? 'var(--success)' : 'var(--text-muted)' }}>
                                        {redisInfo.cve_keys_found || 0}
                                    </div>
                                    <div className="stat-label">CVE Keys</div>
                                </div>
                                <div className="stat-card">
                                    <div className="stat-icon">💾</div>
                                    <div className="stat-value">{redisInfo.used_memory || '?'}</div>
                                    <div className="stat-label">Memory Used</div>
                                </div>
                            </div>

                            {/* Celery queues */}
                            {Object.keys(redisInfo.celery_queues || {}).length > 0 && (
                                <div className="card mb-20">
                                    <div className="card-header"><div className="card-title">⚙️ Celery Queues</div></div>
                                    <div style={{ padding: '12px 20px', display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                                        {Object.entries(redisInfo.celery_queues).map(([q, len]) => (
                                            <div key={q} style={{ padding: '8px 16px', background: 'var(--bg-secondary)', borderRadius: 8 }}>
                                                <span className="text-sm" style={{ fontWeight: 600 }}>{q}</span>
                                                <span className="badge badge-warning" style={{ marginLeft: 8 }}>{len} pending</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Key categories */}
                            {Object.keys(redisInfo.key_categories || {}).length > 0 && (
                                <div className="card mb-20">
                                    <div className="card-header"><div className="card-title">📊 Key Distribution</div></div>
                                    <div className="table-container">
                                        <table>
                                            <thead><tr><th>Key Prefix</th><th>Count</th></tr></thead>
                                            <tbody>
                                                {Object.entries(redisInfo.key_categories).map(([prefix, count]) => (
                                                    <tr key={prefix}>
                                                        <td className="text-mono text-sm">{prefix}</td>
                                                        <td>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                                                                <span className="text-sm">{count.toLocaleString()}</span>
                                                                <div style={{ flex: 1, height: 6, background: 'var(--bg-secondary)', borderRadius: 3, maxWidth: 200 }}>
                                                                    <div style={{
                                                                        height: '100%', borderRadius: 3, background: 'var(--purple-400)',
                                                                        width: `${Math.min(100, (count / redisInfo.total_keys) * 100)}%`,
                                                                    }} />
                                                                </div>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            )}

                            {/* CVE samples */}
                            {(redisInfo.cve_samples || []).length > 0 && (
                                <div className="card">
                                    <div className="card-header"><div className="card-title">🛡️ Sampled CVE Entries in Redis</div></div>
                                    <div className="table-container">
                                        <table>
                                            <thead><tr><th>Key</th><th>CVE ID</th><th>Severity</th><th>Source</th></tr></thead>
                                            <tbody>
                                                {redisInfo.cve_samples.map((s, i) => (
                                                    <tr key={i}>
                                                        <td className="text-mono text-xs">{s.key}</td>
                                                        <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{s.cve_id || s.key}</td>
                                                        <td><span className={`badge badge-${(s.severity || 'unknown').toLowerCase()}`}>{s.severity || 'N/A'}</span></td>
                                                        <td className="text-sm">{s.source || '—'}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            )}

                            {redisInfo.cve_keys_found === 0 && redisInfo.status === 'ok' && (
                                <div className="card" style={{ padding: 20, borderColor: 'var(--warning)' }}>
                                    <span style={{ color: 'var(--warning)' }}>⚠️ Redis is connected but has no <code>cve:*</code> keys. The pipeline hasn't cached any CVEs yet — this is normal before the first scheduled run.</span>
                                </div>
                            )}
                        </>
                    )}
                    {!redisInfo && !redisLoading && !redisError && (
                        <div className="card" style={{ padding: 40, textAlign: 'center' }}>
                            <button className="btn btn-primary" onClick={fetchRedis}>🔴 Inspect Redis Pool</button>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

const LEVEL_COLORS = {
    DEBUG: 'var(--text-muted)',
    INFO: 'var(--info)',
    WARNING: 'var(--warning)',
    ERROR: 'var(--error)',
};

export default function Logs() {
    const [logs, setLogs] = useState([]);
    const [total, setTotal] = useState(0);
    const [page, setPage] = useState(1);
    const [loading, setLoading] = useState(true);
    const [workerTypes, setWorkerTypes] = useState([]);
    const [filters, setFilters] = useState({ worker_type: '', level: '', search: '' });
    const [autoRefresh, setAutoRefresh] = useState(false);

    const fetchLogs = useCallback(async () => {
        try {
            const data = await getLogs({ ...filters, page, per_page: 50 });
            setLogs(data.items || []);
            setTotal(data.total || 0);
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    }, [filters, page]);

    const fetchTypes = async () => {
        try {
            const data = await getWorkerTypes();
            setWorkerTypes(data || []);
        } catch (e) { console.error(e); }
    };

    useEffect(() => { fetchLogs(); fetchTypes(); }, [fetchLogs]);

    useEffect(() => {
        if (!autoRefresh) return;
        const interval = setInterval(fetchLogs, 5000);
        return () => clearInterval(interval);
    }, [autoRefresh, fetchLogs]);

    const handleClear = async (type) => {
        if (!confirm(`Clear ${type || 'all'} logs?`)) return;
        try {
            await clearLogs(type);
            fetchLogs();
            fetchTypes();
        } catch (e) { alert(e.message); }
    };

    const pages = Math.ceil(total / 50);

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading logs...</div></div>;

    return (
        <div className="main-content animate-in">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <div>
                    <h1 className="header-title">📜 Worker Logs</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Monitor Celery worker activity and pipeline logs</p>
                </div>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    <label className="toggle" title="Auto-refresh every 5s">
                        <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} />
                        <span className="toggle-slider" />
                    </label>
                    <span className="text-xs text-muted">Auto-refresh</span>
                    <button className="btn btn-danger btn-sm" onClick={() => handleClear(filters.worker_type)}>
                        🗑️ Clear {filters.worker_type || 'All'}
                    </button>
                </div>
            </div>

            {/* Worker type chips */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 20 }}>
                <button
                    className={`btn btn-sm ${!filters.worker_type ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => { setFilters(f => ({ ...f, worker_type: '' })); setPage(1); }}
                >
                    All ({total})
                </button>
                {workerTypes.map(wt => (
                    <button
                        key={wt.type}
                        className={`btn btn-sm ${filters.worker_type === wt.type ? 'btn-primary' : 'btn-secondary'}`}
                        onClick={() => { setFilters(f => ({ ...f, worker_type: wt.type })); setPage(1); }}
                    >
                        {wt.type} ({wt.count})
                    </button>
                ))}
            </div>

            {/* Level + search filters */}
            <div className="card mb-20" style={{ padding: '12px 20px' }}>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                    <select
                        className="form-select" style={{ width: 150 }}
                        value={filters.level}
                        onChange={e => { setFilters(f => ({ ...f, level: e.target.value })); setPage(1); }}
                    >
                        <option value="">All Levels</option>
                        {LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
                    </select>
                    <input
                        className="form-input" style={{ flex: 1, maxWidth: 400 }}
                        placeholder="Search logs..." value={filters.search}
                        onChange={e => setFilters(f => ({ ...f, search: e.target.value }))}
                        onKeyDown={e => e.key === 'Enter' && fetchLogs()}
                    />
                    <button className="btn btn-secondary btn-sm" onClick={fetchLogs}>🔍 Search</button>
                </div>
            </div>

            {/* Logs table */}
            <div className="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style={{ width: 160 }}>Timestamp</th>
                            <th style={{ width: 100 }}>Worker</th>
                            <th style={{ width: 80 }}>Level</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        {logs.length === 0 ? (
                            <tr><td colSpan={4} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No logs found</td></tr>
                        ) : logs.map(log => (
                            <tr key={log.id}>
                                <td className="text-xs" style={{ fontFamily: 'monospace' }}>
                                    {new Date(log.timestamp).toLocaleString()}
                                </td>
                                <td>
                                    <span className="badge badge-info">{log.worker_type}</span>
                                </td>
                                <td>
                                    <span style={{ color: LEVEL_COLORS[log.level] || 'var(--text-primary)', fontWeight: 600, fontSize: 12 }}>
                                        {log.level}
                                    </span>
                                </td>
                                <td>
                                    <div className="text-sm">{log.message}</div>
                                    {log.details && (
                                        <details style={{ marginTop: 4 }}>
                                            <summary className="text-xs text-muted" style={{ cursor: 'pointer' }}>Details</summary>
                                            <pre style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'pre-wrap', marginTop: 4, maxHeight: 200, overflow: 'auto' }}>
                                                {log.details}
                                            </pre>
                                        </details>
                                    )}
                                    {log.task_id && (
                                        <span className="text-xs text-muted" style={{ marginLeft: 8 }}>Task: {log.task_id}</span>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Pagination */}
            {pages > 1 && (
                <div className="pagination">
                    <button className="pagination-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
                    <span className="text-sm text-muted">Page {page} of {pages} ({total} logs)</span>
                    <button className="pagination-btn" disabled={page >= pages} onClick={() => setPage(p => p + 1)}>Next →</button>
                </div>
            )}
        </div>
    );
}
