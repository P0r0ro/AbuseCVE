import React, { useState, useEffect, useCallback } from 'react';
import { getLogs, getWorkerTypes, clearLogs } from '../api';

const LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR'];
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
