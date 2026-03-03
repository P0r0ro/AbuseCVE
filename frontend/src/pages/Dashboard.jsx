import React, { useState, useEffect, useRef, useCallback } from 'react';
import { getDashboardOverview, triggerScan, initializeDB, initializeDBLocal, getTaskStatus, uploadMitreData, getCVE } from '../api';

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

const TASK_STORAGE_KEY = 'abusecve_active_task';

function getStoredTask() {
    try {
        const raw = localStorage.getItem(TASK_STORAGE_KEY);
        if (raw) return JSON.parse(raw);
    } catch { }
    return null;
}

function storeTask(task) {
    if (task) {
        localStorage.setItem(TASK_STORAGE_KEY, JSON.stringify(task));
    } else {
        localStorage.removeItem(TASK_STORAGE_KEY);
    }
}

export default function Dashboard() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [scanStatus, setScanStatus] = useState('');
    const [initMode, setInitMode] = useState('api');
    const [mitreDir, setMitreDir] = useState('');
    const [mitreFile, setMitreFile] = useState(null);
    const [expandedCve, setExpandedCve] = useState(null);
    const [cveDetail, setCveDetail] = useState(null);
    const [loadingDetail, setLoadingDetail] = useState(false);

    // Persistent task tracking
    const [activeTask, setActiveTask] = useState(getStoredTask);
    const pollRef = useRef(null);

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

    // Auto-refresh dashboard every 60s so new alerts/CVEs appear without manual refresh
    useEffect(() => {
        const interval = setInterval(fetchData, 60_000);
        return () => clearInterval(interval);
    }, []);

    // Poll task status — persists across tab switches
    const pollTask = useCallback(async () => {
        const task = getStoredTask();
        if (!task) return;

        try {
            const result = await getTaskStatus(task.taskId);
            const newTask = {
                ...task,
                status: result.status,
                result: result.result,
                lastChecked: new Date().toISOString(),
            };

            if (['SUCCESS', 'FAILURE', 'REVOKED'].includes(result.status)) {
                // Task finished
                newTask.finished = true;
                newTask.finishedAt = new Date().toISOString();
                storeTask(null); // Clear from storage
                setActiveTask(newTask);

                // Refresh dashboard data
                fetchData();

                // Format result for display
                const formatResult = (r) => {
                    if (!r) return 'Unknown error';
                    if (typeof r === 'string') return r;
                    if (r.detail) return r.detail;
                    if (r.message) return r.message;
                    if (r.error) return r.error;
                    try { return JSON.stringify(r, null, 2); } catch { return String(r); }
                };

                if (result.status === 'SUCCESS') {
                    setScanStatus(`✅ ${task.label} completed successfully!`);
                } else {
                    setScanStatus(`❌ ${task.label} failed: ${formatResult(result.result)}`);
                }
            } else {
                storeTask(newTask);
                setActiveTask(newTask);
            }
        } catch (e) {
            console.error('Task poll error:', e);
        }
    }, []);

    // Start polling on mount and when activeTask changes
    useEffect(() => {
        if (pollRef.current) clearInterval(pollRef.current);

        const stored = getStoredTask();
        if (stored && !stored.finished) {
            // Poll every 5 seconds
            pollTask(); // Immediate check
            pollRef.current = setInterval(pollTask, 5000);
        }

        return () => {
            if (pollRef.current) clearInterval(pollRef.current);
        };
    }, [pollTask]);

    const startTask = (taskId, label) => {
        const task = {
            taskId,
            label,
            status: 'PENDING',
            startedAt: new Date().toISOString(),
            finished: false,
        };
        storeTask(task);
        setActiveTask(task);

        // Start polling
        if (pollRef.current) clearInterval(pollRef.current);
        pollRef.current = setInterval(pollTask, 5000);
    };

    const handleScan = async () => {
        setScanStatus('Triggering scan...');
        try {
            const result = await triggerScan();
            startTask(result.task_id, 'CVE Scan');
            setScanStatus('');
        } catch (e) {
            setScanStatus(`Error: ${e.message}`);
        }
    };

    const handleInitDB = async () => {
        setScanStatus('');
        try {
            if (initMode === 'upload' && mitreFile) {
                const result = await uploadMitreData(mitreFile);
                startTask(result.task_id, 'MITRE Upload');
            } else if (initMode === 'local' && mitreDir) {
                const result = await initializeDBLocal(mitreDir);
                startTask(result.task_id, 'Local DB Init');
            } else {
                const result = await initializeDB();
                startTask(result.task_id, 'DB Init (NVD + KEV + RedHat)');
            }
        } catch (e) {
            setScanStatus(`Error: ${e.message}`);
        }
    };

    const handleCveClick = async (cveId) => {
        if (expandedCve === cveId) {
            setExpandedCve(null);
            setCveDetail(null);
            return;
        }
        setExpandedCve(cveId);
        setLoadingDetail(true);
        try {
            const detail = await getCVE(cveId);
            setCveDetail(detail);
        } catch (e) {
            setCveDetail({ error: e.message });
        } finally {
            setLoadingDetail(false);
        }
    };

    const dismissTask = () => {
        storeTask(null);
        setActiveTask(null);
        if (pollRef.current) clearInterval(pollRef.current);
    };

    const getTaskProgress = () => {
        if (!activeTask) return null;
        const s = activeTask.status;
        if (s === 'SUCCESS') return 100;
        if (s === 'FAILURE' || s === 'REVOKED') return 100;
        if (s === 'STARTED' || s === 'PROGRESS') return 50;
        if (s === 'PENDING') return 10;
        return 30;
    };

    const getTaskColor = () => {
        if (!activeTask) return 'var(--purple-400)';
        if (activeTask.status === 'SUCCESS') return 'var(--success)';
        if (activeTask.status === 'FAILURE') return 'var(--error)';
        return 'var(--purple-400)';
    };

    const getElapsedTime = () => {
        if (!activeTask?.startedAt) return '';
        const start = new Date(activeTask.startedAt);
        const now = activeTask.finishedAt ? new Date(activeTask.finishedAt) : new Date();
        const diff = Math.floor((now - start) / 1000);
        const mins = Math.floor(diff / 60);
        const secs = diff % 60;
        if (mins > 60) {
            const hrs = Math.floor(mins / 60);
            return `${hrs}h ${mins % 60}m`;
        }
        return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading dashboard...</div></div>;

    const sev = data?.severity_distribution || {};
    const maxSev = Math.max(...Object.values(sev), 1);
    const sourceDist = data?.source_distribution || {};
    const taskProgress = getTaskProgress();

    return (
        <div className="main-content animate-in">
            <div className="header" style={{ marginBottom: 24, padding: 0, background: 'transparent', border: 'none', height: 'auto' }}>
                <div>
                    <h1 className="header-title">Dashboard</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Real-time CVE monitoring overview — 4 sources active</p>
                </div>
                <div className="header-actions">
                    <button className="btn btn-primary" onClick={handleScan}
                        disabled={activeTask && !activeTask.finished}>🔍 Trigger Scan</button>
                    <button className="btn btn-secondary" onClick={fetchData}>↻ Refresh</button>
                </div>
            </div>

            {scanStatus && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: scanStatus.includes('✅') ? 'var(--success)' : scanStatus.includes('❌') ? 'var(--error)' : 'var(--border-accent)' }}>
                    <span className="text-sm">{scanStatus}</span>
                    <button className="text-sm" style={{ marginLeft: 12, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}
                        onClick={() => setScanStatus('')}>✕</button>
                </div>
            )}

            {/* Active Task Progress Bar */}
            {activeTask && (
                <div className="card mb-20" style={{
                    padding: '16px 20px',
                    borderColor: getTaskColor(),
                    borderWidth: 1,
                    position: 'relative',
                    overflow: 'hidden',
                }}>
                    {/* Animated background progress */}
                    {!activeTask.finished && (
                        <div style={{
                            position: 'absolute', top: 0, left: 0, bottom: 0,
                            width: `${taskProgress}%`,
                            background: `linear-gradient(90deg, ${getTaskColor()}15, ${getTaskColor()}08)`,
                            transition: 'width 1s ease',
                        }} />
                    )}
                    <div style={{ position: 'relative', zIndex: 1 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                {!activeTask.finished && (
                                    <div className="loading-spinner" style={{ width: 16, height: 16, borderWidth: 2 }} />
                                )}
                                <span style={{ fontWeight: 600, color: getTaskColor() }}>
                                    {activeTask.finished
                                        ? (activeTask.status === 'SUCCESS' ? '✅' : '❌')
                                        : '⏳'} {activeTask.label}
                                </span>
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                                <span className="text-sm text-muted">⏱ {getElapsedTime()}</span>
                                <span className="text-sm" style={{ color: getTaskColor() }}>{activeTask.status}</span>
                                {activeTask.finished && (
                                    <button className="text-sm" style={{
                                        color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer'
                                    }} onClick={dismissTask}>✕</button>
                                )}
                            </div>
                        </div>
                        {/* Progress bar */}
                        <div style={{
                            height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.1)', overflow: 'hidden',
                        }}>
                            <div style={{
                                height: '100%', borderRadius: 2,
                                background: getTaskColor(),
                                width: `${taskProgress}%`,
                                transition: 'width 1s ease',
                                animation: !activeTask.finished ? 'pulse 2s ease-in-out infinite' : 'none',
                            }} />
                        </div>
                        {!activeTask.finished && (
                            <p className="text-xs text-muted" style={{ marginTop: 6 }}>
                                This task runs in the background — you can navigate away safely. Progress is saved.
                            </p>
                        )}
                        {activeTask.finished && activeTask.result && (
                            <pre className="text-xs text-muted" style={{
                                marginTop: 8, background: 'rgba(0,0,0,0.2)', padding: 8, borderRadius: 6,
                                overflow: 'auto', maxHeight: 100,
                            }}>
                                {typeof activeTask.result === 'string' ? activeTask.result : JSON.stringify(activeTask.result, null, 2)}
                            </pre>
                        )}
                    </div>
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
                        Pull CVEs from NVD, CISA KEV, and RedHat via API. Upload MITRE data separately.
                    </p>

                    <div className="form-group" style={{ marginBottom: 12 }}>
                        <div style={{ display: 'flex', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                                <input type="radio" name="initMode" checked={initMode === 'api'} onChange={() => setInitMode('api')} />
                                <span className="text-sm">API (NVD + KEV + RedHat)</span>
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                                <input type="radio" name="initMode" checked={initMode === 'upload'} onChange={() => setInitMode('upload')} />
                                <span className="text-sm">Upload MITRE ZIP</span>
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                                <input type="radio" name="initMode" checked={initMode === 'local'} onChange={() => setInitMode('local')} />
                                <span className="text-sm">Local Directory</span>
                            </label>
                        </div>

                        {initMode === 'upload' && (
                            <div className="form-group">
                                <label className="form-label">MITRE cvelistV5 ZIP File</label>
                                <input type="file" accept=".zip" className="form-input" style={{ padding: '8px 12px' }}
                                    onChange={e => setMitreFile(e.target.files[0])} />
                                <p className="text-xs text-muted" style={{ marginTop: 4 }}>
                                    1. Clone: git clone https://github.com/CVEProject/cvelistV5.git<br />
                                    2. ZIP the cves/ directory<br />
                                    3. Upload the ZIP here
                                </p>
                            </div>
                        )}

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

                    <button className="btn btn-primary" onClick={handleInitDB}
                        disabled={(activeTask && !activeTask.finished) || (initMode === 'upload' && !mitreFile)}>
                        {activeTask && !activeTask.finished ? '⏳ Task Running...' :
                            initMode === 'upload' ? '📤 Upload MITRE Data' :
                                initMode === 'local' ? '📂 Init from Local' :
                                    '🗄️ Initialize Database (API)'}
                    </button>
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
                                <React.Fragment key={cve.cve_id}>
                                    <tr style={{ cursor: 'pointer' }} onClick={() => handleCveClick(cve.cve_id)}
                                        className={expandedCve === cve.cve_id ? 'row-expanded' : ''}>
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
                                            }}>{cve.source || '—'}</span>
                                        </td>
                                        <td>{cve.kev_flag ? <span className="badge badge-kev">⚠ KEV</span> : '—'}</td>
                                        <td className="text-sm text-muted">{cve.first_seen ? new Date(cve.first_seen).toLocaleDateString() : '—'}</td>
                                    </tr>
                                    {expandedCve === cve.cve_id && (
                                        <tr>
                                            <td colSpan="8" style={{ padding: 0, border: 'none' }}>
                                                <div style={{ padding: '16px 24px', background: 'rgba(124,58,237,0.05)', borderLeft: '3px solid var(--purple-400)', animation: 'slideDown 0.2s ease' }}>
                                                    {loadingDetail ? (
                                                        <div className="loading"><div className="loading-spinner" style={{ width: 16, height: 16 }} /> Loading...</div>
                                                    ) : cveDetail?.error ? (
                                                        <div className="text-sm" style={{ color: 'var(--error)' }}>{cveDetail.error}</div>
                                                    ) : cveDetail ? (
                                                        <div>
                                                            <div className="text-sm" style={{ marginBottom: 8 }}><strong>Description:</strong> {cveDetail.description || 'No description'}</div>
                                                            {cveDetail.cvss_vector && <div className="text-xs text-muted" style={{ marginBottom: 4 }}>Vector: {cveDetail.cvss_vector}</div>}
                                                            {cveDetail.published_date && <div className="text-xs text-muted" style={{ marginBottom: 4 }}>Published: {new Date(cveDetail.published_date).toLocaleString()}</div>}
                                                            {cveDetail.references?.length > 0 && (
                                                                <div style={{ marginTop: 8 }}>
                                                                    <strong className="text-xs">References:</strong>
                                                                    <div style={{ marginTop: 4 }}>{cveDetail.references.slice(0, 5).map((ref, i) => (
                                                                        <a key={i} href={ref} target="_blank" rel="noopener" className="text-xs" style={{ display: 'block', color: 'var(--purple-400)', marginBottom: 2 }}>{ref}</a>
                                                                    ))}</div>
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
