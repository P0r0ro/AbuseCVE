import React, { useState, useEffect } from 'react';
import { getFilters, testFilterRule, reloadFilterRules, getQueryHelp } from '../api';

export default function Filters() {
    const [rules, setRules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showHelp, setShowHelp] = useState(false);
    const [helpData, setHelpData] = useState(null);
    const [testingId, setTestingId] = useState(null);
    const [testResults, setTestResults] = useState({});
    const [expandedId, setExpandedId] = useState(null);
    const [reloadMsg, setReloadMsg] = useState('');
    const [adHocPql, setAdHocPql] = useState('');
    const [adHocResult, setAdHocResult] = useState(null);
    const [adHocTesting, setAdHocTesting] = useState(false);

    const fetchRules = async () => {
        try {
            const data = await getFilters();
            setRules(data);
        } catch (e) {
            console.error('Failed to load rules:', e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchRules(); }, []);

    const handleTest = async (ruleId) => {
        setTestingId(ruleId);
        try {
            const result = await testFilterRule({ rule_id: ruleId });
            setTestResults(prev => ({ ...prev, [ruleId]: result }));
        } catch (e) {
            setTestResults(prev => ({ ...prev, [ruleId]: { status: 'error', message: e.message } }));
        } finally {
            setTestingId(null);
        }
    };

    const handleReload = async () => {
        setReloadMsg('Reloading...');
        try {
            const result = await reloadFilterRules();
            setReloadMsg(result.message);
            fetchRules();
        } catch (e) {
            setReloadMsg('Reload failed: ' + e.message);
        }
        setTimeout(() => setReloadMsg(''), 5000);
    };

    const handleShowHelp = async () => {
        if (!helpData) {
            try {
                const data = await getQueryHelp();
                setHelpData(data);
            } catch (e) {
                console.error('Failed to load help:', e);
            }
        }
        setShowHelp(true);
    };

    const handleAdHocTest = async () => {
        if (!adHocPql.trim()) return;
        setAdHocTesting(true);
        setAdHocResult(null);
        try {
            const result = await testFilterRule({ pql: adHocPql });
            setAdHocResult(result);
        } catch (e) {
            setAdHocResult({ status: 'error', message: e.message });
        } finally {
            setAdHocTesting(false);
        }
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading rules...</div></div>;

    return (
        <div className="main-content animate-in">
            {/* Header */}
            <div className="header" style={{ marginBottom: 24, padding: 0, background: 'transparent', border: 'none', height: 'auto' }}>
                <div>
                    <h1 className="header-title">Filter Rules</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>
                        File-based rules loaded from <code>abusecve_filters.yaml</code> &mdash; edit on the server, then reload.
                    </p>
                </div>
                <div className="header-actions" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <button className="btn btn-primary" onClick={handleReload}>Reload Rules</button>
                    <button className="btn btn-secondary" onClick={handleShowHelp} title="PQL Syntax Reference"
                        style={{ padding: '8px 12px', fontSize: 14 }}>? PQL Help</button>
                </div>
            </div>

            {reloadMsg && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: 'var(--border-accent)' }}>
                    <span className="text-sm">{reloadMsg}</span>
                </div>
            )}

            {/* Ad-hoc PQL Tester */}
            <div className="card mb-24">
                <div className="card-header">
                    <div className="card-title">PQL Query Tester</div>
                </div>
                <div style={{ padding: '0 20px 20px' }}>
                    <div style={{ display: 'flex', gap: 8 }}>
                        <input
                            className="form-input"
                            style={{ fontFamily: 'monospace', fontSize: 13, flex: 1 }}
                            placeholder='vendor:fortinet AND cvss:>=7.0 AND severity:HIGH,CRITICAL'
                            value={adHocPql}
                            onChange={e => setAdHocPql(e.target.value)}
                            onKeyDown={e => { if (e.key === 'Enter') handleAdHocTest(); }}
                        />
                        <button className="btn btn-primary" onClick={handleAdHocTest} disabled={adHocTesting}
                            style={{ whiteSpace: 'nowrap' }}>
                            {adHocTesting ? 'Testing...' : 'Test PQL'}
                        </button>
                    </div>
                    {adHocResult && (
                        <div style={{ marginTop: 12 }}>
                            {adHocResult.status === 'error' ? (
                                <div style={{ color: 'var(--error)' }}>Error: {adHocResult.message}</div>
                            ) : (
                                <div>
                                    <div style={{ fontWeight: 600, color: adHocResult.matches > 0 ? 'var(--success)' : 'var(--warning)' }}>
                                        {adHocResult.matches > 0
                                            ? `${adHocResult.matches.toLocaleString()} matches`
                                            : 'No matches'}
                                        <span className="text-muted text-sm" style={{ marginLeft: 8 }}>
                                            ({adHocResult.total_tested.toLocaleString()} CVEs scanned in {adHocResult.elapsed_seconds}s)
                                        </span>
                                    </div>
                                    {adHocResult.matched_cves && adHocResult.matched_cves.length > 0 && (
                                        <div className="table-container" style={{ maxHeight: 200, overflow: 'auto', marginTop: 8 }}>
                                            <table>
                                                <thead><tr><th>CVE ID</th><th>Vendor</th><th>Severity</th><th>CVSS</th><th>KEV</th></tr></thead>
                                                <tbody>
                                                    {adHocResult.matched_cves.slice(0, 20).map(c => (
                                                        <tr key={c.cve_id}>
                                                            <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{c.cve_id}</td>
                                                            <td>{c.vendor || '\u2014'}</td>
                                                            <td><span className={`badge badge-${(c.severity || 'unknown').toLowerCase()}`}>{c.severity || 'N/A'}</span></td>
                                                            <td className="text-mono">{c.cvss_score ?? '\u2014'}</td>
                                                            <td>{c.kev_flag ? 'Yes' : '\u2014'}</td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>

            {/* Rules Table */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">Loaded Rules ({rules.length})</div>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th style={{ width: 70 }}>ID</th>
                                <th>Name</th>
                                <th>Status</th>
                                <th style={{ width: 100 }}>Modified Alert</th>
                                <th style={{ width: 120 }}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rules.map(r => (
                                <React.Fragment key={r.id}>
                                    <tr style={{ cursor: 'pointer' }} onClick={() => setExpandedId(expandedId === r.id ? null : r.id)}>
                                        <td className="text-mono" style={{ fontWeight: 700, color: 'var(--purple-400)' }}>{r.id}</td>
                                        <td>
                                            <div style={{ fontWeight: 600 }}>{r.name}</div>
                                            {r.description && (
                                                <div className="text-xs text-muted" style={{ marginTop: 2, maxWidth: 500 }}>
                                                    {r.description.length > 120 ? r.description.slice(0, 120) + '...' : r.description}
                                                </div>
                                            )}
                                        </td>
                                        <td>
                                            <span className={`badge ${r.enabled ? 'badge-success' : 'badge-error'}`}>
                                                {r.enabled ? 'Active' : 'Disabled'}
                                            </span>
                                        </td>
                                        <td>{r.alert_on_modified ? 'Yes' : '\u2014'}</td>
                                        <td>
                                            <button
                                                className="btn btn-secondary"
                                                style={{ padding: '4px 12px', fontSize: 12, color: 'var(--purple-400)' }}
                                                disabled={testingId === r.id}
                                                onClick={(e) => { e.stopPropagation(); handleTest(r.id); }}>
                                                {testingId === r.id ? 'Testing...' : 'Test'}
                                            </button>
                                        </td>
                                    </tr>
                                    {/* Expanded detail row */}
                                    {expandedId === r.id && (
                                        <tr>
                                            <td colSpan="5" style={{ padding: 0 }}>
                                                <div style={{ padding: '16px 20px', background: 'rgba(0,0,0,0.15)', borderTop: '1px solid var(--border)' }}>
                                                    <div style={{ marginBottom: 8 }}>
                                                        <span className="text-xs text-muted" style={{ display: 'block', marginBottom: 4 }}>PQL Query:</span>
                                                        <pre style={{
                                                            fontFamily: 'monospace', fontSize: 12, whiteSpace: 'pre-wrap',
                                                            padding: 12, background: 'rgba(0,0,0,0.3)', borderRadius: 6,
                                                            color: '#A855F7', margin: 0, lineHeight: 1.5,
                                                        }}>
                                                            {r.pql || '(no PQL query)'}
                                                        </pre>
                                                    </div>
                                                    {r.description && (
                                                        <div className="text-sm text-muted" style={{ marginTop: 8 }}>{r.description}</div>
                                                    )}
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                    {/* Inline test result */}
                                    {testResults[r.id] && (
                                        <tr>
                                            <td colSpan="5" style={{ padding: 0 }}>
                                                <div style={{
                                                    padding: '12px 20px',
                                                    background: 'rgba(0,0,0,0.1)',
                                                    borderTop: '1px solid var(--border)',
                                                }}>
                                                    {testResults[r.id].status === 'error' ? (
                                                        <span style={{ color: 'var(--error)', fontSize: 13 }}>
                                                            Error: {testResults[r.id].message}
                                                        </span>
                                                    ) : (
                                                        <div>
                                                            <span style={{
                                                                fontWeight: 600, fontSize: 13,
                                                                color: testResults[r.id].matches > 0 ? 'var(--success)' : 'var(--warning)',
                                                            }}>
                                                                {testResults[r.id].matches > 0
                                                                    ? `${testResults[r.id].matches.toLocaleString()} matches`
                                                                    : 'No matches'}
                                                            </span>
                                                            <span className="text-muted text-sm" style={{ marginLeft: 8 }}>
                                                                ({testResults[r.id].total_tested?.toLocaleString()} CVEs in {testResults[r.id].elapsed_seconds}s)
                                                            </span>
                                                            {testResults[r.id].matched_cves && testResults[r.id].matched_cves.length > 0 && (
                                                                <div className="table-container" style={{ maxHeight: 200, overflow: 'auto', marginTop: 8 }}>
                                                                    <table>
                                                                        <thead><tr><th>CVE ID</th><th>Vendor</th><th>Severity</th><th>CVSS</th><th>KEV</th></tr></thead>
                                                                        <tbody>
                                                                            {testResults[r.id].matched_cves.slice(0, 20).map(c => (
                                                                                <tr key={c.cve_id}>
                                                                                    <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{c.cve_id}</td>
                                                                                    <td>{c.vendor || '\u2014'}</td>
                                                                                    <td><span className={`badge badge-${(c.severity || 'unknown').toLowerCase()}`}>{c.severity || 'N/A'}</span></td>
                                                                                    <td className="text-mono">{c.cvss_score ?? '\u2014'}</td>
                                                                                    <td>{c.kev_flag ? 'Yes' : '\u2014'}</td>
                                                                                </tr>
                                                                            ))}
                                                                        </tbody>
                                                                    </table>
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}
                                                    <button
                                                        className="text-xs"
                                                        style={{ marginTop: 6, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}
                                                        onClick={() => setTestResults(prev => { const n = { ...prev }; delete n[r.id]; return n; })}>
                                                        Dismiss
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                </React.Fragment>
                            ))}
                            {rules.length === 0 && (
                                <tr><td colSpan="5" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>
                                    No rules loaded. Check abusecve_filters.yaml on the server.
                                </td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* PQL Help Modal */}
            {showHelp && (
                <div style={{
                    position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
                    background: 'rgba(0,0,0,0.7)', display: 'flex', justifyContent: 'center', alignItems: 'center',
                    zIndex: 1000, padding: 20,
                }} onClick={() => setShowHelp(false)}>
                    <div style={{
                        background: 'var(--card-bg)', borderRadius: 12, padding: 30,
                        maxWidth: 700, maxHeight: '80vh', overflow: 'auto', width: '100%',
                        border: '1px solid var(--border-accent)',
                    }} onClick={e => e.stopPropagation()}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20 }}>
                            <h2 style={{ color: 'var(--purple-400)', margin: 0 }}>PQL Syntax Reference</h2>
                            <button className="btn btn-secondary" onClick={() => setShowHelp(false)}
                                style={{ padding: '4px 12px' }}>X</button>
                        </div>

                        {helpData ? (
                            <div>
                                <h3>Syntax</h3>
                                <div className="table-container">
                                    <table>
                                        <thead><tr><th>Pattern</th><th>Description</th><th>Example</th></tr></thead>
                                        <tbody>
                                            {helpData.pql_syntax?.map((s, i) => (
                                                <tr key={i}>
                                                    <td className="text-mono" style={{ color: 'var(--purple-400)', whiteSpace: 'nowrap' }}>{s.syntax}</td>
                                                    <td className="text-sm">{s.description}</td>
                                                    <td className="text-mono text-xs">{s.example}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>

                                <h3 style={{ marginTop: 20 }}>Field Aliases</h3>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                                    {helpData.field_aliases && Object.entries(helpData.field_aliases).map(([alias, field]) => (
                                        <span key={alias} className="badge" style={{ background: 'rgba(124,58,237,0.2)', color: '#A855F7', padding: '4px 10px' }}>
                                            {alias} &rarr; {field}
                                        </span>
                                    ))}
                                </div>

                                <h3 style={{ marginTop: 20 }}>Available Fields</h3>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                    {helpData.fields?.map(f => (
                                        <span key={f} className="badge" style={{ background: 'rgba(124,58,237,0.15)', color: '#A855F7', padding: '4px 8px' }}>
                                            {f}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        ) : (
                            <div className="loading"><div className="loading-spinner" />Loading help...</div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
