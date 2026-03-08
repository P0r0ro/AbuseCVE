import React, { useState, useEffect } from 'react';
import { getCVEs, generateKA, searchCVEsByPQL, getQueryHelp, exportCVEsExcel } from '../api';

const sourceColors = {
    NVD: '#6366F1',
    MITRE: '#F97316',
    CISA_KEV: '#EF4444',
    REDHAT: '#DC2626',
};

export default function CVEDatabase() {
    const [cves, setCves] = useState([]);
    const [total, setTotal] = useState(0);
    const [pages, setPages] = useState(1);
    const [loading, setLoading] = useState(true);
    const [params, setParams] = useState({
        page: 1, per_page: 50, search: '', vendor: '', product: '',
        severity: '', source: '', kev_only: false,
        sort_by: 'published_date', sort_order: 'desc',
    });
    const [selected, setSelected] = useState(null);
    const [genStatus, setGenStatus] = useState('');
    const [pqlQuery, setPqlQuery] = useState('');
    const [showHelp, setShowHelp] = useState(false);
    const [queryHelp, setQueryHelp] = useState(null);
    const [showExportMenu, setShowExportMenu] = useState(false);
    const [exporting, setExporting] = useState(false);

    const fetchData = async () => {
        setLoading(true);
        try {
            const data = await getCVEs(params);
            setCves(data.cves || data.items || []);
            setTotal(data.total || 0);
            setPages(data.pages || 1);
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    };

    useEffect(() => { fetchData(); }, [params]);

    const updateParam = (key, val) => setParams(p => ({ ...p, [key]: val, page: 1 }));

    const handleGenerateKA = async (cveId) => {
        setGenStatus(`Generating report for ${cveId}...`);
        try {
            await generateKA(cveId, 'auto');
            setGenStatus(`✅ Report generated for ${cveId}!`);
        } catch (e) {
            setGenStatus(`❌ Generation failed: ${e.message}`);
        }
    };

    const handleExport = async (mode) => {
        setExporting(true);
        setShowExportMenu(false);
        try {
            const p = { mode };
            if (mode === 'filtered') {
                if (params.severity) p.severity = params.severity;
                if (params.vendor) p.vendor = params.vendor;
                if (params.product) p.product = params.product;
                if (params.source) p.source = params.source;
                if (params.search) p.search = params.search;
                if (params.kev_only) p.kev_only = true;
                if (params.sort_by) p.sort_by = params.sort_by;
                if (params.sort_order) p.sort_order = params.sort_order;
                if (pqlQuery) p.pql = pqlQuery;
            }
            await exportCVEsExcel(p);
        } catch (e) {
            alert('Export failed: ' + e.message);
        } finally {
            setExporting(false);
        }
    };

    return (
        <div className="main-content animate-in">
            <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h1 className="header-title">CVE Database</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Search and browse stored CVEs from all sources</p>
                </div>
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
            </div>

            {genStatus && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: genStatus.includes('✅') ? 'var(--success)' : genStatus.includes('❌') ? 'var(--error)' : 'var(--border-accent)' }}>
                    <span className="text-sm">{genStatus}</span>
                    <button className="text-sm" style={{ marginLeft: 12, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}
                        onClick={() => setGenStatus('')}>✕</button>
                </div>
            )}

            {/* PQL Search Bar */}
            <div className="card mb-20">
                <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    <div style={{ flex: 1 }}>
                        <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            🔍 PQL Search
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
                            onKeyDown={async e => {
                                if (e.key === 'Enter' && pqlQuery.trim()) {
                                    setLoading(true);
                                    try {
                                        const data = await searchCVEsByPQL(pqlQuery, params.page, params.per_page);
                                        setCves(data.cves || data.items || data.results || []);
                                        setTotal(data.total || 0);
                                        setPages(data.pages || 1);
                                    } catch (e2) { console.error(e2); }
                                    finally { setLoading(false); }
                                }
                            }}
                        />
                        <span className="text-xs text-muted" style={{ marginTop: 4, display: 'block' }}>
                            Press Enter to search • Supports: vendor:X product:X severity:X cvss:&gt;N kev:true description:"phrase"
                        </span>
                    </div>
                    <button className="btn btn-primary" style={{ alignSelf: 'flex-end', marginBottom: 20 }}
                        onClick={async () => {
                            if (!pqlQuery.trim()) return;
                            setLoading(true);
                            try {
                                const data = await searchCVEsByPQL(pqlQuery, params.page, params.per_page);
                                setCves(data.cves || data.items || data.results || []);
                                setTotal(data.total || 0);
                                setPages(data.pages || 1);
                            } catch (e) { console.error(e); }
                            finally { setLoading(false); }
                        }}>🔎 Search</button>
                    {pqlQuery && (
                        <button className="btn btn-secondary" style={{ alignSelf: 'flex-end', marginBottom: 20 }}
                            onClick={() => { setPqlQuery(''); fetchData(); }}>✕ Clear</button>
                    )}
                </div>
            </div>

            {/* Standard Filters */}
            <div className="card mb-20">
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                    <div style={{ flex: 2, minWidth: 200 }}>
                        <label className="form-label">Quick Search</label>
                        <input className="form-input" placeholder="Search CVE ID, description, vendor..."
                            value={params.search} onChange={e => updateParam('search', e.target.value)} />
                    </div>
                    <div style={{ flex: 1, minWidth: 140 }}>
                        <label className="form-label">Vendor</label>
                        <input className="form-input" placeholder="Vendor" value={params.vendor}
                            onChange={e => updateParam('vendor', e.target.value)} />
                    </div>
                    <div style={{ flex: 1, minWidth: 140 }}>
                        <label className="form-label">Product</label>
                        <input className="form-input" placeholder="Product" value={params.product}
                            onChange={e => updateParam('product', e.target.value)} />
                    </div>
                    <div style={{ minWidth: 120 }}>
                        <label className="form-label">Severity</label>
                        <select className="form-select" value={params.severity}
                            onChange={e => updateParam('severity', e.target.value)}>
                            <option value="">All</option>
                            <option value="CRITICAL">Critical</option>
                            <option value="HIGH">High</option>
                            <option value="MEDIUM">Medium</option>
                            <option value="LOW">Low</option>
                            <option value="CRITICAL,HIGH">Critical + High</option>
                        </select>
                    </div>
                    <div style={{ minWidth: 120 }}>
                        <label className="form-label">Source</label>
                        <select className="form-select" value={params.source}
                            onChange={e => updateParam('source', e.target.value)}>
                            <option value="">All</option>
                            <option value="NVD">NVD</option>
                            <option value="MITRE">MITRE</option>
                            <option value="CISA_KEV">CISA KEV</option>
                            <option value="REDHAT">RedHat</option>
                        </select>
                    </div>
                    <div className="flex items-center gap-8" style={{ paddingBottom: 2 }}>
                        <label className="toggle">
                            <input type="checkbox" checked={params.kev_only}
                                onChange={e => updateParam('kev_only', e.target.checked)} />
                            <span className="toggle-slider" />
                        </label>
                        <span className="text-sm">KEV Only</span>
                    </div>
                </div>
            </div>

            {/* Results */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">Results ({total.toLocaleString()} CVEs)</div>
                    <div className="flex gap-8">
                        <select className="form-select" style={{ width: 'auto' }}
                            value={params.sort_by} onChange={e => setParams(p => ({ ...p, sort_by: e.target.value }))}>
                            <option value="published_date">Published Date</option>
                            <option value="cvss_score">CVSS Score</option>
                            <option value="first_seen">First Seen</option>
                            <option value="seen_count">Seen Count</option>
                        </select>
                        <button className="btn btn-secondary btn-sm"
                            onClick={() => setParams(p => ({ ...p, sort_order: p.sort_order === 'desc' ? 'asc' : 'desc' }))}>
                            {params.sort_order === 'desc' ? '↓' : '↑'}
                        </button>
                    </div>
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
                                <th>Published</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {cves.map(cve => (
                                <tr key={cve.cve_id}>
                                    <td className="text-mono" style={{ color: 'var(--purple-400)', cursor: 'pointer' }}
                                        onClick={() => setSelected(cve)}>{cve.cve_id}</td>
                                    <td>{cve.vendor || '—'}</td>
                                    <td>{cve.product || '—'}</td>
                                    <td><span className={`badge badge-${(cve.severity || 'unknown').toLowerCase()}`}>{cve.severity || 'N/A'}</span></td>
                                    <td className="text-mono">{cve.cvss_score ?? '—'}</td>
                                    <td>
                                        <span style={{
                                            fontSize: 11, padding: '2px 6px', borderRadius: 4,
                                            background: `${sourceColors[cve.source] || '#666'}20`,
                                            color: sourceColors[cve.source] || '#888',
                                        }}>
                                            {cve.source || '—'}
                                        </span>
                                    </td>
                                    <td>{cve.kev_flag ? <span className="badge badge-kev">⚠ KEV</span> : '—'}</td>
                                    <td className="text-sm text-muted">{cve.published_date ? new Date(cve.published_date).toLocaleDateString() : '—'}</td>
                                    <td>
                                        <button className="btn btn-secondary" style={{ padding: '2px 8px', fontSize: 11 }}
                                            onClick={() => handleGenerateKA(cve.cve_id)}
                                            title="Generate Knowledge Article">📝 KA</button>
                                    </td>
                                </tr>
                            ))}
                            {!loading && cves.length === 0 && (
                                <tr><td colSpan="9" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>No CVEs match your criteria.</td></tr>
                            )}
                        </tbody>
                    </table>
                </div>

                {pages > 1 && (
                    <div className="pagination">
                        <button className="pagination-btn" disabled={params.page <= 1}
                            onClick={() => setParams(p => ({ ...p, page: p.page - 1 }))}>← Prev</button>
                        <span className="text-sm text-muted">Page {params.page} of {pages}</span>
                        <button className="pagination-btn" disabled={params.page >= pages}
                            onClick={() => setParams(p => ({ ...p, page: p.page + 1 }))}>Next →</button>
                    </div>
                )}
            </div>

            {/* CVE Detail Modal */}
            {selected && (
                <div className="modal-overlay" onClick={() => setSelected(null)}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h2 className="modal-title" style={{ color: 'var(--purple-400)' }}>{selected.cve_id}</h2>
                            <button className="modal-close" onClick={() => setSelected(null)}>✕</button>
                        </div>
                        <div className="flex gap-8 mb-16">
                            <span className={`badge badge-${(selected.severity || 'unknown').toLowerCase()}`}>{selected.severity || 'N/A'}</span>
                            {selected.kev_flag && <span className="badge badge-kev">⚠️ Known Exploited</span>}
                            {selected.source && (
                                <span style={{
                                    fontSize: 11, padding: '2px 8px', borderRadius: 4,
                                    background: `${sourceColors[selected.source] || '#666'}20`,
                                    color: sourceColors[selected.source] || '#888',
                                }}>
                                    {selected.source}
                                </span>
                            )}
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                            <div><span className="text-xs text-muted">Vendor</span><p>{selected.vendor || 'N/A'}</p></div>
                            <div><span className="text-xs text-muted">Product</span><p>{selected.product || 'N/A'}</p></div>
                            <div><span className="text-xs text-muted">CVSS Score</span><p className="text-mono">{selected.cvss_score ?? 'N/A'}</p></div>
                            <div><span className="text-xs text-muted">Source</span><p>{selected.source || 'N/A'}</p></div>
                            <div><span className="text-xs text-muted">Published</span><p>{selected.published_date ? new Date(selected.published_date).toLocaleDateString() : 'N/A'}</p></div>
                            <div><span className="text-xs text-muted">Sources</span><p>{(selected.sources || []).join(', ') || 'N/A'}</p></div>
                        </div>

                        {/* Multi-Provider CVSS */}
                        {selected.cvss_scores && Object.keys(selected.cvss_scores).length > 0 && (
                            <div className="mb-16">
                                <span className="text-xs text-muted">CVSS Scores by Provider</span>
                                <div style={{ marginTop: 6 }}>
                                    {Object.entries(selected.cvss_scores).map(([provider, data]) => (
                                        <div key={provider} style={{
                                            display: 'inline-block', marginRight: 8, marginBottom: 4,
                                            padding: '4px 10px', borderRadius: 6,
                                            background: 'rgba(124,58,237,0.1)',
                                            fontSize: 12,
                                        }}>
                                            <strong>{provider}:</strong> {typeof data === 'object' ? `${data.score} (v${data.version})` : data}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        <div className="mb-16">
                            <span className="text-xs text-muted">Description</span>
                            <p style={{ marginTop: 4, lineHeight: 1.6 }}>{selected.description || 'No description available.'}</p>
                        </div>

                        {selected.references?.length > 0 && (
                            <div className="mb-16">
                                <span className="text-xs text-muted">References</span>
                                <div style={{ marginTop: 4 }}>
                                    {selected.references.slice(0, 10).map((ref, i) => (
                                        <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                                            style={{ display: 'block', color: 'var(--purple-400)', fontSize: 13, marginBottom: 4, wordBreak: 'break-all' }}>
                                            {ref}
                                        </a>
                                    ))}
                                </div>
                            </div>
                        )}

                        <div style={{ display: 'flex', gap: 8 }}>
                            <button className="btn btn-primary" style={{ padding: '6px 16px', fontSize: 13 }}
                                onClick={() => handleGenerateKA(selected.cve_id)}>
                                📝 Generate KA
                            </button>
                        </div>
                    </div>
                </div>
            )}

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
                                {queryHelp.operators && (
                                    <div className="mb-16">
                                        <h3 className="text-sm" style={{ fontWeight: 700, marginBottom: 8 }}>Operators</h3>
                                        <table style={{ width: '100%', fontSize: 13 }}>
                                            <thead><tr><th>Operator</th><th>Description</th><th>Example</th></tr></thead>
                                            <tbody>
                                                {queryHelp.operators.map((op, i) => (
                                                    <tr key={i}>
                                                        <td className="text-mono">{op.operator || op.name}</td>
                                                        <td className="text-sm">{op.description}</td>
                                                        <td className="text-mono text-sm">{op.example || ''}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
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
                                    <pre style={{ background: 'var(--bg-secondary)', padding: 16, borderRadius: 8, fontSize: 12, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>{`# Search by field
vendor:microsoft
severity:CRITICAL,HIGH
cvss:>7.0

# Quoted phrases
description:"buffer overflow"

# Comparisons
cvss:>=9.0
cvss:<4.0

# Boolean
vendor:fortinet AND severity:CRITICAL
description:"remote code" OR description:"RCE"

# KEV flag
kev:true

# Bare words (search all text fields)
fortinet`}</pre>
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
