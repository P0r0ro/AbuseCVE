import React, { useState, useEffect } from 'react';
import { getCVEs, generateKA } from '../api';

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

    return (
        <div className="main-content animate-in">
            <div style={{ marginBottom: 24 }}>
                <h1 className="header-title">CVE Database</h1>
                <p className="text-sm text-muted" style={{ marginTop: 4 }}>Search and browse stored CVEs from all sources</p>
            </div>

            {genStatus && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: genStatus.includes('✅') ? 'var(--success)' : genStatus.includes('❌') ? 'var(--error)' : 'var(--border-accent)' }}>
                    <span className="text-sm">{genStatus}</span>
                    <button className="text-sm" style={{ marginLeft: 12, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}
                        onClick={() => setGenStatus('')}>✕</button>
                </div>
            )}

            {/* Search & Filters */}
            <div className="card mb-20">
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                    <div style={{ flex: 2, minWidth: 200 }}>
                        <label className="form-label">Search</label>
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
        </div>
    );
}
