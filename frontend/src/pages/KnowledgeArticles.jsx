import React, { useState, useEffect } from 'react';
import { getKAs, deleteKA, generateKA, exportKA, getCVEs } from '../api';

export default function KnowledgeArticles() {
    const [kas, setKAs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [generating, setGenerating] = useState('');
    const [genStatus, setGenStatus] = useState('');
    const [showPreview, setShowPreview] = useState(null);
    const [cveSearch, setCveSearch] = useState('');
    const [cveResults, setCveResults] = useState([]);
    const [searchLoading, setSearchLoading] = useState(false);
    const [aiProvider, setAiProvider] = useState('auto');

    const fetchKAs = async () => {
        try {
            const data = await getKAs();
            setKAs(data);
        } catch (e) {
            console.error('Failed to load KAs:', e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchKAs(); }, []);

    const handleGenerate = async (cveId) => {
        setGenerating(cveId);
        setGenStatus(`Generating report for ${cveId}...`);
        try {
            const result = await generateKA(cveId, aiProvider);
            setGenStatus(`✅ Report generated for ${cveId}`);
            setShowPreview(result);
            fetchKAs();
        } catch (e) {
            setGenStatus(`❌ Generation failed: ${e.message}`);
        } finally {
            setGenerating('');
        }
    };

    const handleDelete = async (id) => {
        if (!confirm('Delete this Knowledge Article?')) return;
        try {
            await deleteKA(id);
            fetchKAs();
        } catch (e) {
            alert('Delete failed: ' + e.message);
        }
    };

    const handleExport = async (kaId) => {
        try {
            await exportKA(kaId);
        } catch (e) {
            alert('Export failed: ' + e.message);
        }
    };

    const handleCopy = (content) => {
        navigator.clipboard.writeText(content).then(
            () => setGenStatus('📋 Copied to clipboard!'),
            () => setGenStatus('❌ Copy failed')
        );
    };

    const handleCVESearch = async () => {
        if (!cveSearch.trim()) return;
        setSearchLoading(true);
        try {
            const result = await getCVEs({ search: cveSearch, per_page: 20 });
            setCveResults(result.cves || []);
        } catch (e) {
            console.error('Search failed:', e);
        } finally {
            setSearchLoading(false);
        }
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading knowledge articles...</div></div>;

    return (
        <div className="main-content animate-in">
            <div className="header" style={{ marginBottom: 24, padding: 0, background: 'transparent', border: 'none', height: 'auto' }}>
                <div>
                    <h1 className="header-title">Knowledge Articles</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Auto-generate vulnerability reports for CVEs</p>
                </div>
            </div>

            {genStatus && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: genStatus.includes('✅') || genStatus.includes('📋') ? 'var(--success)' : genStatus.includes('❌') ? 'var(--error)' : 'var(--border-accent)' }}>
                    <span className="text-sm">{genStatus}</span>
                    <button className="text-sm" style={{ marginLeft: 12, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}
                        onClick={() => setGenStatus('')}>✕</button>
                </div>
            )}

            {/* Generate Section */}
            <div className="card mb-24">
                <div className="card-header">
                    <div className="card-title">🤖 Generate Vulnerability Report</div>
                </div>
                <div style={{ padding: '0 20px 20px' }}>
                    <p className="text-sm text-muted mb-16">Search for a CVE in the database, then click Generate to create a report.</p>

                    <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
                        <input className="form-input" placeholder="Search CVE ID, vendor, product..."
                            value={cveSearch} onChange={e => setCveSearch(e.target.value)}
                            onKeyDown={e => { if (e.key === 'Enter') handleCVESearch(); }} />
                        <button className="btn btn-primary" onClick={handleCVESearch} disabled={searchLoading}>
                            {searchLoading ? '...' : '🔍 Search'}
                        </button>
                    </div>

                    {/* AI Provider Selection */}
                    <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
                        <span className="text-sm text-muted" style={{ marginTop: 4 }}>AI Provider:</span>
                        {['auto', 'mistral', 'gemini', 'template'].map(p => (
                            <label key={p} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
                                <input type="radio" name="aiProvider" checked={aiProvider === p} onChange={() => setAiProvider(p)} />
                                <span className="text-sm" style={{ textTransform: 'capitalize' }}>{p}</span>
                            </label>
                        ))}
                    </div>

                    {/* Search Results */}
                    {cveResults.length > 0 && (
                        <div className="table-container" style={{ maxHeight: 300, overflow: 'auto' }}>
                            <table>
                                <thead><tr><th>CVE ID</th><th>Vendor</th><th>Severity</th><th>CVSS</th><th>Action</th></tr></thead>
                                <tbody>
                                    {cveResults.map(cve => (
                                        <tr key={cve.cve_id}>
                                            <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{cve.cve_id}</td>
                                            <td className="text-sm">{cve.vendor || '—'}</td>
                                            <td><span className={`badge badge-${(cve.severity || 'unknown').toLowerCase()}`}>{cve.severity || 'N/A'}</span></td>
                                            <td className="text-mono">{cve.cvss_score ?? '—'}</td>
                                            <td>
                                                <button className="btn btn-primary" style={{ padding: '4px 12px', fontSize: 12 }}
                                                    onClick={() => handleGenerate(cve.cve_id)}
                                                    disabled={generating === cve.cve_id}>
                                                    {generating === cve.cve_id ? '⏳' : '📝'} Generate
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>

            {/* Preview Modal */}
            {showPreview && (
                <div className="card mb-24">
                    <div className="card-header">
                        <div className="card-title">📄 Generated Report Preview</div>
                        <div style={{ display: 'flex', gap: 8 }}>
                            <button className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: 12 }}
                                onClick={() => handleCopy(showPreview.content || showPreview.text_content || '')}>
                                📋 Copy
                            </button>
                            {showPreview.id && (
                                <button className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: 12 }}
                                    onClick={() => handleExport(showPreview.id)}>
                                    📄 Export
                                </button>
                            )}
                            <button className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: 12 }}
                                onClick={() => setShowPreview(null)}>✕ Close</button>
                        </div>
                    </div>
                    <div style={{ padding: 20 }}>
                        {showPreview.html_content ? (
                            <div dangerouslySetInnerHTML={{ __html: showPreview.html_content }} />
                        ) : (
                            <pre style={{
                                whiteSpace: 'pre-wrap', fontFamily: "'Inter', sans-serif", fontSize: 13,
                                lineHeight: 1.6, color: 'var(--text-primary)',
                            }}>
                                {showPreview.content || showPreview.text_content}
                            </pre>
                        )}
                        <div className="text-sm text-muted" style={{ marginTop: 12 }}>
                            Method: {showPreview.generation_method || 'template'} |
                            Status: {showPreview.status}
                        </div>
                    </div>
                </div>
            )}

            {/* Existing KAs */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">Saved Articles ({kas.length})</div>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Title</th>
                                <th>CVE IDs</th>
                                <th>Status</th>
                                <th>Author</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {kas.map(ka => (
                                <tr key={ka.id}>
                                    <td style={{ fontWeight: 600, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>{ka.title}</td>
                                    <td className="text-mono text-sm" style={{ color: 'var(--purple-400)' }}>
                                        {(ka.cve_ids || []).join(', ')}
                                    </td>
                                    <td><span className={`badge ${ka.status === 'published' ? 'badge-success' : 'badge-warning'}`}>{ka.status}</span></td>
                                    <td className="text-sm">{ka.author || '—'}</td>
                                    <td className="text-sm text-muted">{ka.created_at ? new Date(ka.created_at).toLocaleDateString() : '—'}</td>
                                    <td>
                                        <div style={{ display: 'flex', gap: 6 }}>
                                            <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }}
                                                onClick={() => setShowPreview(ka)}>👁️</button>
                                            <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }}
                                                onClick={() => handleCopy(ka.content || '')}>📋</button>
                                            <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }}
                                                onClick={() => handleExport(ka.id)}>📄</button>
                                            <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12, color: 'var(--error)' }}
                                                onClick={() => handleDelete(ka.id)}>🗑️</button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                            {kas.length === 0 && (
                                <tr><td colSpan="6" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>
                                    No knowledge articles yet. Search for a CVE and generate one.
                                </td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
