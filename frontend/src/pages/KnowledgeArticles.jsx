import React, { useState, useEffect } from 'react';
import { getKAs, deleteKA, generateKA, exportKA, getCVEs, getAIStatus, generateBatchKA } from '../api';

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
    const [aiStatus, setAiStatus] = useState(null);
    const [selectedCves, setSelectedCves] = useState(new Set());
    const [batchGenerating, setBatchGenerating] = useState(false);

    const fetchAIStatus = async () => {
        try {
            const status = await getAIStatus();
            setAiStatus(status);
        } catch (e) {
            console.error('Failed to check AI status:', e);
        }
    };

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

    useEffect(() => { fetchKAs(); fetchAIStatus(); }, []);

    const handleGenerate = async (cveId) => {
        setGenerating(cveId);
        setGenStatus(`Generating report for ${cveId}...`);
        try {
            const result = await generateKA(cveId, aiProvider);
            let statusMsg = `✅ Report generated for ${cveId}`;
            if (result.ai_status === 'fallback_to_template' && result.ai_error) {
                statusMsg += ` (AI unavailable: ${result.ai_error} — used template)`;
            } else if (result.generation_method && result.generation_method.startsWith('ai_')) {
                statusMsg += ` (via ${result.generation_method.replace('ai_', '').toUpperCase()})`;
            }
            setGenStatus(statusMsg);
            setShowPreview(result);
            fetchKAs();
        } catch (e) {
            setGenStatus(`❌ Generation failed: ${e.message}`);
        } finally {
            setGenerating('');
        }
    };

    const handleBatchGenerate = async () => {
        const cveIds = Array.from(selectedCves);
        if (cveIds.length < 2) return;
        setBatchGenerating(true);
        setGenStatus(`Generating batch report for ${cveIds.length} CVEs...`);
        try {
            const result = await generateBatchKA(cveIds, aiProvider);
            let statusMsg = `✅ Batch report generated for ${result.cve_count || cveIds.length} CVEs`;
            if (result.missing_cves?.length) {
                statusMsg += ` (${result.missing_cves.length} not found)`;
            }
            if (result.ai_status === 'fallback_to_template' && result.ai_error) {
                statusMsg += ` (AI unavailable — used template)`;
            } else if (result.generation_method?.startsWith('ai_')) {
                statusMsg += ` (via ${result.generation_method.replace('ai_', '').toUpperCase()})`;
            }
            setGenStatus(statusMsg);
            setShowPreview(result);
            setSelectedCves(new Set());
            fetchKAs();
        } catch (e) {
            setGenStatus(`❌ Batch generation failed: ${e.message}`);
        } finally {
            setBatchGenerating(false);
        }
    };

    const toggleCveSelection = (cveId) => {
        setSelectedCves(prev => {
            const next = new Set(prev);
            if (next.has(cveId)) next.delete(cveId);
            else next.add(cveId);
            return next;
        });
    };

    const toggleSelectAll = () => {
        if (selectedCves.size === cveResults.length) {
            setSelectedCves(new Set());
        } else {
            setSelectedCves(new Set(cveResults.map(c => c.cve_id)));
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
        setSelectedCves(new Set());
        try {
            const result = await getCVEs({ search: cveSearch, per_page: 50 });
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

            {/* AI Key Warning */}
            {aiStatus && !aiStatus.any_configured && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: 'var(--warning)', background: 'rgba(255,215,0,0.05)' }}>
                    <span className="text-sm" style={{ color: 'var(--warning)' }}>
                        No AI API keys configured. Add MISTRAL_API_KEY or GEMINI_API_KEY to your .env file for AI-powered reports. Currently using template-based generation only.
                    </span>
                </div>
            )}

            {/* Generate Section */}
            <div className="card mb-24">
                <div className="card-header">
                    <div className="card-title">🤖 Generate Vulnerability Report</div>
                </div>
                <div style={{ padding: '0 20px 20px' }}>
                    <p className="text-sm text-muted mb-16">Search for CVEs, then generate individual or batch reports. Select multiple CVEs for a consolidated batch KA.</p>

                    <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
                        <input className="form-input" placeholder="Search CVE ID, vendor, product..."
                            value={cveSearch} onChange={e => setCveSearch(e.target.value)}
                            onKeyDown={e => { if (e.key === 'Enter') handleCVESearch(); }} />
                        <button className="btn btn-primary" onClick={handleCVESearch} disabled={searchLoading}>
                            {searchLoading ? '...' : '🔍 Search'}
                        </button>
                    </div>

                    {/* AI Provider Selection */}
                    <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
                        <span className="text-sm text-muted" style={{ marginTop: 4 }}>AI Provider:</span>
                        {['auto', 'mistral', 'gemini', 'template'].map(p => (
                            <label key={p} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
                                <input type="radio" name="aiProvider" checked={aiProvider === p} onChange={() => setAiProvider(p)} />
                                <span className="text-sm" style={{ textTransform: 'capitalize' }}>{p}</span>
                            </label>
                        ))}
                    </div>

                    {/* Batch Generate Bar */}
                    {selectedCves.size >= 2 && (
                        <div style={{
                            display: 'flex', gap: 12, alignItems: 'center', padding: '10px 16px',
                            background: 'rgba(124,58,237,0.1)', borderRadius: 8, marginBottom: 16,
                            border: '1px solid rgba(124,58,237,0.3)',
                        }}>
                            <span className="text-sm" style={{ color: 'var(--purple-400)', fontWeight: 600 }}>
                                {selectedCves.size} CVEs selected
                            </span>
                            <button className="btn btn-primary" style={{ padding: '6px 16px', fontSize: 13 }}
                                onClick={handleBatchGenerate} disabled={batchGenerating}>
                                {batchGenerating ? '⏳ Generating Batch...' : '📝 Generate Batch KA'}
                            </button>
                            <button className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: 12 }}
                                onClick={() => setSelectedCves(new Set())}>
                                ✕ Clear Selection
                            </button>
                        </div>
                    )}

                    {/* Search Results */}
                    {cveResults.length > 0 && (
                        <div className="table-container" style={{ maxHeight: 400, overflow: 'auto' }}>
                            <table>
                                <thead>
                                    <tr>
                                        <th style={{ width: 40 }}>
                                            <input type="checkbox"
                                                checked={cveResults.length > 0 && selectedCves.size === cveResults.length}
                                                onChange={toggleSelectAll}
                                                title="Select All" />
                                        </th>
                                        <th>CVE ID</th>
                                        <th>Vendor</th>
                                        <th>Severity</th>
                                        <th>CVSS</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {cveResults.map(cve => (
                                        <tr key={cve.cve_id} style={{
                                            background: selectedCves.has(cve.cve_id) ? 'rgba(124,58,237,0.08)' : undefined,
                                        }}>
                                            <td>
                                                <input type="checkbox"
                                                    checked={selectedCves.has(cve.cve_id)}
                                                    onChange={() => toggleCveSelection(cve.cve_id)} />
                                            </td>
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
                            {showPreview.cve_count && ` | CVEs: ${showPreview.cve_count}`}
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
                                    <td className="text-mono text-sm" style={{ color: 'var(--purple-400)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                        {(ka.cve_ids || []).length > 3
                                            ? `${ka.cve_ids.slice(0, 3).join(', ')} +${ka.cve_ids.length - 3} more`
                                            : (ka.cve_ids || []).join(', ')}
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
