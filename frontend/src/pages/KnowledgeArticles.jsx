import React, { useState, useEffect } from 'react';
import { getKAs, createKA, updateKA, deleteKA, getCVEs } from '../api';

export default function KnowledgeArticles() {
    const [articles, setArticles] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [selected, setSelected] = useState(null);
    const [form, setForm] = useState({ title: '', cve_ids: [], content: '', summary: '', recommendations: '', author: '' });
    const [cveInput, setCveInput] = useState('');

    const fetchKAs = async () => {
        try { setArticles(await getKAs()); } catch (e) { console.error(e); }
        finally { setLoading(false); }
    };

    useEffect(() => { fetchKAs(); }, []);

    const handleCreate = async () => {
        try {
            await createKA(form);
            setShowModal(false);
            setForm({ title: '', cve_ids: [], content: '', summary: '', recommendations: '', author: '' });
            fetchKAs();
        } catch (e) { alert(e.message); }
    };

    const handleDelete = async (id) => {
        if (!confirm('Delete this Knowledge Article?')) return;
        try { await deleteKA(id); fetchKAs(); } catch (e) { alert(e.message); }
    };

    const addCVE = () => {
        if (!cveInput.trim()) return;
        setForm(f => ({ ...f, cve_ids: [...f.cve_ids, cveInput.trim().toUpperCase()] }));
        setCveInput('');
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading...</div></div>;

    return (
        <div className="main-content animate-in">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <div>
                    <h1 className="header-title">Knowledge Articles</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>CVE analysis reports and documentation</p>
                </div>
                <button className="btn btn-primary" onClick={() => setShowModal(true)}>+ New Article</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {articles.map(ka => (
                    <div key={ka.id} className="card" style={{ cursor: 'pointer' }} onClick={() => setSelected(ka)}>
                        <div className="flex justify-between items-center">
                            <div>
                                <div className="flex items-center gap-12 mb-8">
                                    <h3 style={{ fontSize: 16, fontWeight: 700 }}>{ka.title}</h3>
                                    <span className={`badge ${ka.status === 'published' ? 'badge-success' : 'badge-info'}`}>{ka.status}</span>
                                    {ka.severity_assessment && (
                                        <span className={`badge badge-${ka.severity_assessment.toLowerCase()}`}>{ka.severity_assessment}</span>
                                    )}
                                </div>
                                <p className="text-sm text-muted mb-8">{ka.summary || 'No summary'}</p>
                                <div className="flex gap-8">
                                    {(ka.cve_ids || []).slice(0, 5).map(id => (
                                        <span key={id} className="tag">{id}</span>
                                    ))}
                                    {ka.cve_ids?.length > 5 && <span className="text-xs text-muted">+{ka.cve_ids.length - 5} more</span>}
                                </div>
                            </div>
                            <div className="flex gap-8" onClick={e => e.stopPropagation()}>
                                <button className="btn btn-danger btn-sm" onClick={() => handleDelete(ka.id)}>🗑️</button>
                            </div>
                        </div>
                    </div>
                ))}
                {articles.length === 0 && (
                    <div className="empty-state">
                        <div className="empty-icon">📝</div>
                        <h3>No Knowledge Articles</h3>
                        <p className="text-muted">Create your first article from CVE data.</p>
                    </div>
                )}
            </div>

            {/* Create Modal */}
            {showModal && (
                <div className="modal-overlay" onClick={() => setShowModal(false)}>
                    <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 700 }}>
                        <div className="modal-header">
                            <h2 className="modal-title">New Knowledge Article</h2>
                            <button className="modal-close" onClick={() => setShowModal(false)}>✕</button>
                        </div>
                        <div className="form-group">
                            <label className="form-label">Title</label>
                            <input className="form-input" placeholder="Article title..."
                                value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">CVE IDs (press Enter)</label>
                            <div className="tags-input">
                                {form.cve_ids.map((id, i) => (
                                    <span key={i} className="tag">{id}
                                        <span className="tag-remove" onClick={() => setForm(f => ({ ...f, cve_ids: f.cve_ids.filter((_, j) => j !== i) }))}>✕</span>
                                    </span>
                                ))}
                                <input placeholder="CVE-YYYY-NNNNN" value={cveInput}
                                    onChange={e => setCveInput(e.target.value)}
                                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addCVE(); } }} />
                            </div>
                        </div>
                        <div className="form-group">
                            <label className="form-label">Content (leave empty for auto-generation)</label>
                            <textarea className="form-textarea" placeholder="Markdown content (auto-generated if blank)..."
                                style={{ minHeight: 150 }} value={form.content}
                                onChange={e => setForm(f => ({ ...f, content: e.target.value }))} />
                        </div>
                        <div className="grid-2">
                            <div className="form-group">
                                <label className="form-label">Author</label>
                                <input className="form-input" placeholder="Author name"
                                    value={form.author} onChange={e => setForm(f => ({ ...f, author: e.target.value }))} />
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
                            <button className="btn btn-primary" onClick={handleCreate}
                                disabled={!form.title || form.cve_ids.length === 0}>+ Create Article</button>
                        </div>
                    </div>
                </div>
            )}

            {/* Detail Modal */}
            {selected && (
                <div className="modal-overlay" onClick={() => setSelected(null)}>
                    <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 800, maxHeight: '90vh' }}>
                        <div className="modal-header">
                            <h2 className="modal-title">{selected.title}</h2>
                            <button className="modal-close" onClick={() => setSelected(null)}>✕</button>
                        </div>
                        <div className="flex gap-8 mb-16">
                            <span className={`badge ${selected.status === 'published' ? 'badge-success' : 'badge-info'}`}>{selected.status}</span>
                            {selected.severity_assessment && (
                                <span className={`badge badge-${selected.severity_assessment.toLowerCase()}`}>{selected.severity_assessment}</span>
                            )}
                        </div>
                        <div className="mb-16">
                            <span className="text-xs text-muted">CVEs</span>
                            <div className="flex gap-8 mt-8" style={{ flexWrap: 'wrap' }}>
                                {(selected.cve_ids || []).map(id => <span key={id} className="tag">{id}</span>)}
                            </div>
                        </div>
                        {selected.summary && <div className="mb-16"><span className="text-xs text-muted">Summary</span><p style={{ marginTop: 4 }}>{selected.summary}</p></div>}
                        <div className="markdown-content mb-16" dangerouslySetInnerHTML={{
                            __html: (selected.content || '').replace(/\n/g, '<br>').replace(/^# (.*)$/gm, '<h1>$1</h1>')
                                .replace(/^## (.*)$/gm, '<h2>$1</h2>').replace(/^---$/gm, '<hr>')
                                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                        }} />
                        {selected.recommendations && (
                            <div className="card" style={{ background: 'rgba(124,58,237,0.05)' }}>
                                <h4 style={{ color: 'var(--purple-400)', marginBottom: 8 }}>Recommendations</h4>
                                <div style={{ whiteSpace: 'pre-wrap', fontSize: 13, lineHeight: 1.7 }}>{selected.recommendations}</div>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
