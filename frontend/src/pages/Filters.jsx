import React, { useState, useEffect } from 'react';
import { getFilters, createFilter, updateFilter, deleteFilter, toggleFilter } from '../api';

const SEVERITY_OPTIONS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const COMMON_VENDORS = [
    'Fortinet', 'Cisco', 'Microsoft', 'Palo Alto Networks', 'VMware', 'Ivanti',
    'SonicWall', 'Citrix', 'F5', 'Juniper', 'Check Point', 'CrowdStrike',
    'Trend Micro', 'Sophos', 'Barracuda', 'Apache', 'Google', 'Apple',
    'Adobe', 'Oracle', 'SAP', 'IBM', 'Linux', 'WordPress', 'Atlassian',
];

export default function Filters() {
    const [filters, setFilters] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [editing, setEditing] = useState(null);
    const [form, setForm] = useState({
        name: '', vendor: '', products: [], enabled: true,
        min_cvss: null, max_cvss: null, severity_filter: [],
        keywords_include: [], keywords_exclude: [],
        cpe_vendor: '', description: '',
    });
    const [productInput, setProductInput] = useState('');
    const [kwIncInput, setKwIncInput] = useState('');
    const [kwExcInput, setKwExcInput] = useState('');

    const fetchFilters = async () => {
        try {
            const data = await getFilters();
            setFilters(data);
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    };

    useEffect(() => { fetchFilters(); }, []);

    const resetForm = () => {
        setForm({
            name: '', vendor: '', products: [], enabled: true,
            min_cvss: null, max_cvss: null, severity_filter: [],
            keywords_include: [], keywords_exclude: [],
            cpe_vendor: '', description: '',
        });
        setProductInput('');
        setKwIncInput('');
        setKwExcInput('');
        setEditing(null);
    };

    const openCreate = () => { resetForm(); setShowModal(true); };

    const openEdit = (rule) => {
        setForm({
            name: rule.name, vendor: rule.vendor, products: rule.products || [],
            enabled: rule.enabled, min_cvss: rule.min_cvss, max_cvss: rule.max_cvss,
            severity_filter: rule.severity_filter || [], keywords_include: rule.keywords_include || [],
            keywords_exclude: rule.keywords_exclude || [], cpe_vendor: rule.cpe_vendor || '',
            description: rule.description || '',
        });
        setEditing(rule.id);
        setShowModal(true);
    };

    const handleSubmit = async () => {
        try {
            if (editing) {
                await updateFilter(editing, form);
            } else {
                await createFilter(form);
            }
            setShowModal(false);
            fetchFilters();
        } catch (e) { alert(e.message); }
    };

    const handleDelete = async (id) => {
        if (!confirm('Delete this filter rule?')) return;
        try {
            await deleteFilter(id);
            fetchFilters();
        } catch (e) { alert(e.message); }
    };

    const handleToggle = async (id) => {
        try {
            await toggleFilter(id);
            fetchFilters();
        } catch (e) { alert(e.message); }
    };

    const addTag = (field, inputVal, setInput) => {
        if (!inputVal.trim()) return;
        setForm(f => ({ ...f, [field]: [...f[field], inputVal.trim()] }));
        setInput('');
    };

    const removeTag = (field, idx) => {
        setForm(f => ({ ...f, [field]: f[field].filter((_, i) => i !== idx) }));
    };

    const toggleSeverity = (sev) => {
        setForm(f => ({
            ...f,
            severity_filter: f.severity_filter.includes(sev)
                ? f.severity_filter.filter(s => s !== sev)
                : [...f.severity_filter, sev],
        }));
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading filters...</div></div>;

    return (
        <div className="main-content animate-in">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <div>
                    <h1 className="header-title">Filters & Tags</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Define vendor/product monitoring rules</p>
                </div>
                <button className="btn btn-primary" onClick={openCreate}>+ New Filter</button>
            </div>

            {/* Filter Cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {filters.map(rule => (
                    <div key={rule.id} className="card" style={{ opacity: rule.enabled ? 1 : 0.5 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                            <div style={{ flex: 1 }}>
                                <div className="flex items-center gap-12 mb-8">
                                    <h3 style={{ fontSize: 16, fontWeight: 700 }}>{rule.name}</h3>
                                    <span className={`badge ${rule.enabled ? 'badge-success' : 'badge-error'}`}>
                                        {rule.enabled ? 'Active' : 'Disabled'}
                                    </span>
                                </div>
                                <div className="flex gap-16 mb-12" style={{ flexWrap: 'wrap' }}>
                                    <span className="text-sm"><strong style={{ color: 'var(--purple-400)' }}>Vendor:</strong> {rule.vendor}</span>
                                    {rule.products?.length > 0 && (
                                        <span className="text-sm"><strong style={{ color: 'var(--purple-400)' }}>Products:</strong> {rule.products.join(', ')}</span>
                                    )}
                                    {rule.min_cvss && <span className="text-sm"><strong style={{ color: 'var(--purple-400)' }}>Min CVSS:</strong> {rule.min_cvss}</span>}
                                    {rule.max_cvss && <span className="text-sm"><strong style={{ color: 'var(--purple-400)' }}>Max CVSS:</strong> {rule.max_cvss}</span>}
                                </div>
                                {rule.severity_filter?.length > 0 && (
                                    <div className="flex gap-8 mb-8">
                                        {rule.severity_filter.map(s => (
                                            <span key={s} className={`badge badge-${s.toLowerCase()}`}>{s}</span>
                                        ))}
                                    </div>
                                )}
                                {rule.description && <p className="text-sm text-muted">{rule.description}</p>}
                            </div>
                            <div className="flex gap-8">
                                <label className="toggle">
                                    <input type="checkbox" checked={rule.enabled} onChange={() => handleToggle(rule.id)} />
                                    <span className="toggle-slider" />
                                </label>
                                <button className="btn btn-secondary btn-sm" onClick={() => openEdit(rule)}>✏️</button>
                                <button className="btn btn-danger btn-sm" onClick={() => handleDelete(rule.id)}>🗑️</button>
                            </div>
                        </div>
                    </div>
                ))}
                {filters.length === 0 && (
                    <div className="empty-state">
                        <div className="empty-icon">🔍</div>
                        <h3>No Filters Configured</h3>
                        <p className="text-muted">Create your first filter rule to start monitoring CVEs for specific vendors and products.</p>
                        <button className="btn btn-primary mt-16" onClick={openCreate}>+ Create Filter</button>
                    </div>
                )}
            </div>

            {/* Create/Edit Modal */}
            {showModal && (
                <div className="modal-overlay" onClick={() => setShowModal(false)}>
                    <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 700, maxHeight: '90vh' }}>
                        <div className="modal-header">
                            <h2 className="modal-title">{editing ? 'Edit Filter Rule' : 'New Filter Rule'}</h2>
                            <button className="modal-close" onClick={() => setShowModal(false)}>✕</button>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Rule Name</label>
                            <input className="form-input" placeholder="e.g., Fortinet Critical Products"
                                value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
                        </div>

                        <div className="grid-2">
                            <div className="form-group">
                                <label className="form-label">Vendor</label>
                                <select className="form-select" value={form.vendor}
                                    onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))}>
                                    <option value="">Select vendor...</option>
                                    {COMMON_VENDORS.map(v => <option key={v} value={v.toLowerCase()}>{v}</option>)}
                                    <option value="__custom">Custom...</option>
                                </select>
                                {form.vendor === '__custom' && (
                                    <input className="form-input" style={{ marginTop: 8 }} placeholder="Enter vendor name"
                                        onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))} />
                                )}
                            </div>
                            <div className="form-group">
                                <label className="form-label">CPE Vendor (optional)</label>
                                <input className="form-input" placeholder="e.g., fortinet"
                                    value={form.cpe_vendor} onChange={e => setForm(f => ({ ...f, cpe_vendor: e.target.value }))} />
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Products (press Enter to add)</label>
                            <div className="tags-input">
                                {form.products.map((p, i) => (
                                    <span key={i} className="tag">{p} <span className="tag-remove" onClick={() => removeTag('products', i)}>✕</span></span>
                                ))}
                                <input placeholder="Add product..." value={productInput}
                                    onChange={e => setProductInput(e.target.value)}
                                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag('products', productInput, setProductInput); } }} />
                            </div>
                            <span className="text-xs text-muted">e.g., FortiGate, FortiEDR, FortiMail</span>
                        </div>

                        <div className="grid-2">
                            <div className="form-group">
                                <label className="form-label">Min CVSS Score: {form.min_cvss ?? 0}</label>
                                <input type="range" min="0" max="10" step="0.1"
                                    value={form.min_cvss ?? 0}
                                    onChange={e => setForm(f => ({ ...f, min_cvss: parseFloat(e.target.value) || null }))} />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Max CVSS Score: {form.max_cvss ?? 10}</label>
                                <input type="range" min="0" max="10" step="0.1"
                                    value={form.max_cvss ?? 10}
                                    onChange={e => setForm(f => ({ ...f, max_cvss: parseFloat(e.target.value) || null }))} />
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Severity Filter</label>
                            <div className="checkbox-group">
                                {SEVERITY_OPTIONS.map(sev => (
                                    <div key={sev}
                                        className={`checkbox-item ${form.severity_filter.includes(sev) ? 'selected' : ''}`}
                                        onClick={() => toggleSeverity(sev)}>
                                        <span className={`badge badge-${sev.toLowerCase()}`} style={{ padding: '2px 8px' }}>{sev}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Keywords Include (press Enter)</label>
                            <div className="tags-input">
                                {form.keywords_include.map((k, i) => (
                                    <span key={i} className="tag">{k} <span className="tag-remove" onClick={() => removeTag('keywords_include', i)}>✕</span></span>
                                ))}
                                <input placeholder="Add keyword..." value={kwIncInput}
                                    onChange={e => setKwIncInput(e.target.value)}
                                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag('keywords_include', kwIncInput, setKwIncInput); } }} />
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Keywords Exclude (press Enter)</label>
                            <div className="tags-input">
                                {form.keywords_exclude.map((k, i) => (
                                    <span key={i} className="tag" style={{ borderColor: 'rgba(239,68,68,0.3)', color: 'var(--error)' }}>
                                        {k} <span className="tag-remove" onClick={() => removeTag('keywords_exclude', i)}>✕</span>
                                    </span>
                                ))}
                                <input placeholder="Exclude keyword..." value={kwExcInput}
                                    onChange={e => setKwExcInput(e.target.value)}
                                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag('keywords_exclude', kwExcInput, setKwExcInput); } }} />
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Description</label>
                            <textarea className="form-textarea" placeholder="Optional description for this rule"
                                value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
                        </div>

                        <div className="modal-footer">
                            <button className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
                            <button className="btn btn-primary" onClick={handleSubmit}
                                disabled={!form.name || !form.vendor}>
                                {editing ? '💾 Save Changes' : '+ Create Filter'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
