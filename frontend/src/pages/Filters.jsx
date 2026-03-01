import React, { useState, useEffect, useRef } from 'react';
import {
    getFilters, createFilter, updateFilter, deleteFilter, toggleFilter,
    testFilterRule, exportFiltersYAML, importFiltersYAML, getQueryHelp
} from '../api';

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export default function Filters() {
    const [filters, setFilters] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showEditor, setShowEditor] = useState(false);
    const [editId, setEditId] = useState(null);
    const [testResult, setTestResult] = useState(null);
    const [showHelp, setShowHelp] = useState(false);
    const [helpData, setHelpData] = useState(null);
    const [importStatus, setImportStatus] = useState('');
    const fileInputRef = useRef(null);

    // Form state
    const [form, setForm] = useState({
        name: '',
        vendor: '',
        products: [],
        enabled: true,
        min_cvss: '',
        max_cvss: '',
        severity_filter: [],
        keywords_include: [],
        keywords_exclude: [],
        cpe_vendor: '',
        description: '',
        alert_on_modified: false,
        conditions: null,
        severity_mapping: null,
        include_unknown: false,
        pql_query: '',
    });
    const [productInput, setProductInput] = useState('');
    const [kwIncludeInput, setKwIncludeInput] = useState('');
    const [kwExcludeInput, setKwExcludeInput] = useState('');

    const fetchFilters = async () => {
        try {
            const data = await getFilters();
            setFilters(data);
        } catch (e) {
            console.error('Failed to load filters:', e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchFilters(); }, []);

    const resetForm = () => {
        setForm({
            name: '', vendor: '', products: [], enabled: true,
            min_cvss: '', max_cvss: '', severity_filter: [],
            keywords_include: [], keywords_exclude: [], cpe_vendor: '',
            description: '', alert_on_modified: false, conditions: null,
            severity_mapping: null, include_unknown: false, pql_query: '',
        });
        setProductInput('');
        setKwIncludeInput('');
        setKwExcludeInput('');
        setEditId(null);
        setTestResult(null);
    };

    const handleEdit = (filter) => {
        setForm({
            name: filter.name || '',
            vendor: filter.vendor || '',
            products: filter.products || [],
            enabled: filter.enabled !== false,
            min_cvss: filter.min_cvss ?? '',
            max_cvss: filter.max_cvss ?? '',
            severity_filter: filter.severity_filter || [],
            keywords_include: filter.keywords_include || [],
            keywords_exclude: filter.keywords_exclude || [],
            cpe_vendor: filter.cpe_vendor || '',
            description: filter.description || '',
            alert_on_modified: filter.alert_on_modified || false,
            conditions: filter.conditions || null,
            severity_mapping: filter.severity_mapping || null,
            include_unknown: filter.include_unknown || false,
            pql_query: filter.pql_query || '',
        });
        setEditId(filter.id);
        setShowEditor(true);
        setTestResult(null);
    };

    const handleSave = async () => {
        const payload = {
            ...form,
            min_cvss: form.min_cvss !== '' ? parseFloat(form.min_cvss) : null,
            max_cvss: form.max_cvss !== '' ? parseFloat(form.max_cvss) : null,
            // Merge products into keywords_include (products become default include keywords)
            keywords_include: [...new Set([...form.keywords_include, ...form.products.filter(p => !form.keywords_include.includes(p))])],
            severity_mapping: form.severity_mapping,
            include_unknown: form.include_unknown,
            pql_query: form.pql_query || null,
        };
        try {
            if (editId) {
                await updateFilter(editId, payload);
            } else {
                await createFilter(payload);
            }
            resetForm();
            setShowEditor(false);
            fetchFilters();
        } catch (e) {
            alert('Save failed: ' + e.message);
        }
    };

    const handleDelete = async (id) => {
        if (!confirm('Delete this filter rule?')) return;
        try {
            await deleteFilter(id);
            fetchFilters();
        } catch (e) {
            alert('Delete failed: ' + e.message);
        }
    };

    const handleToggle = async (id) => {
        try {
            await toggleFilter(id);
            fetchFilters();
        } catch (e) {
            alert('Toggle failed: ' + e.message);
        }
    };

    const addProduct = () => {
        const val = productInput.trim();
        if (val && !form.products.includes(val)) {
            setForm(f => ({ ...f, products: [...f.products, val] }));
        }
        setProductInput('');
    };

    const removeProduct = (p) => {
        setForm(f => ({ ...f, products: f.products.filter(x => x !== p) }));
    };

    const addKwInclude = () => {
        const val = kwIncludeInput.trim();
        if (val && !form.keywords_include.includes(val)) {
            setForm(f => ({ ...f, keywords_include: [...f.keywords_include, val] }));
        }
        setKwIncludeInput('');
    };

    const removeKwInclude = (kw) => {
        setForm(f => ({ ...f, keywords_include: f.keywords_include.filter(x => x !== kw) }));
    };

    const addKwExclude = () => {
        const val = kwExcludeInput.trim();
        if (val && !form.keywords_exclude.includes(val)) {
            setForm(f => ({ ...f, keywords_exclude: [...f.keywords_exclude, val] }));
        }
        setKwExcludeInput('');
    };

    const removeKwExclude = (kw) => {
        setForm(f => ({ ...f, keywords_exclude: f.keywords_exclude.filter(x => x !== kw) }));
    };

    const toggleSeverity = (sev) => {
        setForm(f => {
            const current = f.severity_filter || [];
            if (current.includes(sev)) {
                return { ...f, severity_filter: current.filter(s => s !== sev) };
            }
            return { ...f, severity_filter: [...current, sev] };
        });
    };

    const handleTestFilter = async () => {
        setTestResult({ loading: true });
        try {
            const result = await testFilterRule({
                name: form.name || 'Test Rule',
                vendor: form.vendor,
                products: form.products,
                min_cvss: form.min_cvss ? parseFloat(form.min_cvss) : null,
                max_cvss: form.max_cvss ? parseFloat(form.max_cvss) : null,
                severity_filter: form.severity_filter,
                keywords_include: [...form.keywords_include, ...form.products],
                keywords_exclude: form.keywords_exclude,
                cpe_vendor: form.cpe_vendor,
                alert_on_modified: form.alert_on_modified,
                conditions: form.conditions,
                send_test_alert: true,
            });
            setTestResult(result);
        } catch (e) {
            setTestResult({ status: 'error', message: e.message });
        }
    };

    const handleExportYAML = async () => {
        try {
            await exportFiltersYAML();
        } catch (e) {
            alert('Export failed: ' + e.message);
        }
    };

    const handleImportYAML = async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        setImportStatus('Importing...');
        try {
            const result = await importFiltersYAML(file);
            setImportStatus(`✅ ${result.message}`);
            fetchFilters();
        } catch (err) {
            setImportStatus(`❌ Import failed: ${err.message}`);
        }
        if (fileInputRef.current) fileInputRef.current.value = '';
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

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading filters...</div></div>;

    return (
        <div className="main-content animate-in">
            <div className="header" style={{ marginBottom: 24, padding: 0, background: 'transparent', border: 'none', height: 'auto' }}>
                <div>
                    <h1 className="header-title">Filter Rules</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Define CVE monitoring rules with advanced query support</p>
                </div>
                <div className="header-actions" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <button className="btn btn-primary" onClick={() => { resetForm(); setShowEditor(true); }}>+ New Filter</button>
                    <button className="btn btn-secondary" onClick={handleExportYAML}>📥 Export YAML</button>
                    <label className="btn btn-secondary" style={{ cursor: 'pointer' }}>
                        📤 Import YAML
                        <input type="file" accept=".yaml,.yml,.json" ref={fileInputRef}
                            onChange={handleImportYAML} style={{ display: 'none' }} />
                    </label>
                    <button className="btn btn-secondary" onClick={handleShowHelp} title="Query Language Help"
                        style={{ padding: '8px 12px', fontSize: 16 }}>❓</button>
                </div>
            </div>

            {importStatus && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: importStatus.includes('✅') ? 'var(--success)' : 'var(--error)' }}>
                    <span className="text-sm">{importStatus}</span>
                    <button className="text-sm" style={{ marginLeft: 12, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}
                        onClick={() => setImportStatus('')}>✕</button>
                </div>
            )}

            {/* Filter Editor */}
            {showEditor && (
                <div className="card mb-24">
                    <div className="card-header">
                        <div className="card-title">{editId ? 'Edit Filter Rule' : 'New Filter Rule'}</div>
                        <button className="btn btn-secondary" onClick={() => { setShowEditor(false); resetForm(); }}
                            style={{ padding: '4px 12px', fontSize: 12 }}>✕ Close</button>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, padding: '0 20px 20px' }}>
                        {/* Rule Name */}
                        <div className="form-group">
                            <label className="form-label">Rule Name *</label>
                            <input className="form-input" placeholder="e.g., Fortinet Critical Alerts"
                                value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
                        </div>
                        {/* Vendor (text input, NOT dropdown) */}
                        <div className="form-group">
                            <label className="form-label">Vendor</label>
                            <input className="form-input" placeholder="Type vendor name (e.g., fortinet, microsoft)"
                                value={form.vendor} onChange={e => setForm(f => ({ ...f, vendor: e.target.value }))} />
                        </div>

                        {/* Products + Include Keywords (merged) */}
                        <div className="form-group" style={{ gridColumn: 'span 2' }}>
                            <label className="form-label">Products & Include Keywords</label>
                            <p className="text-sm text-muted" style={{ marginBottom: 8 }}>Products are automatically included as keywords. Default keywords: CVE, vulnerability</p>
                            <div style={{ display: 'flex', gap: 8 }}>
                                <input className="form-input" placeholder="Add product/keyword..."
                                    value={productInput}
                                    onChange={e => setProductInput(e.target.value)}
                                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addProduct(); } }} />
                                <button className="btn btn-secondary" onClick={addProduct} style={{ whiteSpace: 'nowrap' }}>+ Add</button>
                            </div>
                            {form.products.length > 0 && (
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                                    {form.products.map(p => (
                                        <span key={p} className="badge" style={{
                                            background: 'rgba(124,58,237,0.2)', color: '#A855F7', padding: '4px 10px',
                                            cursor: 'pointer', borderRadius: 6,
                                        }} onClick={() => removeProduct(p)}>
                                            {p} ✕
                                        </span>
                                    ))}
                                </div>
                            )}
                        </div>

                        {/* Additional Include Keywords */}
                        <div className="form-group">
                            <label className="form-label">Extra Include Keywords</label>
                            <div style={{ display: 'flex', gap: 8 }}>
                                <input className="form-input" placeholder="Additional keyword..."
                                    value={kwIncludeInput}
                                    onChange={e => setKwIncludeInput(e.target.value)}
                                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addKwInclude(); } }} />
                                <button className="btn btn-secondary" onClick={addKwInclude}>+</button>
                            </div>
                            {form.keywords_include.length > 0 && (
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                                    {form.keywords_include.map(kw => (
                                        <span key={kw} className="badge" style={{
                                            background: 'rgba(74,222,128,0.2)', color: '#4ADE80', padding: '4px 10px',
                                            cursor: 'pointer', borderRadius: 6,
                                        }} onClick={() => removeKwInclude(kw)}>
                                            {kw} ✕
                                        </span>
                                    ))}
                                </div>
                            )}
                        </div>

                        {/* Exclude Keywords */}
                        <div className="form-group">
                            <label className="form-label">Exclude Keywords</label>
                            <div style={{ display: 'flex', gap: 8 }}>
                                <input className="form-input" placeholder="Keyword to exclude..."
                                    value={kwExcludeInput}
                                    onChange={e => setKwExcludeInput(e.target.value)}
                                    onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addKwExclude(); } }} />
                                <button className="btn btn-secondary" onClick={addKwExclude}>+</button>
                            </div>
                            {form.keywords_exclude.length > 0 && (
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                                    {form.keywords_exclude.map(kw => (
                                        <span key={kw} className="badge" style={{
                                            background: 'rgba(255,68,68,0.2)', color: '#FF4444', padding: '4px 10px',
                                            cursor: 'pointer', borderRadius: 6,
                                        }} onClick={() => removeKwExclude(kw)}>
                                            {kw} ✕
                                        </span>
                                    ))}
                                </div>
                            )}
                        </div>

                        {/* Severity Filter (checkboxes for multi-select) */}
                        <div className="form-group">
                            <label className="form-label">Severity Filter</label>
                            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                                {SEVERITIES.map(sev => (
                                    <label key={sev} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                                        <input type="checkbox" checked={(form.severity_filter || []).includes(sev)}
                                            onChange={() => toggleSeverity(sev)}
                                            style={{ accentColor: 'var(--purple-400)' }} />
                                        <span className={`badge badge-${sev.toLowerCase()}`}>{sev}</span>
                                    </label>
                                ))}
                            </div>
                        </div>

                        {/* CVSS Range */}
                        <div className="form-group">
                            <label className="form-label">CVSS Score Range</label>
                            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                <input className="form-input" type="number" min="0" max="10" step="0.1" placeholder="Min"
                                    value={form.min_cvss} onChange={e => setForm(f => ({ ...f, min_cvss: e.target.value }))}
                                    style={{ width: 100 }} />
                                <span className="text-muted">to</span>
                                <input className="form-input" type="number" min="0" max="10" step="0.1" placeholder="Max"
                                    value={form.max_cvss} onChange={e => setForm(f => ({ ...f, max_cvss: e.target.value }))}
                                    style={{ width: 100 }} />
                            </div>
                        </div>

                        {/* Alert on Modified / Updated CVE */}
                        <div className="form-group" style={{ gridColumn: 'span 2' }}>
                            <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
                                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                    <input type="checkbox" checked={form.alert_on_modified}
                                        onChange={e => setForm(f => ({ ...f, alert_on_modified: e.target.checked }))}
                                        style={{ accentColor: 'var(--purple-400)' }} />
                                    <span>🔄 Alert when CVE is updated/modified</span>
                                </label>
                                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                    <input type="checkbox" checked={form.enabled}
                                        onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))}
                                        style={{ accentColor: 'var(--purple-400)' }} />
                                    <span>✅ Enabled</span>
                                </label>
                            </div>
                        </div>

                        {/* Description */}
                        <div className="form-group" style={{ gridColumn: 'span 2' }}>
                            <label className="form-label">Description</label>
                            <textarea className="form-input" rows="2" placeholder="Optional description for this rule..."
                                value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
                        </div>

                        {/* Advanced: PQL Query */}
                        <div className="form-group" style={{ gridColumn: 'span 2' }}>
                            <label className="form-label">🔮 PQL Query (Advanced Filter Mode)</label>
                            <textarea className="form-textarea" style={{ fontFamily: 'monospace', fontSize: 12 }}
                                rows="3" placeholder='vendor:fortinet AND severity:CRITICAL,HIGH AND cvss:>7.0'
                                value={form.pql_query} onChange={e => setForm(f => ({ ...f, pql_query: e.target.value }))} />
                            <span className="text-xs text-muted">When set, PQL query takes precedence over standard fields. Supports: vendor, product, severity, cvss, kev, description.</span>
                        </div>

                        {/* Custom Severity Mapping */}
                        <div className="form-group">
                            <label className="form-label">Custom Severity Mapping</label>
                            <div style={{ fontSize: 12 - 1 }}>
                                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(level => (
                                    <div key={level} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                        <span style={{ width: 70, fontWeight: 600, fontSize: 11 }}>{level}:</span>
                                        <input className="form-input" type="number" step="0.1" min="0" max="10"
                                            style={{ width: 70, padding: '4px 6px', fontSize: 11 }}
                                            placeholder="Min"
                                            value={form.severity_mapping?.[level]?.min ?? ''}
                                            onChange={e => {
                                                const val = e.target.value;
                                                setForm(f => ({
                                                    ...f,
                                                    severity_mapping: {
                                                        ...(f.severity_mapping || {}),
                                                        [level]: { ...(f.severity_mapping?.[level] || {}), min: val ? parseFloat(val) : undefined }
                                                    }
                                                }));
                                            }} />
                                        <span className="text-xs text-muted">–</span>
                                        <input className="form-input" type="number" step="0.1" min="0" max="10"
                                            style={{ width: 70, padding: '4px 6px', fontSize: 11 }}
                                            placeholder="Max"
                                            value={form.severity_mapping?.[level]?.max ?? ''}
                                            onChange={e => {
                                                const val = e.target.value;
                                                setForm(f => ({
                                                    ...f,
                                                    severity_mapping: {
                                                        ...(f.severity_mapping || {}),
                                                        [level]: { ...(f.severity_mapping?.[level] || {}), max: val ? parseFloat(val) : undefined }
                                                    }
                                                }));
                                            }} />
                                    </div>
                                ))}
                            </div>
                            <span className="text-xs text-muted">Override default severity levels with custom CVSS score ranges.</span>
                        </div>

                        {/* Include Unknown */}
                        <div className="form-group">
                            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', marginTop: 24 }}>
                                <input type="checkbox" checked={form.include_unknown}
                                    onChange={e => setForm(f => ({ ...f, include_unknown: e.target.checked }))}
                                    style={{ accentColor: 'var(--purple-400)' }} />
                                <span>❓ Include CVEs without CVSS scores (UNKNOWN severity)</span>
                            </label>
                        </div>
                    </div>

                    {/* Actions */}
                    <div style={{ display: 'flex', gap: 12, padding: '0 20px 20px', flexWrap: 'wrap' }}>
                        <button className="btn btn-primary" onClick={handleSave}>
                            {editId ? '💾 Update Rule' : '✨ Create Rule'}
                        </button>
                        <button className="btn btn-secondary" onClick={handleTestFilter}>
                            🧪 Test Filter
                        </button>
                        <button className="btn btn-secondary" onClick={() => { setShowEditor(false); resetForm(); }}>
                            Cancel
                        </button>
                    </div>

                    {/* Test Result */}
                    {testResult && (
                        <div className="card" style={{ margin: '0 20px 20px', padding: 16, borderColor: 'var(--border-accent)' }}>
                            {testResult.loading ? (
                                <div className="loading"><div className="loading-spinner" />Testing filter...</div>
                            ) : testResult.status === 'error' ? (
                                <div style={{ color: 'var(--error)' }}>❌ {testResult.message}</div>
                            ) : (
                                <div>
                                    <div style={{ marginBottom: 8, fontWeight: 'bold', color: testResult.matches > 0 ? 'var(--success)' : 'var(--warning)' }}>
                                        {testResult.matches > 0 ? `✅ ${testResult.matches} matches found` : '⚠️ No matches'}
                                        <span className="text-muted text-sm" style={{ marginLeft: 8 }}>
                                            (tested against {testResult.total_tested} CVEs)
                                        </span>
                                    </div>
                                    {testResult.matched_cves && testResult.matched_cves.length > 0 && (
                                        <div className="table-container" style={{ maxHeight: 200, overflow: 'auto' }}>
                                            <table>
                                                <thead><tr><th>CVE ID</th><th>Vendor</th><th>Severity</th><th>CVSS</th></tr></thead>
                                                <tbody>
                                                    {testResult.matched_cves.map(c => (
                                                        <tr key={c.cve_id}>
                                                            <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{c.cve_id}</td>
                                                            <td>{c.vendor || '—'}</td>
                                                            <td><span className={`badge badge-${(c.severity || 'unknown').toLowerCase()}`}>{c.severity || 'N/A'}</span></td>
                                                            <td className="text-mono">{c.cvss_score ?? '—'}</td>
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
            )}

            {/* Filter List */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">Active Rules ({filters.length})</div>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Vendor</th>
                                <th>Products</th>
                                <th>Severity</th>
                                <th>CVSS Range</th>
                                <th>Modified Alert</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filters.map(f => (
                                <tr key={f.id}>
                                    <td style={{ fontWeight: 600 }}>{f.name}</td>
                                    <td className="text-sm">{f.vendor || '—'}</td>
                                    <td className="text-sm">
                                        {(f.products || []).length > 0
                                            ? (f.products || []).slice(0, 3).join(', ') + (f.products.length > 3 ? ` +${f.products.length - 3}` : '')
                                            : '—'}
                                    </td>
                                    <td>
                                        {(f.severity_filter || []).length > 0
                                            ? (f.severity_filter || []).map(s => (
                                                <span key={s} className={`badge badge-${s.toLowerCase()}`} style={{ marginRight: 4, fontSize: 10 }}>{s}</span>
                                            ))
                                            : '—'}
                                    </td>
                                    <td className="text-mono text-sm">
                                        {f.min_cvss != null || f.max_cvss != null
                                            ? `${f.min_cvss ?? 0} – ${f.max_cvss ?? 10}`
                                            : '—'}
                                    </td>
                                    <td>{f.alert_on_modified ? '🔄 Yes' : '—'}</td>
                                    <td>
                                        <span className={`badge ${f.enabled ? 'badge-success' : 'badge-error'}`}
                                            style={{ cursor: 'pointer' }} onClick={() => handleToggle(f.id)}>
                                            {f.enabled ? 'Active' : 'Disabled'}
                                        </span>
                                    </td>
                                    <td>
                                        <div style={{ display: 'flex', gap: 6 }}>
                                            <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }}
                                                onClick={() => handleEdit(f)}>✏️ Edit</button>
                                            <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12, color: 'var(--error)' }}
                                                onClick={() => handleDelete(f.id)}>🗑️</button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                            {filters.length === 0 && (
                                <tr><td colSpan="8" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>
                                    No filter rules yet. Create one or import from YAML.
                                </td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Query Help Modal */}
            {showHelp && (
                <div style={{
                    position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
                    background: 'rgba(0,0,0,0.7)', display: 'flex', justifyContent: 'center', alignItems: 'center',
                    zIndex: 1000, padding: 20,
                }} onClick={() => setShowHelp(false)}>
                    <div style={{
                        background: 'var(--card-bg)', borderRadius: 12, padding: 30,
                        maxWidth: 800, maxHeight: '80vh', overflow: 'auto', width: '100%',
                        border: '1px solid var(--border-accent)',
                    }} onClick={e => e.stopPropagation()}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20 }}>
                            <h2 style={{ color: 'var(--purple-400)', margin: 0 }}>📖 Query Language Reference</h2>
                            <button className="btn btn-secondary" onClick={() => setShowHelp(false)}
                                style={{ padding: '4px 12px' }}>✕</button>
                        </div>

                        {helpData ? (
                            <div>
                                <h3>Operators</h3>
                                <div className="table-container">
                                    <table>
                                        <thead><tr><th>Operator</th><th>Description</th></tr></thead>
                                        <tbody>
                                            {helpData.operators?.map(op => (
                                                <tr key={op.name}>
                                                    <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{op.name}</td>
                                                    <td className="text-sm">{op.description}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>

                                <h3 style={{ marginTop: 20 }}>Wildcards</h3>
                                <div style={{ padding: 16, background: 'rgba(0,0,0,0.2)', borderRadius: 8 }}>
                                    <p><code className="text-mono" style={{ color: '#A855F7' }}>*</code> — {helpData.wildcards?.['*']}</p>
                                    <p style={{ marginTop: 8 }}><code className="text-mono" style={{ color: '#A855F7' }}>?</code> — {helpData.wildcards?.['?']}</p>
                                </div>

                                <h3 style={{ marginTop: 20 }}>Case Sensitivity</h3>
                                <p className="text-sm text-muted">{helpData.case_sensitivity}</p>

                                <h3 style={{ marginTop: 20 }}>Available Fields</h3>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                    {helpData.fields?.map(f => (
                                        <span key={f} className="badge" style={{ background: 'rgba(124,58,237,0.2)', color: '#A855F7', padding: '4px 8px' }}>
                                            {f}
                                        </span>
                                    ))}
                                </div>

                                <h3 style={{ marginTop: 20 }}>Nested Query Example</h3>
                                <pre style={{ padding: 16, background: 'rgba(0,0,0,0.3)', borderRadius: 8, overflow: 'auto', fontSize: 12 }}>
                                    {JSON.stringify(helpData.nesting?.example, null, 2)}
                                </pre>
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
