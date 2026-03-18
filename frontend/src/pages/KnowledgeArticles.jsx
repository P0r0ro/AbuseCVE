import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { getKAs, getKA, deleteKA, createKA, exportKA, lookupCVEs, previewKA } from '../api';

const STEPS = ['Header', 'Indicators', 'Synopsis', 'Mitigation', 'References', 'Preview'];

export default function KnowledgeArticles() {
    const location = useLocation();
    const navigate = useNavigate();

    const [kas, setKAs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [status, setStatus] = useState('');

    // Wizard state
    const [wizardOpen, setWizardOpen] = useState(false);
    const [step, setStep] = useState(0);
    const [saving, setSaving] = useState(false);

    // Form fields
    const [title, setTitle] = useState('');
    const [cveIds, setCveIds] = useState([]);
    const [cveDetails, setCveDetails] = useState([]);
    const [severity, setSeverity] = useState('');
    const [pocAvailable, setPocAvailable] = useState(false);
    const [userInteraction, setUserInteraction] = useState(false);
    const [isBatch, setIsBatch] = useState(false);
    const [categories, setCategories] = useState([{ name: '', component: '', cve_ids: [], analysis: '' }]);
    const [mitigation, setMitigation] = useState('');
    const [references, setReferences] = useState(['']);

    // Preview
    const [previewHtml, setPreviewHtml] = useState('');
    const [viewKA, setViewKA] = useState(null);

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

    // Handle incoming CVE IDs from CVEDatabase page
    useEffect(() => {
        if (location.state?.selectedCveIds?.length) {
            openWizardWithCves(location.state.selectedCveIds);
            // Clear navigation state
            navigate(location.pathname, { replace: true, state: {} });
        }
    }, [location.state]);

    const openWizardWithCves = async (ids) => {
        resetWizard();
        setCveIds(ids);
        setIsBatch(ids.length > 1);
        setWizardOpen(true);
        setStep(0);
        // Look up CVE details
        try {
            const result = await lookupCVEs(ids);
            setCveDetails(result.cves || []);
            // Auto-fill severity from highest CVSS
            const scores = (result.cves || []).map(c => c.cvss_score).filter(Boolean);
            if (scores.length === 1) {
                setSeverity(String(scores[0]));
            } else if (scores.length > 1) {
                const min = Math.min(...scores);
                const max = Math.max(...scores);
                setSeverity(min === max ? String(max) : `${min} - ${max}`);
            }
            // Pre-populate categories with all CVE IDs for single mode
            if (ids.length === 1) {
                setCategories([{ name: '', component: '', cve_ids: [...ids], analysis: '' }]);
            } else {
                setCategories([{ name: '', component: '', cve_ids: [], analysis: '' }]);
            }
        } catch (e) {
            console.error('CVE lookup failed:', e);
        }
    };

    const resetWizard = () => {
        setStep(0);
        setTitle('');
        setCveIds([]);
        setCveDetails([]);
        setSeverity('');
        setPocAvailable(false);
        setUserInteraction(false);
        setIsBatch(false);
        setCategories([{ name: '', component: '', cve_ids: [], analysis: '' }]);
        setMitigation('');
        setReferences(['']);
        setPreviewHtml('');
    };

    const getWizardPayload = () => ({
        title: title || 'Vulnerability Report',
        cve_ids: cveIds,
        severity,
        poc_available: pocAvailable,
        user_interaction: userInteraction,
        is_batch: isBatch,
        categories: categories.filter(c => c.analysis || c.name),
        mitigation,
        references: references.filter(r => r.trim()),
    });

    const handlePreview = async () => {
        try {
            const result = await previewKA(getWizardPayload());
            setPreviewHtml(result.preview_html || '');
        } catch (e) {
            setStatus('Preview failed: ' + e.message);
        }
    };

    const handleSave = async () => {
        setSaving(true);
        try {
            await createKA(getWizardPayload());
            setStatus('Report saved successfully.');
            setWizardOpen(false);
            resetWizard();
            fetchKAs();
        } catch (e) {
            setStatus('Save failed: ' + e.message);
        } finally {
            setSaving(false);
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

    const handleView = async (ka) => {
        try {
            const full = await getKA(ka.id);
            setViewKA(full);
        } catch (e) {
            setViewKA(ka);
        }
    };

    const handleCopyForCRM = async (ka) => {
        // Get the CRM (light) HTML from the full KA
        let html = ka.html_content || ka.content || '';
        if (!html && ka.id) {
            try {
                const full = await getKA(ka.id);
                html = full.html_content || full.content || '';
            } catch (e) { /* fallback */ }
        }
        if (!html) {
            setStatus('No content to copy.');
            return;
        }
        // Copy as HTML to clipboard for rich paste into CRM
        try {
            const blob = new Blob([html], { type: 'text/html' });
            const item = new ClipboardItem({ 'text/html': blob, 'text/plain': new Blob([html.replace(/<[^>]*>/g, '')], { type: 'text/plain' }) });
            await navigator.clipboard.write([item]);
            setStatus('Copied to clipboard with formatting (ready for CRM paste).');
        } catch (e) {
            // Fallback: plain text
            navigator.clipboard.writeText(html.replace(/<[^>]*>/g, ''));
            setStatus('Copied as plain text (rich copy not supported in this browser).');
        }
    };

    const handleExport = async (kaId) => {
        try {
            await exportKA(kaId);
        } catch (e) {
            alert('Export failed: ' + e.message);
        }
    };

    // Category helpers
    const updateCategory = (idx, field, value) => {
        setCategories(prev => prev.map((c, i) => i === idx ? { ...c, [field]: value } : c));
    };
    const addCategory = () => {
        setCategories(prev => [...prev, { name: '', component: '', cve_ids: [], analysis: '' }]);
    };
    const removeCategory = (idx) => {
        if (categories.length <= 1) return;
        setCategories(prev => prev.filter((_, i) => i !== idx));
    };
    const toggleCveCat = (catIdx, cveId) => {
        setCategories(prev => prev.map((c, i) => {
            if (i !== catIdx) return c;
            const ids = c.cve_ids.includes(cveId) ? c.cve_ids.filter(id => id !== cveId) : [...c.cve_ids, cveId];
            return { ...c, cve_ids: ids };
        }));
    };

    // Reference helpers
    const updateRef = (idx, val) => {
        setReferences(prev => prev.map((r, i) => i === idx ? val : r));
    };
    const addRef = () => setReferences(prev => [...prev, '']);
    const removeRef = (idx) => {
        if (references.length <= 1) return;
        setReferences(prev => prev.filter((_, i) => i !== idx));
    };

    // Step navigation
    const goNext = () => {
        if (step === STEPS.length - 2) handlePreview(); // trigger preview before showing
        setStep(s => Math.min(s + 1, STEPS.length - 1));
    };
    const goBack = () => setStep(s => Math.max(s - 1, 0));

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading knowledge articles...</div></div>;

    return (
        <div className="main-content animate-in">
            <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                    <h1 className="header-title">Knowledge Articles</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Compose structured vulnerability reports for CRM distribution</p>
                </div>
                {!wizardOpen && (
                    <button className="btn btn-primary" onClick={() => { resetWizard(); setWizardOpen(true); }}>
                        + New Report
                    </button>
                )}
            </div>

            {status && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: status.includes('failed') || status.includes('Failed') ? 'var(--error)' : 'var(--success)' }}>
                    <span className="text-sm">{status}</span>
                    <button className="text-sm" style={{ marginLeft: 12, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}
                        onClick={() => setStatus('')}>x</button>
                </div>
            )}

            {/* ── Wizard ── */}
            {wizardOpen && (
                <div className="card mb-24">
                    <div className="card-header">
                        <div className="card-title">Vulnerability Report Wizard</div>
                        <button className="btn btn-secondary btn-sm" onClick={() => { setWizardOpen(false); resetWizard(); }}>x Cancel</button>
                    </div>

                    {/* Step indicator */}
                    <div style={{ display: 'flex', gap: 4, marginBottom: 24, padding: '0 4px' }}>
                        {STEPS.map((s, i) => (
                            <div key={s} style={{ flex: 1, textAlign: 'center' }}>
                                <div style={{
                                    height: 4, borderRadius: 2, marginBottom: 6,
                                    background: i <= step ? 'var(--purple-500)' : 'var(--bg-secondary)',
                                    transition: 'background 300ms',
                                }} />
                                <span className="text-xs" style={{ color: i === step ? 'var(--purple-400)' : 'var(--text-muted)', fontWeight: i === step ? 700 : 400 }}>{s}</span>
                            </div>
                        ))}
                    </div>

                    <div style={{ minHeight: 300 }}>
                        {/* Step 0: Header */}
                        {step === 0 && (
                            <div>
                                <div className="form-group">
                                    <label className="form-label">Report Title</label>
                                    <input className="form-input" placeholder='e.g. "Microsoft Outlook RCE" or "Cisco 2026 Semiannual Batch"'
                                        value={title} onChange={e => setTitle(e.target.value)} />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Associated CVE IDs</label>
                                    <div className="tags-input" onClick={() => document.getElementById('cve-tag-input')?.focus()}>
                                        {cveIds.map(id => (
                                            <span key={id} className="tag">
                                                {id}
                                                <span className="tag-remove" onClick={() => setCveIds(prev => prev.filter(c => c !== id))}>x</span>
                                            </span>
                                        ))}
                                        <input id="cve-tag-input" placeholder="Type CVE ID and press Enter"
                                            onKeyDown={e => {
                                                if (e.key === 'Enter' && e.target.value.trim()) {
                                                    e.preventDefault();
                                                    const val = e.target.value.trim().toUpperCase();
                                                    if (!cveIds.includes(val)) {
                                                        setCveIds(prev => [...prev, val]);
                                                    }
                                                    e.target.value = '';
                                                }
                                            }} />
                                    </div>
                                    <span className="text-xs text-muted" style={{ marginTop: 4, display: 'block' }}>
                                        {cveIds.length} CVE(s) selected
                                        {cveDetails.length > 0 && ` (${cveDetails.length} found in database)`}
                                    </span>
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Severity</label>
                                    <input className="form-input" placeholder='e.g. "9.8" or "4.3 - 8.6" or "Critical"'
                                        value={severity} onChange={e => setSeverity(e.target.value)} />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Report Mode</label>
                                    <div style={{ display: 'flex', gap: 12 }}>
                                        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', padding: '8px 16px', background: !isBatch ? 'rgba(124,58,237,0.15)' : 'var(--bg-secondary)', border: `1px solid ${!isBatch ? 'var(--border-accent)' : 'var(--border-subtle)'}`, borderRadius: 8 }}>
                                            <input type="radio" name="mode" checked={!isBatch} onChange={() => setIsBatch(false)} />
                                            <span className="text-sm">Single CVE</span>
                                        </label>
                                        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', padding: '8px 16px', background: isBatch ? 'rgba(124,58,237,0.15)' : 'var(--bg-secondary)', border: `1px solid ${isBatch ? 'var(--border-accent)' : 'var(--border-subtle)'}`, borderRadius: 8 }}>
                                            <input type="radio" name="mode" checked={isBatch} onChange={() => setIsBatch(true)} />
                                            <span className="text-sm">Batch (multiple CVEs)</span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Step 1: Indicators */}
                        {step === 1 && (
                            <div>
                                <p className="text-sm text-muted mb-16">Quick indicators for this vulnerability report.</p>
                                <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                                        <span className="text-sm" style={{ fontWeight: 600 }}>PoC Available?</span>
                                        <label className="toggle">
                                            <input type="checkbox" checked={pocAvailable} onChange={e => setPocAvailable(e.target.checked)} />
                                            <span className="toggle-slider" />
                                        </label>
                                        <span className="text-sm" style={{ color: pocAvailable ? 'var(--warning)' : 'var(--text-muted)' }}>
                                            {pocAvailable ? 'Yes' : 'No'}
                                        </span>
                                    </div>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                                        <span className="text-sm" style={{ fontWeight: 600 }}>User Interaction Required?</span>
                                        <label className="toggle">
                                            <input type="checkbox" checked={userInteraction} onChange={e => setUserInteraction(e.target.checked)} />
                                            <span className="toggle-slider" />
                                        </label>
                                        <span className="text-sm" style={{ color: userInteraction ? 'var(--info)' : 'var(--text-muted)' }}>
                                            {userInteraction ? 'Yes' : 'No'}
                                        </span>
                                    </div>
                                </div>
                                {/* Show selected CVE summary */}
                                {cveDetails.length > 0 && (
                                    <div style={{ marginTop: 24 }}>
                                        <p className="text-sm" style={{ fontWeight: 600, marginBottom: 8 }}>Selected CVEs Summary</p>
                                        <div className="table-container" style={{ maxHeight: 250, overflow: 'auto' }}>
                                            <table>
                                                <thead><tr><th>CVE ID</th><th>Vendor</th><th>Severity</th><th>CVSS</th></tr></thead>
                                                <tbody>
                                                    {cveDetails.map(c => (
                                                        <tr key={c.cve_id}>
                                                            <td className="text-mono" style={{ color: 'var(--purple-400)' }}>{c.cve_id}</td>
                                                            <td className="text-sm">{c.vendor || '-'}</td>
                                                            <td><span className={`badge badge-${(c.severity || 'unknown').toLowerCase()}`}>{c.severity || 'N/A'}</span></td>
                                                            <td className="text-mono">{c.cvss_score ?? '-'}</td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Step 2: Synopsis (Categories) */}
                        {step === 2 && (
                            <div>
                                <p className="text-sm text-muted mb-16">
                                    {isBatch
                                        ? 'Group CVEs into technical categories (e.g. DoS, RCE, Bypass) and provide analysis for each.'
                                        : 'Provide the technical analysis / synopsis for this vulnerability.'}
                                </p>
                                {categories.map((cat, catIdx) => (
                                    <div key={catIdx} style={{
                                        padding: 16, marginBottom: 16,
                                        background: 'var(--bg-secondary)', borderRadius: 10,
                                        border: '1px solid var(--border-subtle)',
                                    }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                                            <span className="text-sm" style={{ fontWeight: 700, color: 'var(--purple-400)' }}>
                                                {isBatch ? `Category ${catIdx + 1}` : 'Analysis'}
                                            </span>
                                            {isBatch && categories.length > 1 && (
                                                <button className="btn btn-secondary btn-sm" style={{ color: 'var(--error)', padding: '2px 10px' }}
                                                    onClick={() => removeCategory(catIdx)}>Remove</button>
                                            )}
                                        </div>
                                        {isBatch && (
                                            <>
                                                <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
                                                    <div style={{ flex: 1 }}>
                                                        <label className="form-label">Category Name</label>
                                                        <input className="form-input" placeholder='e.g. "Denial of Service (DoS)"'
                                                            value={cat.name} onChange={e => updateCategory(catIdx, 'name', e.target.value)} />
                                                    </div>
                                                    <div style={{ flex: 1 }}>
                                                        <label className="form-label">Component</label>
                                                        <input className="form-input" placeholder='e.g. "VPN & SSL"'
                                                            value={cat.component} onChange={e => updateCategory(catIdx, 'component', e.target.value)} />
                                                    </div>
                                                </div>
                                                <div style={{ marginBottom: 12 }}>
                                                    <label className="form-label">CVEs in this group</label>
                                                    <div className="checkbox-group">
                                                        {cveIds.map(id => (
                                                            <div key={id}
                                                                className={`checkbox-item ${cat.cve_ids.includes(id) ? 'selected' : ''}`}
                                                                onClick={() => toggleCveCat(catIdx, id)}>
                                                                <input type="checkbox" checked={cat.cve_ids.includes(id)} readOnly style={{ pointerEvents: 'none' }} />
                                                                <span className="text-mono text-xs">{id}</span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            </>
                                        )}
                                        <div>
                                            <label className="form-label">Technical Analysis</label>
                                            <textarea className="form-textarea" rows={6} style={{ minHeight: 120 }}
                                                placeholder="Provide the detailed technical analysis here..."
                                                value={cat.analysis} onChange={e => updateCategory(catIdx, 'analysis', e.target.value)} />
                                        </div>
                                    </div>
                                ))}
                                {isBatch && (
                                    <button className="btn btn-secondary" onClick={addCategory}>+ Add Category</button>
                                )}
                            </div>
                        )}

                        {/* Step 3: Mitigation */}
                        {step === 3 && (
                            <div>
                                <div className="form-group">
                                    <label className="form-label">Mitigation / Remediation Steps</label>
                                    <textarea className="form-textarea" rows={8} style={{ minHeight: 180 }}
                                        placeholder="Describe the recommended mitigation strategy, software updates, workarounds..."
                                        value={mitigation} onChange={e => setMitigation(e.target.value)} />
                                </div>
                            </div>
                        )}

                        {/* Step 4: References */}
                        {step === 4 && (
                            <div>
                                <label className="form-label">Reference URLs</label>
                                {references.map((ref, i) => (
                                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                                        <input className="form-input" placeholder="https://advisory.vendor.com/..."
                                            value={ref} onChange={e => updateRef(i, e.target.value)} />
                                        {references.length > 1 && (
                                            <button className="btn btn-secondary btn-sm" style={{ color: 'var(--error)' }}
                                                onClick={() => removeRef(i)}>x</button>
                                        )}
                                    </div>
                                ))}
                                <button className="btn btn-secondary btn-sm" onClick={addRef}>+ Add Reference</button>
                            </div>
                        )}

                        {/* Step 5: Preview */}
                        {step === 5 && (
                            <div>
                                <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
                                    <button className="btn btn-secondary btn-sm" onClick={handlePreview}>Refresh Preview</button>
                                    <button className="btn btn-secondary btn-sm" onClick={() => {
                                        // Copy the CRM HTML
                                        const payload = getWizardPayload();
                                        previewKA(payload).then(r => {
                                            const html = r.html_content || '';
                                            const blob = new Blob([html], { type: 'text/html' });
                                            const item = new ClipboardItem({
                                                'text/html': blob,
                                                'text/plain': new Blob([html.replace(/<[^>]*>/g, '')], { type: 'text/plain' }),
                                            });
                                            navigator.clipboard.write([item]).then(
                                                () => setStatus('Copied CRM-ready report to clipboard.'),
                                                () => setStatus('Copy failed — try the Export button instead.')
                                            );
                                        });
                                    }}>Copy for CRM</button>
                                </div>
                                {previewHtml ? (
                                    <div style={{
                                        background: 'var(--bg-secondary)', borderRadius: 10, padding: 0,
                                        border: '1px solid var(--border-subtle)', overflow: 'hidden',
                                    }}>
                                        <div dangerouslySetInnerHTML={{ __html: previewHtml }} />
                                    </div>
                                ) : (
                                    <div className="loading"><div className="loading-spinner" /> Loading preview...</div>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Navigation buttons */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 24, paddingTop: 16, borderTop: '1px solid var(--border-subtle)' }}>
                        <button className="btn btn-secondary" onClick={goBack} disabled={step === 0}>Back</button>
                        <div style={{ display: 'flex', gap: 8 }}>
                            {step === STEPS.length - 1 ? (
                                <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                                    {saving ? 'Saving...' : 'Save Report'}
                                </button>
                            ) : (
                                <button className="btn btn-primary" onClick={goNext}>
                                    Next: {STEPS[step + 1]}
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* ── View KA Modal ── */}
            {viewKA && (
                <div className="modal-overlay" onClick={() => setViewKA(null)}>
                    <div className="modal" style={{ maxWidth: 800, maxHeight: '90vh' }} onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h2 className="modal-title" style={{ fontSize: 16 }}>{viewKA.title}</h2>
                            <button className="modal-close" onClick={() => setViewKA(null)}>x</button>
                        </div>
                        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
                            <button className="btn btn-primary btn-sm" onClick={() => handleCopyForCRM(viewKA)}>Copy for CRM</button>
                            <button className="btn btn-secondary btn-sm" onClick={() => handleExport(viewKA.id)}>Export HTML</button>
                        </div>
                        <div style={{ overflow: 'auto', maxHeight: '60vh' }}>
                            {viewKA.preview_html ? (
                                <div dangerouslySetInnerHTML={{ __html: viewKA.preview_html }} />
                            ) : viewKA.content ? (
                                <div dangerouslySetInnerHTML={{ __html: viewKA.content }} />
                            ) : (
                                <p className="text-muted">No content available.</p>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* ── Saved Articles Table ── */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title">Saved Reports ({kas.length})</div>
                </div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Title</th>
                                <th>CVE IDs</th>
                                <th>Severity</th>
                                <th>Type</th>
                                <th>Author</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {kas.map(ka => (
                                <tr key={ka.id}>
                                    <td style={{ fontWeight: 600, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ka.title}</td>
                                    <td className="text-mono text-sm" style={{ color: 'var(--purple-400)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                        {(ka.cve_ids || []).length > 3
                                            ? `${ka.cve_ids.slice(0, 3).join(', ')} +${ka.cve_ids.length - 3} more`
                                            : (ka.cve_ids || []).join(', ')}
                                    </td>
                                    <td className="text-sm">{ka.severity_assessment || '-'}</td>
                                    <td><span className={`badge ${ka.is_batch ? 'badge-info' : 'badge-success'}`}>{ka.is_batch ? 'Batch' : 'Single'}</span></td>
                                    <td className="text-sm">{ka.author || '-'}</td>
                                    <td className="text-sm text-muted">{ka.created_at ? new Date(ka.created_at).toLocaleDateString() : '-'}</td>
                                    <td>
                                        <div style={{ display: 'flex', gap: 6 }}>
                                            <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }}
                                                onClick={() => handleView(ka)} title="View report">View</button>
                                            <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }}
                                                onClick={() => handleCopyForCRM(ka)} title="Copy for CRM">Copy</button>
                                            <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }}
                                                onClick={() => handleExport(ka.id)} title="Export HTML file">Export</button>
                                            {ka.report_data && (
                                                <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }}
                                                    onClick={() => {
                                                        // Re-open wizard with existing data
                                                        const d = ka.report_data;
                                                        resetWizard();
                                                        setTitle(d.title || ka.title);
                                                        setCveIds(d.cve_ids || ka.cve_ids || []);
                                                        setSeverity(d.severity || ka.severity_assessment || '');
                                                        setPocAvailable(d.poc_available || false);
                                                        setUserInteraction(d.user_interaction || false);
                                                        setIsBatch(d.is_batch || false);
                                                        setCategories(d.categories?.length ? d.categories : [{ name: '', component: '', cve_ids: [], analysis: '' }]);
                                                        setMitigation(d.mitigation || '');
                                                        setReferences(d.references?.length ? d.references : ['']);
                                                        setWizardOpen(true);
                                                        setStep(0);
                                                        // Look up CVE details
                                                        if (d.cve_ids?.length) lookupCVEs(d.cve_ids).then(r => setCveDetails(r.cves || [])).catch(() => {});
                                                    }} title="Edit / Clone">Edit</button>
                                            )}
                                            <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12, color: 'var(--error)' }}
                                                onClick={() => handleDelete(ka.id)} title="Delete">Del</button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                            {kas.length === 0 && (
                                <tr><td colSpan="7" className="text-muted" style={{ textAlign: 'center', padding: 40 }}>
                                    No reports yet. Select CVEs from the CVE Database or click "New Report" to create one.
                                </td></tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
