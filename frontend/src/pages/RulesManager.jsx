import React, { useState, useEffect } from 'react';
import {
    getFilters,
    testFilterRule,
    reloadFilterRules,
    getQueryHelp,
    createFilterRule,
    updateFilterRule,
    deleteFilterRule,
    getPqlAutocomplete,
} from '../api';
import RefineModal from '../components/RefineModal';
import { usePermissions } from '../permissions';
import PqlInput from '../components/PqlInput';

const WIZARD_STEPS = ['Basics', 'Field Selectors', 'Review'];
const SEVERITY_OPTS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function RulesManager() {
    const { isAdmin, canPerform } = usePermissions();
    const canCreate = canPerform('rule_create');
    const canRefine = canPerform('rule_refine');
    const canEdit = canPerform('rule_edit');
    const canDelete = canPerform('rule_delete');

    const [rules, setRules] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showHelp, setShowHelp] = useState(false);
    const [helpData, setHelpData] = useState(null);
    const [testingId, setTestingId] = useState(null);
    const [testResults, setTestResults] = useState({});
    const [expandedId, setExpandedId] = useState(null);
    const [reloadMsg, setReloadMsg] = useState('');
    const [refineRule, setRefineRule] = useState(null);

    // ── Edit modal state ─────────────────────────
    const [editRule, setEditRule] = useState(null);   // full rule being edited
    const [editName, setEditName] = useState('');
    const [editDesc, setEditDesc] = useState('');
    const [editPql, setEditPql] = useState('');
    const [editEnabled, setEditEnabled] = useState(true);
    const [editAlertMod, setEditAlertMod] = useState(false);
    const [editSaving, setEditSaving] = useState(false);
    const [editMsg, setEditMsg] = useState('');

    // ── Delete confirmation ──────────────────────
    const [deleteRule, setDeleteRule] = useState(null);
    const [deleting, setDeleting] = useState(false);
    const [deleteMsg, setDeleteMsg] = useState('');

    // ── Rule Wizard state ────────────────────────
    const [wizardOpen, setWizardOpen] = useState(false);
    const [wizardStep, setWizardStep] = useState(0);
    const [wizardSaving, setWizardSaving] = useState(false);
    const [wizardMsg, setWizardMsg] = useState('');
    const [wizName, setWizName] = useState('');
    const [wizDesc, setWizDesc] = useState('');
    const [wizVendor, setWizVendor] = useState('');
    const [wizProduct, setWizProduct] = useState('');
    const [wizDescKeyword, setWizDescKeyword] = useState('');
    const [wizSeverity, setWizSeverity] = useState([]);
    const [wizCvssMin, setWizCvssMin] = useState('');
    const [wizKev, setWizKev] = useState(false);

    // ── Advanced Mode ────────────────────────────
    const [advancedOpen, setAdvancedOpen] = useState(false);
    const [advName, setAdvName] = useState('');
    const [advDesc, setAdvDesc] = useState('');
    const [advPql, setAdvPql] = useState('');
    const [advSaving, setAdvSaving] = useState(false);
    const [advMsg, setAdvMsg] = useState('');

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

    // ── Wizard — build PQL from field selectors ─────
    const buildWizardPql = () => {
        const parts = [];
        if (wizVendor.trim()) parts.push(`vendor:${wizVendor.trim()}`);
        if (wizProduct.trim()) parts.push(`product:${wizProduct.trim()}`);
        if (wizDescKeyword.trim()) parts.push(`description:${wizDescKeyword.trim()}`);
        if (wizSeverity.length) parts.push(`severity:${wizSeverity.join(',')}`);
        if (wizCvssMin.trim()) parts.push(`cvss:>=${wizCvssMin.trim()}`);
        if (wizKev) parts.push('kev:true');
        return parts.join(' AND ');
    };

    const resetWizard = () => {
        setWizardStep(0);
        setWizName('');
        setWizDesc('');
        setWizVendor('');
        setWizProduct('');
        setWizDescKeyword('');
        setWizSeverity([]);
        setWizCvssMin('');
        setWizKev(false);
        setWizardMsg('');
    };

    const handleWizardSave = async () => {
        const pql = buildWizardPql();
        if (!wizName.trim() || !pql) {
            setWizardMsg('Name and at least one selector are required.');
            return;
        }
        setWizardSaving(true);
        try {
            const result = await createFilterRule({
                name: wizName.trim(),
                description: wizDesc.trim(),
                pql,
                enabled: true,
                alert_on_modified: false,
            });
            setWizardMsg(`Rule ${result.rule_id} saved and reloaded.`);
            await fetchRules();
            setTimeout(() => {
                setWizardOpen(false);
                resetWizard();
            }, 1200);
        } catch (e) {
            setWizardMsg('Save failed: ' + e.message);
        } finally {
            setWizardSaving(false);
        }
    };

    const openEditModal = (rule) => {
        setEditRule(rule);
        setEditName(rule.name || '');
        setEditDesc(rule.description || '');
        setEditPql(rule.pql || '');
        setEditEnabled(rule.enabled !== false);
        setEditAlertMod(!!rule.alert_on_modified);
        setEditMsg('');
    };

    const closeEditModal = () => {
        setEditRule(null);
        setEditMsg('');
        setEditSaving(false);
    };

    const handleEditSave = async () => {
        if (!editRule) return;
        if (!editName.trim() || !editPql.trim()) {
            setEditMsg('Name and PQL are required.');
            return;
        }
        setEditSaving(true);
        setEditMsg('');
        try {
            await updateFilterRule(editRule.id, {
                name: editName.trim(),
                description: editDesc,
                pql: editPql.trim(),
                enabled: editEnabled,
                alert_on_modified: editAlertMod,
            });
            setEditMsg(`Rule ${editRule.id} updated and reloaded.`);
            await fetchRules();
            setTimeout(closeEditModal, 900);
        } catch (e) {
            setEditMsg('Save failed: ' + e.message);
        } finally {
            setEditSaving(false);
        }
    };

    const handleDeleteConfirm = async () => {
        if (!deleteRule) return;
        setDeleting(true);
        setDeleteMsg('');
        try {
            await deleteFilterRule(deleteRule.id);
            setDeleteMsg(`Rule ${deleteRule.id} deleted.`);
            await fetchRules();
            setTimeout(() => {
                setDeleteRule(null);
                setDeleteMsg('');
                setDeleting(false);
            }, 800);
        } catch (e) {
            setDeleteMsg('Delete failed: ' + e.message);
            setDeleting(false);
        }
    };

    const handleAdvancedSave = async () => {
        if (!advName.trim() || !advPql.trim()) {
            setAdvMsg('Name and PQL are required.');
            return;
        }
        setAdvSaving(true);
        try {
            const result = await createFilterRule({
                name: advName.trim(),
                description: advDesc.trim(),
                pql: advPql.trim(),
                enabled: true,
                alert_on_modified: false,
            });
            setAdvMsg(`Rule ${result.rule_id} saved and reloaded.`);
            await fetchRules();
            setTimeout(() => {
                setAdvancedOpen(false);
                setAdvName('');
                setAdvDesc('');
                setAdvPql('');
                setAdvMsg('');
            }, 1200);
        } catch (e) {
            setAdvMsg('Save failed: ' + e.message);
        } finally {
            setAdvSaving(false);
        }
    };

    const toggleSev = (sev) => {
        setWizSeverity(prev => prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]);
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading rules...</div></div>;

    return (
        <div className="main-content animate-in">
            {/* Header */}
            <div className="header" style={{ marginBottom: 24, padding: 0, background: 'transparent', border: 'none', height: 'auto' }}>
                <div>
                    <h1 className="header-title">Rules Manager</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>
                        File-based detection rules loaded from <code>abusecve_filters.yaml</code>. Build with the wizard or edit the raw YAML on disk.
                    </p>
                </div>
                <div className="header-actions" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {canCreate && (
                        <>
                            <button className="btn btn-primary" onClick={() => { resetWizard(); setWizardOpen(true); setAdvancedOpen(false); }}>+ Rule Wizard</button>
                            <button className="btn btn-secondary" onClick={() => { setAdvancedOpen(true); setWizardOpen(false); }}>Advanced Mode</button>
                        </>
                    )}
                    <button className="btn btn-secondary" onClick={handleReload}>Reload Rules</button>
                    <button className="btn btn-secondary" onClick={handleShowHelp} title="PQL Syntax Reference"
                        style={{ padding: '8px 12px', fontSize: 14 }}>? PQL Help</button>
                </div>
            </div>

            {reloadMsg && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: 'var(--border-accent)' }}>
                    <span className="text-sm">{reloadMsg}</span>
                </div>
            )}

            {/* ── Rule Wizard ── */}
            {wizardOpen && canCreate && (
                <div className="card mb-24">
                    <div className="card-header">
                        <div className="card-title">Rule Wizard</div>
                        <button className="btn btn-secondary btn-sm" onClick={() => { setWizardOpen(false); resetWizard(); }}>x Cancel</button>
                    </div>
                    <div style={{ padding: 16 }}>
                        {/* Step indicator */}
                        <div style={{ display: 'flex', gap: 4, marginBottom: 18 }}>
                            {WIZARD_STEPS.map((s, i) => (
                                <div key={s} style={{ flex: 1, textAlign: 'center' }}>
                                    <div style={{ height: 4, borderRadius: 2, marginBottom: 6, background: i <= wizardStep ? 'var(--purple-500)' : 'var(--bg-secondary)' }} />
                                    <span className="text-xs" style={{ color: i === wizardStep ? 'var(--purple-400)' : 'var(--text-muted)', fontWeight: i === wizardStep ? 700 : 400 }}>{s}</span>
                                </div>
                            ))}
                        </div>

                        {wizardStep === 0 && (
                            <div>
                                <div className="form-group">
                                    <label className="form-label">Rule Name</label>
                                    <input className="form-input" value={wizName} onChange={e => setWizName(e.target.value)} placeholder='e.g. "Critical Microsoft RCEs"' />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Description</label>
                                    <textarea className="form-textarea" rows={3} value={wizDesc} onChange={e => setWizDesc(e.target.value)} placeholder="What this rule monitors…" />
                                </div>
                            </div>
                        )}

                        {wizardStep === 1 && (
                            <div>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                                    <div className="form-group">
                                        <label className="form-label">Vendor</label>
                                        <input className="form-input" value={wizVendor} onChange={e => setWizVendor(e.target.value)} placeholder="e.g. microsoft" />
                                    </div>
                                    <div className="form-group">
                                        <label className="form-label">Product</label>
                                        <input className="form-input" value={wizProduct} onChange={e => setWizProduct(e.target.value)} placeholder="e.g. exchange" />
                                    </div>
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Description Keyword</label>
                                    <input
                                        className="form-input"
                                        value={wizDescKeyword}
                                        onChange={e => setWizDescKeyword(e.target.value)}
                                        placeholder='e.g. "remote code execution" or rce'
                                    />
                                    <div className="text-xs text-muted" style={{ marginTop: 4 }}>
                                        Full-text search against the CVE description. Matches are case-insensitive.
                                    </div>
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Severity</label>
                                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                        {SEVERITY_OPTS.map(s => (
                                            <label key={s} style={{
                                                display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px',
                                                background: wizSeverity.includes(s) ? 'rgba(124,58,237,0.2)' : 'var(--bg-secondary)',
                                                border: `1px solid ${wizSeverity.includes(s) ? 'var(--border-accent)' : 'var(--border-subtle)'}`,
                                                borderRadius: 8, cursor: 'pointer',
                                            }}>
                                                <input type="checkbox" checked={wizSeverity.includes(s)} onChange={() => toggleSev(s)} />
                                                <span className="text-sm">{s}</span>
                                            </label>
                                        ))}
                                    </div>
                                </div>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, alignItems: 'end' }}>
                                    <div className="form-group">
                                        <label className="form-label">Minimum CVSS</label>
                                        <input className="form-input" type="number" min="0" max="10" step="0.1" value={wizCvssMin} onChange={e => setWizCvssMin(e.target.value)} placeholder="e.g. 7.0" />
                                    </div>
                                    <div className="form-group">
                                        <label className="form-label">KEV Only</label>
                                        <label style={{
                                            display: 'flex', alignItems: 'center', gap: 10,
                                            padding: '10px 14px',
                                            background: wizKev ? 'rgba(124,58,237,0.2)' : 'var(--bg-secondary)',
                                            border: `1px solid ${wizKev ? 'var(--border-accent)' : 'var(--border-subtle)'}`,
                                            borderRadius: 8, cursor: 'pointer',
                                        }}>
                                            <input
                                                type="checkbox"
                                                checked={wizKev}
                                                onChange={e => setWizKev(e.target.checked)}
                                                style={{ width: 16, height: 16, accentColor: 'var(--purple-500)' }}
                                            />
                                            <span className="text-sm">Only include CVEs in CISA KEV catalog</span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                        )}

                        {wizardStep === 2 && (
                            <div>
                                <p className="text-sm text-muted mb-16">Review the generated PQL. Save to append this rule to abusecve_filters.yaml.</p>
                                <div style={{ padding: 12, background: 'rgba(0,0,0,0.25)', borderRadius: 8, border: '1px solid var(--border-subtle)', marginBottom: 12 }}>
                                    <div className="text-xs text-muted" style={{ marginBottom: 4 }}>Name</div>
                                    <div className="text-sm" style={{ fontWeight: 600, marginBottom: 8 }}>{wizName || '(no name)'}</div>
                                    {wizDesc && <>
                                        <div className="text-xs text-muted" style={{ marginBottom: 4 }}>Description</div>
                                        <div className="text-sm text-muted" style={{ marginBottom: 8 }}>{wizDesc}</div>
                                    </>}
                                    <div className="text-xs text-muted" style={{ marginBottom: 4 }}>Generated PQL</div>
                                    <pre style={{ fontFamily: 'monospace', fontSize: 12, color: '#A855F7', margin: 0, whiteSpace: 'pre-wrap' }}>
                                        {buildWizardPql() || '(no selectors chosen)'}
                                    </pre>
                                </div>
                                {wizardMsg && <div className="text-sm" style={{ color: wizardMsg.includes('failed') ? 'var(--error)' : 'var(--success)' }}>{wizardMsg}</div>}
                            </div>
                        )}

                        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--border-subtle)' }}>
                            <button className="btn btn-secondary" onClick={() => setWizardStep(s => Math.max(0, s - 1))} disabled={wizardStep === 0}>Back</button>
                            {wizardStep < WIZARD_STEPS.length - 1 ? (
                                <button className="btn btn-primary" onClick={() => setWizardStep(s => s + 1)}>Next</button>
                            ) : (
                                <button className="btn btn-primary" onClick={handleWizardSave} disabled={wizardSaving}>
                                    {wizardSaving ? 'Saving…' : 'Save Rule'}
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* ── Advanced Mode ── */}
            {advancedOpen && canCreate && (
                <div className="card mb-24">
                    <div className="card-header">
                        <div className="card-title">Advanced Mode — Raw PQL Editor</div>
                        <button className="btn btn-secondary btn-sm" onClick={() => { setAdvancedOpen(false); setAdvMsg(''); }}>x Cancel</button>
                    </div>
                    <div style={{ padding: 16 }}>
                        <p className="text-sm text-muted mb-16">
                            Hand-craft PQL for complex detection logic. The rule is validated and appended to <code>abusecve_filters.yaml</code> on save.
                        </p>
                        <div className="form-group">
                            <label className="form-label">Rule Name</label>
                            <input className="form-input" value={advName} onChange={e => setAdvName(e.target.value)} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Description</label>
                            <input className="form-input" value={advDesc} onChange={e => setAdvDesc(e.target.value)} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">PQL (raw)</label>
                            <PqlInput
                                value={advPql}
                                onChange={setAdvPql}
                                multiline
                                rows={6}
                                placeholder='(vendor:microsoft OR vendor:adobe) AND severity:CRITICAL,HIGH AND cvss:>=7.0'
                            />
                        </div>
                        {advMsg && <div className="text-sm" style={{ color: advMsg.includes('failed') ? 'var(--error)' : 'var(--success)' }}>{advMsg}</div>}
                        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
                            <button className="btn btn-primary" onClick={handleAdvancedSave} disabled={advSaving}>
                                {advSaving ? 'Saving…' : 'Save Rule'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

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
                                            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                                                <button className="btn btn-secondary"
                                                    style={{ padding: '4px 12px', fontSize: 12, color: 'var(--purple-400)' }}
                                                    disabled={testingId === r.id}
                                                    onClick={(e) => { e.stopPropagation(); handleTest(r.id); }}>
                                                    {testingId === r.id ? 'Testing...' : 'Test'}
                                                </button>
                                                {canRefine && (
                                                    <button className="btn btn-secondary"
                                                        style={{ padding: '4px 10px', fontSize: 12 }}
                                                        onClick={(e) => { e.stopPropagation(); setRefineRule(r); }}
                                                        title="Refine this rule to reduce false positives">
                                                        Refine
                                                    </button>
                                                )}
                                                {canEdit && (
                                                    <button className="btn btn-secondary"
                                                        style={{ padding: '4px 10px', fontSize: 12 }}
                                                        onClick={(e) => { e.stopPropagation(); openEditModal(r); }}
                                                        title="Edit this rule">
                                                        Edit
                                                    </button>
                                                )}
                                                {canDelete && (
                                                    <button className="btn btn-secondary"
                                                        style={{ padding: '4px 10px', fontSize: 12, color: 'var(--error)' }}
                                                        onClick={(e) => { e.stopPropagation(); setDeleteRule(r); setDeleteMsg(''); }}
                                                        title="Delete this rule">
                                                        Delete
                                                    </button>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
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
                                    {testResults[r.id] && (
                                        <tr>
                                            <td colSpan="5" style={{ padding: 0 }}>
                                                <div style={{ padding: '12px 20px', background: 'rgba(0,0,0,0.1)', borderTop: '1px solid var(--border)' }}>
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
                                                    <button className="text-xs"
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

            {refineRule && (
                <RefineModal
                    ruleId={refineRule.id}
                    ruleName={refineRule.name}
                    onClose={() => setRefineRule(null)}
                    onSuccess={() => { fetchRules(); setRefineRule(null); }}
                />
            )}

            {/* ── Edit Rule Modal ── */}
            {editRule && (
                <div
                    style={{
                        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
                        background: 'rgba(0,0,0,0.92)', zIndex: 1000,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        backdropFilter: 'blur(6px)', padding: 20,
                    }}
                    onClick={closeEditModal}
                >
                    <div
                        onClick={e => e.stopPropagation()}
                        style={{
                            background: 'var(--bg, #1a1a2e)', border: '1px solid rgba(124,58,237,0.4)',
                            borderRadius: 12, padding: 24, width: '100%', maxWidth: 720,
                            maxHeight: '88vh', overflowY: 'auto', boxShadow: '0 16px 48px rgba(0,0,0,0.8)',
                        }}
                    >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                            <h2 style={{ margin: 0, fontSize: 18 }}>
                                Edit Rule <span style={{ color: 'var(--purple-400)' }}>#{editRule.id}</span>
                            </h2>
                            <button onClick={closeEditModal} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 20, cursor: 'pointer' }}>&times;</button>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Rule Name</label>
                            <input className="form-input" value={editName} onChange={e => setEditName(e.target.value)} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Description</label>
                            <textarea className="form-textarea" rows={3} value={editDesc} onChange={e => setEditDesc(e.target.value)} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">PQL</label>
                            <PqlInput
                                value={editPql}
                                onChange={setEditPql}
                                multiline
                                rows={6}
                                placeholder='(vendor:microsoft OR vendor:adobe) AND severity:CRITICAL,HIGH'
                            />
                        </div>
                        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 12 }}>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                <input type="checkbox" checked={editEnabled} onChange={e => setEditEnabled(e.target.checked)} style={{ accentColor: 'var(--purple-500)' }} />
                                <span className="text-sm">Enabled</span>
                            </label>
                            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                                <input type="checkbox" checked={editAlertMod} onChange={e => setEditAlertMod(e.target.checked)} style={{ accentColor: 'var(--purple-500)' }} />
                                <span className="text-sm">Alert on Modified CVEs</span>
                            </label>
                        </div>

                        {editMsg && (
                            <div className="text-sm" style={{
                                padding: '8px 12px', marginBottom: 12, borderRadius: 6,
                                background: editMsg.includes('failed') ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)',
                                border: `1px solid ${editMsg.includes('failed') ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}`,
                                color: editMsg.includes('failed') ? 'var(--error)' : 'var(--success)',
                            }}>
                                {editMsg}
                            </div>
                        )}

                        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 8 }}>
                            <button className="btn btn-secondary" onClick={closeEditModal} disabled={editSaving}>Cancel</button>
                            <button className="btn btn-primary" onClick={handleEditSave} disabled={editSaving}>
                                {editSaving ? 'Saving…' : 'Save Changes'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Delete Confirmation ── */}
            {deleteRule && (
                <div
                    style={{
                        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
                        background: 'rgba(0,0,0,0.92)', zIndex: 1000,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        backdropFilter: 'blur(6px)', padding: 20,
                    }}
                    onClick={() => !deleting && setDeleteRule(null)}
                >
                    <div
                        onClick={e => e.stopPropagation()}
                        style={{
                            background: 'var(--bg, #1a1a2e)', border: '1px solid rgba(239,68,68,0.4)',
                            borderRadius: 12, padding: 24, width: '100%', maxWidth: 480,
                            boxShadow: '0 16px 48px rgba(0,0,0,0.8)',
                        }}
                    >
                        <h2 style={{ margin: '0 0 8px', fontSize: 18, color: 'var(--error)' }}>Delete Rule?</h2>
                        <p className="text-sm text-muted" style={{ marginBottom: 12 }}>
                            This will permanently remove rule <strong style={{ color: 'var(--text-primary)' }}>#{deleteRule.id} — {deleteRule.name}</strong> from
                            <code> abusecve_filters.yaml</code>. A timestamped backup is created on the server before the write.
                        </p>
                        {deleteRule.pql && (
                            <pre style={{
                                fontFamily: 'monospace', fontSize: 11, padding: 10,
                                background: 'rgba(0,0,0,0.3)', borderRadius: 6,
                                color: '#A855F7', marginBottom: 12, whiteSpace: 'pre-wrap',
                                maxHeight: 120, overflowY: 'auto',
                            }}>
                                {deleteRule.pql}
                            </pre>
                        )}
                        {deleteMsg && (
                            <div className="text-sm" style={{
                                padding: '8px 12px', marginBottom: 12, borderRadius: 6,
                                background: deleteMsg.includes('failed') ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)',
                                border: `1px solid ${deleteMsg.includes('failed') ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.3)'}`,
                                color: deleteMsg.includes('failed') ? 'var(--error)' : 'var(--success)',
                            }}>
                                {deleteMsg}
                            </div>
                        )}
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                            <button className="btn btn-secondary" disabled={deleting} onClick={() => setDeleteRule(null)}>Cancel</button>
                            <button
                                className="btn btn-primary"
                                disabled={deleting}
                                onClick={handleDeleteConfirm}
                                style={{ background: 'var(--error)', borderColor: 'var(--error)' }}
                            >
                                {deleting ? 'Deleting…' : 'Delete Rule'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

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
                            <button className="btn btn-secondary" onClick={() => setShowHelp(false)} style={{ padding: '4px 12px' }}>X</button>
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
