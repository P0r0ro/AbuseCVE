import React, { useState, useEffect } from 'react';
import { getIntegrations, createIntegration, updateIntegration, deleteIntegration, toggleIntegration, testIntegration } from '../api';

const TYPES = [
    { value: 'webhook', label: '🔗 Webhook', desc: 'Generic HTTP webhook' },
    { value: 'ms_crm', label: '🏢 Microsoft CRM', desc: 'Dynamics 365 case creation' },
    { value: 'jira', label: '🎫 Jira', desc: 'Jira issue creation' },
    { value: 'custom', label: '⚡ Custom', desc: 'Custom HTTP endpoint' },
];

const AUTH_TYPES = [
    { value: '', label: 'None' },
    { value: 'bearer', label: 'Bearer Token' },
    { value: 'api_key', label: 'API Key (X-API-Key)' },
    { value: 'basic', label: 'Basic Auth' },
];

export default function Integrations() {
    const [integrations, setIntegrations] = useState([]);
    const [loading, setLoading] = useState(true);
    const [editing, setEditing] = useState(null);
    const [testing, setTesting] = useState(null);
    const [testResult, setTestResult] = useState(null);
    const [form, setForm] = useState({
        name: '', type: 'webhook', url: '', method: 'POST',
        headers: {}, auth_type: '', auth_token: '', payload_template: '', enabled: true,
    });

    const fetchIntegrations = async () => {
        try {
            const data = await getIntegrations();
            setIntegrations(data || []);
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    };

    useEffect(() => { fetchIntegrations(); }, []);

    const handleSave = async () => {
        try {
            if (editing && editing !== 'new') {
                await updateIntegration(editing, form);
            } else {
                await createIntegration(form);
            }
            setEditing(null);
            fetchIntegrations();
        } catch (e) { alert(e.message); }
    };

    const handleDelete = async (id) => {
        if (!confirm('Delete this integration?')) return;
        try {
            await deleteIntegration(id);
            fetchIntegrations();
        } catch (e) { alert(e.message); }
    };

    const handleToggle = async (id) => {
        try {
            await toggleIntegration(id);
            fetchIntegrations();
        } catch (e) { alert(e.message); }
    };

    const handleTest = async (id) => {
        setTesting(id);
        setTestResult(null);
        try {
            const result = await testIntegration(id);
            setTestResult(result);
        } catch (e) { setTestResult({ status: 'failed', error: e.message }); }
        finally { setTesting(null); }
    };

    const openEditor = (integration) => {
        if (integration) {
            setForm({
                name: integration.name,
                type: integration.type,
                url: integration.url,
                method: integration.method || 'POST',
                headers: integration.headers || {},
                auth_type: integration.auth_type || '',
                auth_token: integration.auth_token || '',
                payload_template: integration.payload_template || '',
                enabled: integration.enabled,
            });
            setEditing(integration.id);
        } else {
            setForm({
                name: '', type: 'webhook', url: '', method: 'POST',
                headers: {}, auth_type: '', auth_token: '', payload_template: '', enabled: true,
            });
            setEditing('new');
        }
        setTestResult(null);
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading integrations...</div></div>;

    return (
        <div className="main-content animate-in">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <div>
                    <h1 className="header-title">🔗 Integrations</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Configure webhooks and CRM integrations for automated alert dispatch</p>
                </div>
                <button className="btn btn-primary" onClick={() => openEditor(null)}>➕ Add Integration</button>
            </div>

            {/* Integration cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(400px, 1fr))', gap: 20, marginBottom: 24 }}>
                {integrations.map(int => (
                    <div key={int.id} className="card" style={{ opacity: int.enabled ? 1 : 0.6 }}>
                        <div className="card-header">
                            <div>
                                <div className="card-title">{int.name}</div>
                                <div className="text-xs text-muted" style={{ marginTop: 2 }}>
                                    {TYPES.find(t => t.value === int.type)?.label || int.type}
                                </div>
                            </div>
                            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                <label className="toggle">
                                    <input type="checkbox" checked={int.enabled} onChange={() => handleToggle(int.id)} />
                                    <span className="toggle-slider" />
                                </label>
                            </div>
                        </div>

                        <div className="text-sm" style={{ wordBreak: 'break-all', color: 'var(--purple-400)', marginBottom: 12 }}>
                            {int.method} {int.url}
                        </div>

                        {int.last_used && (
                            <div className="text-xs text-muted" style={{ marginBottom: 8 }}>
                                Last used: {new Date(int.last_used).toLocaleString()} —
                                <span style={{ color: int.last_status === 'success' ? 'var(--success)' : 'var(--error)', marginLeft: 4 }}>
                                    {int.last_status || 'never'}
                                </span>
                            </div>
                        )}
                        {int.last_error && (
                            <div className="text-xs" style={{ color: 'var(--error)', marginBottom: 8 }}>{int.last_error}</div>
                        )}

                        <div style={{ display: 'flex', gap: 8 }}>
                            <button className="btn btn-secondary btn-sm" onClick={() => openEditor(int)}>✏️ Edit</button>
                            <button className="btn btn-secondary btn-sm" onClick={() => handleTest(int.id)} disabled={testing === int.id}>
                                {testing === int.id ? '⏳ Testing...' : '🧪 Test'}
                            </button>
                            <button className="btn btn-danger btn-sm" onClick={() => handleDelete(int.id)}>🗑️</button>
                        </div>
                    </div>
                ))}

                {integrations.length === 0 && (
                    <div className="card" style={{ textAlign: 'center', padding: 40, gridColumn: '1 / -1' }}>
                        <p className="text-muted">No integrations configured</p>
                        <p className="text-sm text-muted" style={{ marginTop: 8 }}>Add a webhook or CRM integration to receive alerts externally</p>
                    </div>
                )}
            </div>

            {/* Test result */}
            {testResult && (
                <div className="card mb-20" style={{ borderColor: testResult.status === 'success' ? 'rgba(74,222,128,0.3)' : 'rgba(239,68,68,0.3)' }}>
                    <div className="card-header">
                        <div className="card-title">{testResult.status === 'success' ? '✅ Test Successful' : '❌ Test Failed'}</div>
                        <button className="modal-close" onClick={() => setTestResult(null)}>×</button>
                    </div>
                    {testResult.status_code && (
                        <div className="text-sm" style={{ marginBottom: 8 }}>HTTP Status: <strong>{testResult.status_code}</strong></div>
                    )}
                    {testResult.error && (
                        <div className="text-sm" style={{ color: 'var(--error)', marginBottom: 8 }}>{testResult.error}</div>
                    )}
                    {testResult.response_body && (
                        <details>
                            <summary className="text-sm text-muted" style={{ cursor: 'pointer' }}>Response Body</summary>
                            <pre style={{ fontSize: 12, marginTop: 8, maxHeight: 200, overflow: 'auto', background: 'var(--bg-secondary)', padding: 12, borderRadius: 8 }}>
                                {testResult.response_body}
                            </pre>
                        </details>
                    )}
                </div>
            )}

            {/* Editor modal */}
            {editing && (
                <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setEditing(null)}>
                    <div className="modal" style={{ maxWidth: 640 }}>
                        <div className="modal-header">
                            <h2 className="modal-title">{editing === 'new' ? '➕ New Integration' : '✏️ Edit Integration'}</h2>
                            <button className="modal-close" onClick={() => setEditing(null)}>×</button>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Name</label>
                            <input className="form-input" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="My Webhook" />
                        </div>

                        <div className="grid-2" style={{ gap: 16 }}>
                            <div className="form-group">
                                <label className="form-label">Type</label>
                                <select className="form-select" value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}>
                                    {TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                                </select>
                            </div>
                            <div className="form-group">
                                <label className="form-label">Method</label>
                                <select className="form-select" value={form.method} onChange={e => setForm(f => ({ ...f, method: e.target.value }))}>
                                    <option value="POST">POST</option>
                                    <option value="PUT">PUT</option>
                                </select>
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label">URL</label>
                            <input className="form-input" value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))} placeholder="https://webhook.example.com/alerts" />
                        </div>

                        <div className="grid-2" style={{ gap: 16 }}>
                            <div className="form-group">
                                <label className="form-label">Auth Type</label>
                                <select className="form-select" value={form.auth_type} onChange={e => setForm(f => ({ ...f, auth_type: e.target.value }))}>
                                    {AUTH_TYPES.map(a => <option key={a.value} value={a.value}>{a.label}</option>)}
                                </select>
                            </div>
                            <div className="form-group">
                                <label className="form-label">Auth Token</label>
                                <input className="form-input" type="password" value={form.auth_token} onChange={e => setForm(f => ({ ...f, auth_token: e.target.value }))} placeholder="Bearer token or API key" />
                            </div>
                        </div>

                        <div className="form-group">
                            <label className="form-label">Custom Payload Template (JSON)</label>
                            <textarea
                                className="form-textarea" style={{ fontFamily: 'monospace', fontSize: 12 }}
                                value={form.payload_template}
                                onChange={e => setForm(f => ({ ...f, payload_template: e.target.value }))}
                                placeholder={'{\n  "title": "{{cve.cve_id}}",\n  "description": "{{cve.description}}"\n}'}
                            />
                            <span className="text-xs text-muted">Use {'{{cve.field}}'} placeholders. Leave empty for default payload.</span>
                        </div>

                        <div className="modal-footer">
                            <button className="btn btn-secondary" onClick={() => setEditing(null)}>Cancel</button>
                            <button className="btn btn-primary" onClick={handleSave} disabled={!form.name || !form.url}>
                                {editing === 'new' ? '➕ Create' : '💾 Save'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
