import React, { useState, useEffect } from 'react';
import { getConfig, updateConfig } from '../api';

export default function Configuration() {
    const [config, setConfig] = useState({});
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState('');
    const [form, setForm] = useState({});

    const fetchConfig = async () => {
        try {
            const data = await getConfig();
            setConfig(data);
            setForm(data);
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    };

    useEffect(() => { fetchConfig(); }, []);

    const handleSave = async () => {
        setSaving(true);
        setMessage('');
        try {
            // Only send fields that changed
            const changed = {};
            Object.keys(form).forEach(k => {
                if (form[k] !== config[k] && !['app_env'].includes(k)) {
                    changed[k] = form[k];
                }
            });
            if (Object.keys(changed).length === 0) {
                setMessage('No changes to save.');
                return;
            }
            // Don't send masked password
            if (changed.smtp_password === '***') delete changed.smtp_password;
            if (changed.nvd_api_key?.startsWith('***')) delete changed.nvd_api_key;

            await updateConfig(changed);
            setMessage('✅ Configuration saved successfully!');
            fetchConfig();
        } catch (e) { setMessage(`❌ ${e.message}`); }
        finally { setSaving(false); }
    };

    if (loading) return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading config...</div></div>;

    return (
        <div className="main-content animate-in">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
                <div>
                    <h1 className="header-title">Configuration</h1>
                    <p className="text-sm text-muted" style={{ marginTop: 4 }}>Platform settings and SMTP configuration</p>
                </div>
                <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                    {saving ? '⏳ Saving...' : '💾 Save Configuration'}
                </button>
            </div>

            {message && (
                <div className="card mb-20" style={{ padding: '12px 20px', borderColor: message.startsWith('✅') ? 'rgba(74,222,128,0.3)' : 'rgba(239,68,68,0.3)' }}>
                    <span className="text-sm">{message}</span>
                </div>
            )}

            <div className="grid-2">
                {/* SMTP Settings */}
                <div className="card">
                    <div className="card-header"><div className="card-title">📧 SMTP Configuration</div></div>
                    <div className="form-group">
                        <label className="form-label">SMTP Host</label>
                        <input className="form-input" value={form.smtp_host || ''} onChange={e => setForm(f => ({ ...f, smtp_host: e.target.value }))} />
                    </div>
                    <div className="form-group">
                        <label className="form-label">SMTP Port</label>
                        <input className="form-input" type="number" value={form.smtp_port || ''} onChange={e => setForm(f => ({ ...f, smtp_port: parseInt(e.target.value) }))} />
                    </div>
                    <div className="form-group">
                        <label className="form-label">Username</label>
                        <input className="form-input" value={form.smtp_user || ''} onChange={e => setForm(f => ({ ...f, smtp_user: e.target.value }))} />
                    </div>
                    <div className="form-group">
                        <label className="form-label">Password</label>
                        <input className="form-input" type="password" value={form.smtp_password || ''} onChange={e => setForm(f => ({ ...f, smtp_password: e.target.value }))} />
                    </div>
                    <div className="form-group">
                        <label className="form-label">From Address</label>
                        <input className="form-input" value={form.smtp_from || ''} onChange={e => setForm(f => ({ ...f, smtp_from: e.target.value }))} />
                    </div>
                    <div className="flex items-center gap-12">
                        <label className="toggle">
                            <input type="checkbox" checked={form.smtp_tls ?? true} onChange={e => setForm(f => ({ ...f, smtp_tls: e.target.checked }))} />
                            <span className="toggle-slider" />
                        </label>
                        <span className="text-sm">TLS Encryption</span>
                    </div>
                </div>

                {/* Alert & Scheduler */}
                <div className="card">
                    <div className="card-header"><div className="card-title">🔔 Alerts & Scheduling</div></div>
                    <div className="form-group">
                        <label className="form-label">Alert Recipients (comma-separated)</label>
                        <textarea className="form-textarea" style={{ minHeight: 80 }} value={form.alert_recipients || ''}
                            onChange={e => setForm(f => ({ ...f, alert_recipients: e.target.value }))}
                            placeholder="email1@example.com, email2@example.com" />
                    </div>
                    <div className="form-group">
                        <label className="form-label">CVE Scan Interval (minutes)</label>
                        <input className="form-input" type="number" min="30" value={form.scan_interval_minutes || 120}
                            onChange={e => setForm(f => ({ ...f, scan_interval_minutes: parseInt(e.target.value) }))} />
                        <span className="text-xs text-muted">NVD recommends no more than once every 2 hours (120 min)</span>
                    </div>
                    <div className="grid-2">
                        <div className="form-group">
                            <label className="form-label">Health Report Hour (UTC)</label>
                            <input className="form-input" type="number" min="0" max="23" value={form.health_report_hour ?? 23}
                                onChange={e => setForm(f => ({ ...f, health_report_hour: parseInt(e.target.value) }))} />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Health Report Minute</label>
                            <input className="form-input" type="number" min="0" max="59" value={form.health_report_minute ?? 59}
                                onChange={e => setForm(f => ({ ...f, health_report_minute: parseInt(e.target.value) }))} />
                        </div>
                    </div>
                </div>
            </div>

            {/* API Keys */}
            <div className="card mt-24">
                <div className="card-header"><div className="card-title">🔑 API Keys</div></div>
                <div className="form-group">
                    <label className="form-label">NVD API Key</label>
                    <input className="form-input" type="password" value={form.nvd_api_key || ''}
                        onChange={e => setForm(f => ({ ...f, nvd_api_key: e.target.value }))}
                        placeholder="Enter NVD API key for higher rate limits" />
                    <span className="text-xs text-muted">Get a key from <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" style={{ color: 'var(--purple-400)' }}>NVD Developers</a></span>
                </div>
            </div>

            {/* Current Status */}
            <div className="card mt-24">
                <div className="card-header"><div className="card-title">ℹ️ System Info</div></div>
                <div className="grid-2" style={{ gap: 12 }}>
                    <div><span className="text-xs text-muted">Environment</span><p className="text-sm">{config.app_env || 'N/A'}</p></div>
                    <div><span className="text-xs text-muted">NVD API Status</span><p className="text-sm">{config.nvd_api_key?.startsWith('***') ? '✅ Configured' : '⚠️ Not Set'}</p></div>
                </div>
            </div>
        </div>
    );
}
