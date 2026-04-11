import React, { useEffect, useState } from 'react';
import { ShieldCheck, Lock, Unlock } from 'lucide-react';
import { getAdminToggles, setAdminToggle } from '../api';
import { usePermissions } from '../permissions';

// ── Admin Toggles Page ───────────────────────────────
// Admin-only page for enabling / disabling suite surfaces for SOC
// analysts. Admins always see everything; SOC users see disabled
// components greyed out in the sidebar and blocked by the router.
//
// Changes persist in Redis (shared across backend workers), so they
// take effect immediately for all authenticated clients on their next
// /api/auth/toggles read (triggered on login and on page load).

const COMPONENT_LABELS = [
    { key: 'dashboard', label: 'Dashboard', description: 'Live CVE metrics and trigger scan button.' },
    { key: 'rules_manager', label: 'Rules Manager', description: 'View / test file-based detection rules. Write actions are controlled separately below.' },
    { key: 'alerts', label: 'Alerts', description: 'Triggered alert feed from the filter engine.' },
    { key: 'cve_database', label: 'CVE Database', description: 'Full CVE catalog with PQL search.' },
    { key: 'knowledge', label: 'Knowledge Articles', description: 'Composed vulnerability reports.' },
    { key: 'logs', label: 'Logs', description: 'Worker / task / system log viewer.' },
    { key: 'health', label: 'Health Reports', description: 'Component status and uptime history.' },
];

// Per-action permissions granted to SOC users. Each key maps to a
// middleware toggle (soc_<key>) enforced server-side in Redis.
const ACTION_LABELS = [
    { key: 'soc_rule_create', label: 'Create Rules', description: 'Allow SOC to add new rules via Rule Wizard or Advanced Mode.' },
    { key: 'soc_rule_refine', label: 'Refine Rules', description: 'Allow SOC to append AND NOT negation logic to reduce false positives.' },
    { key: 'soc_rule_edit', label: 'Edit Rules', description: 'Allow SOC to modify existing rules (name, description, PQL, enabled state).' },
    { key: 'soc_rule_delete', label: 'Delete Rules', description: 'Allow SOC to permanently remove rules from abusecve_filters.yaml.' },
    { key: 'soc_ka_delete', label: 'Delete Knowledge Articles', description: 'Allow SOC to permanently delete composed vulnerability reports.' },
];

export default function AdminToggles() {
    const { isAdmin, toggles: ctxToggles, setToggles: setCtxToggles } = usePermissions();
    const [toggles, setToggles] = useState({});
    const [loading, setLoading] = useState(true);
    const [status, setStatus] = useState('');
    const [saving, setSaving] = useState(null);

    useEffect(() => {
        (async () => {
            try {
                const data = await getAdminToggles();
                setToggles(data.toggles || {});
            } catch (e) {
                setStatus('Failed to load toggles: ' + e.message);
            } finally {
                setLoading(false);
            }
        })();
    }, []);

    if (!isAdmin) {
        return (
            <div className="main-content">
                <div className="card" style={{ padding: 24 }}>
                    <h2>Admin only</h2>
                    <p className="text-sm text-muted">This page is restricted to administrators.</p>
                </div>
            </div>
        );
    }

    const handleToggle = async (key, next) => {
        setSaving(key);
        setStatus('');
        try {
            const res = await setAdminToggle(key, next);
            setToggles(res.toggles || { ...toggles, [key]: next });
            if (setCtxToggles) setCtxToggles(res.toggles || { ...toggles, [key]: next });
            setStatus(`${key} set to ${next ? 'enabled' : 'disabled'}.`);
        } catch (e) {
            setStatus('Failed: ' + e.message);
        } finally {
            setSaving(null);
            setTimeout(() => setStatus(''), 3000);
        }
    };

    if (loading) {
        return <div className="main-content"><div className="loading"><div className="loading-spinner" />Loading toggles…</div></div>;
    }

    return (
        <div className="main-content animate-in">
            <div style={{ marginBottom: 24 }}>
                <h1 className="header-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <ShieldCheck size={26} style={{ color: 'var(--purple-400)' }} />
                    Access Control
                </h1>
                <p className="text-sm text-muted" style={{ marginTop: 4 }}>
                    Enable or disable suite components for SOC analysts. Admins always have full access.
                    Webhooks &amp; Integrations and the Test Chain are always admin-only and cannot be exposed to SOC.
                </p>
            </div>

            {status && (
                <div className="card mb-20" style={{ padding: '10px 16px', borderColor: 'var(--border-accent)' }}>
                    <span className="text-sm">{status}</span>
                </div>
            )}

            <div className="card">
                <div className="card-header">
                    <div className="card-title">SOC-visible Components</div>
                </div>
                <div style={{ padding: 0 }}>
                    {COMPONENT_LABELS.map((c, i) => {
                        const enabled = toggles[c.key] !== false;
                        return (
                            <div
                                key={c.key}
                                style={{
                                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                    padding: '16px 20px',
                                    borderTop: i === 0 ? 'none' : '1px solid var(--border-subtle)',
                                }}
                            >
                                <div style={{ flex: 1, paddingRight: 16 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                        {enabled
                                            ? <Unlock size={14} style={{ color: 'var(--success)' }} />
                                            : <Lock size={14} style={{ color: 'var(--text-muted)' }} />
                                        }
                                        <span style={{ fontWeight: 600 }}>{c.label}</span>
                                        <code style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.key}</code>
                                    </div>
                                    <div className="text-xs text-muted" style={{ marginTop: 4, paddingLeft: 22 }}>
                                        {c.description}
                                    </div>
                                </div>
                                <label style={{
                                    display: 'flex', alignItems: 'center', gap: 8,
                                    padding: '8px 14px',
                                    background: enabled ? 'rgba(34,197,94,0.12)' : 'var(--bg-secondary)',
                                    border: `1px solid ${enabled ? 'rgba(34,197,94,0.4)' : 'var(--border-subtle)'}`,
                                    borderRadius: 8, cursor: saving === c.key ? 'wait' : 'pointer',
                                    opacity: saving === c.key ? 0.6 : 1,
                                }}>
                                    <input
                                        type="checkbox"
                                        checked={enabled}
                                        disabled={saving === c.key}
                                        onChange={e => handleToggle(c.key, e.target.checked)}
                                        style={{ width: 16, height: 16, accentColor: 'var(--purple-500)' }}
                                    />
                                    <span className="text-xs" style={{ fontWeight: 700, textTransform: 'uppercase' }}>
                                        {enabled ? 'Visible to SOC' : 'Hidden from SOC'}
                                    </span>
                                </label>
                            </div>
                        );
                    })}
                </div>
            </div>

            <div className="card mt-20">
                <div className="card-header">
                    <div className="card-title">SOC Privileged Actions</div>
                </div>
                <div style={{ padding: '10px 20px 4px' }}>
                    <p className="text-xs text-muted" style={{ marginBottom: 6 }}>
                        Grant SOC analysts the ability to perform specific write actions. Each toggle is
                        enforced server-side by the RBAC middleware, so disabling it blocks the API call
                        regardless of what the UI shows. All actions default to <strong>off</strong>.
                    </p>
                </div>
                <div style={{ padding: 0 }}>
                    {ACTION_LABELS.map((a, i) => {
                        const enabled = toggles[a.key] === true;
                        return (
                            <div
                                key={a.key}
                                style={{
                                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                    padding: '16px 20px',
                                    borderTop: '1px solid var(--border-subtle)',
                                }}
                            >
                                <div style={{ flex: 1, paddingRight: 16 }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                        {enabled
                                            ? <Unlock size={14} style={{ color: 'var(--success)' }} />
                                            : <Lock size={14} style={{ color: 'var(--text-muted)' }} />
                                        }
                                        <span style={{ fontWeight: 600 }}>{a.label}</span>
                                        <code style={{ fontSize: 11, color: 'var(--text-muted)' }}>{a.key}</code>
                                    </div>
                                    <div className="text-xs text-muted" style={{ marginTop: 4, paddingLeft: 22 }}>
                                        {a.description}
                                    </div>
                                </div>
                                <label style={{
                                    display: 'flex', alignItems: 'center', gap: 8,
                                    padding: '8px 14px',
                                    background: enabled ? 'rgba(34,197,94,0.12)' : 'var(--bg-secondary)',
                                    border: `1px solid ${enabled ? 'rgba(34,197,94,0.4)' : 'var(--border-subtle)'}`,
                                    borderRadius: 8, cursor: saving === a.key ? 'wait' : 'pointer',
                                    opacity: saving === a.key ? 0.6 : 1,
                                }}>
                                    <input
                                        type="checkbox"
                                        checked={enabled}
                                        disabled={saving === a.key}
                                        onChange={e => handleToggle(a.key, e.target.checked)}
                                        style={{ width: 16, height: 16, accentColor: 'var(--purple-500)' }}
                                    />
                                    <span className="text-xs" style={{ fontWeight: 700, textTransform: 'uppercase' }}>
                                        {enabled ? 'SOC Allowed' : 'Admin Only'}
                                    </span>
                                </label>
                            </div>
                        );
                    })}
                </div>
            </div>

            <div className="card mt-20" style={{ padding: '14px 20px' }}>
                <div className="text-xs text-muted">
                    <strong style={{ color: 'var(--purple-400)' }}>Always enforced (cannot be granted to SOC):</strong>
                    <ul style={{ margin: '6px 0 0 18px' }}>
                        <li>Integrations &amp; Webhooks (create / edit / delete)</li>
                        <li>Test Chain</li>
                    </ul>
                </div>
            </div>
        </div>
    );
}
