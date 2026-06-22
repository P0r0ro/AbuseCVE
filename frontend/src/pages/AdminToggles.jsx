import React, { useEffect, useState } from 'react';
import {
    ShieldCheck, Lock, Unlock, Users as UsersIcon,
    Sliders, ListChecks, UserPlus, KeyRound, Power, PowerOff, Pencil, RefreshCw,
} from 'lucide-react';
import {
    getAdminToggles, setAdminToggle,
    listUsers, createUser, updateUser, deactivateUser,
    getAuditLog,
} from '../api';
import { usePermissions } from '../permissions';

// ── Admin / Access Control Page ───────────────────────
// Three tabs:
//   • Toggles    — SOC visibility + privileged-action toggles (existing)
//   • Users      — analyst account CRUD (Phase 1)
//   • Audit Log  — append-only history of sensitive actions (Phase 2)

const COMPONENT_LABELS = [
    { key: 'dashboard', label: 'Dashboard', description: 'Live CVE metrics and trigger scan button.' },
    { key: 'rules_manager', label: 'Rules Manager', description: 'View / test file-based detection rules. Write actions are controlled separately below.' },
    { key: 'alerts', label: 'Alerts', description: 'Triggered alert feed from the filter engine.' },
    { key: 'cve_database', label: 'CVE Database', description: 'Full CVE catalog with PQL search.' },
    { key: 'knowledge', label: 'Knowledge Articles', description: 'Composed vulnerability reports.' },
    { key: 'logs', label: 'Logs', description: 'Worker / task / system log viewer.' },
    { key: 'health', label: 'Health Reports', description: 'Component status and uptime history.' },
];

const ACTION_LABELS = [
    { key: 'soc_rule_create', label: 'Create Rules', description: 'Allow SOC to add new rules via Rule Wizard or Advanced Mode.' },
    { key: 'soc_rule_refine', label: 'Refine Rules', description: 'Allow SOC to append AND NOT negation logic to reduce false positives.' },
    { key: 'soc_rule_edit', label: 'Edit Rules', description: 'Allow SOC to modify existing rules (name, description, PQL, enabled state).' },
    { key: 'soc_rule_delete', label: 'Delete Rules', description: 'Allow SOC to permanently remove rules from abusecve_filters.yaml.' },
    { key: 'soc_ka_delete', label: 'Delete Knowledge Articles', description: 'Allow SOC to permanently delete composed vulnerability reports.' },
];

const TABS = [
    { key: 'toggles', label: 'Toggles',   icon: Sliders },
    { key: 'users',   label: 'Users',     icon: UsersIcon },
    { key: 'audit',   label: 'Audit Log', icon: ListChecks },
];

export default function AdminToggles() {
    const { isAdmin } = usePermissions();
    const [tab, setTab] = useState('toggles');

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

    return (
        <div className="main-content animate-in">
            <div style={{ marginBottom: 24 }}>
                <h1 className="header-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <ShieldCheck size={26} style={{ color: 'var(--purple-400)' }} />
                    Access Control
                </h1>
                <p className="text-sm text-muted" style={{ marginTop: 4 }}>
                    Manage analyst accounts, grant per-action SOC permissions, and audit who did what.
                </p>
            </div>

            {/* Tab bar */}
            <div style={{
                display: 'flex', gap: 4, marginBottom: 20,
                borderBottom: '1px solid var(--border-subtle)',
            }}>
                {TABS.map(t => {
                    const Icon = t.icon;
                    const active = tab === t.key;
                    return (
                        <button
                            key={t.key}
                            onClick={() => setTab(t.key)}
                            className="btn btn-secondary"
                            style={{
                                background: 'transparent',
                                borderBottom: active ? '2px solid var(--purple-500)' : '2px solid transparent',
                                borderRadius: 0,
                                color: active ? 'var(--purple-400)' : 'var(--text-muted)',
                                fontWeight: active ? 700 : 500,
                                paddingBottom: 10,
                            }}
                        >
                            <Icon size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                            {t.label}
                        </button>
                    );
                })}
            </div>

            {tab === 'toggles' && <TogglesTab />}
            {tab === 'users'   && <UsersTab />}
            {tab === 'audit'   && <AuditTab />}
        </div>
    );
}

// ══════════════════════════════════════════════════════
//  TogglesTab — original AdminToggles content unchanged
// ══════════════════════════════════════════════════════
function TogglesTab() {
    const { toggles: ctxToggles, setToggles: setCtxToggles } = usePermissions();
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

    if (loading) return <div className="loading"><div className="loading-spinner" />Loading toggles…</div>;

    return (
        <>
            {status && (
                <div className="card mb-20" style={{ padding: '10px 16px', borderColor: 'var(--border-accent)' }}>
                    <span className="text-sm">{status}</span>
                </div>
            )}

            <div className="card">
                <div className="card-header"><div className="card-title">SOC-visible Components</div></div>
                <div style={{ padding: 0 }}>
                    {COMPONENT_LABELS.map((c, i) => {
                        const enabled = toggles[c.key] !== false;
                        return (
                            <ToggleRow
                                key={c.key} k={c.key} label={c.label} description={c.description}
                                enabled={enabled} saving={saving === c.key}
                                onChange={(next) => handleToggle(c.key, next)}
                                firstRow={i === 0}
                                onLabel="Visible to SOC" offLabel="Hidden from SOC"
                            />
                        );
                    })}
                </div>
            </div>

            <div className="card mt-20">
                <div className="card-header"><div className="card-title">SOC Privileged Actions</div></div>
                <div style={{ padding: '10px 20px 4px' }}>
                    <p className="text-xs text-muted" style={{ marginBottom: 6 }}>
                        Grant SOC analysts the ability to perform specific write actions. Each toggle is
                        enforced server-side by the RBAC middleware, so disabling it blocks the API call
                        regardless of what the UI shows. All actions default to <strong>off</strong>.
                    </p>
                </div>
                <div style={{ padding: 0 }}>
                    {ACTION_LABELS.map((a) => {
                        const enabled = toggles[a.key] === true;
                        return (
                            <ToggleRow
                                key={a.key} k={a.key} label={a.label} description={a.description}
                                enabled={enabled} saving={saving === a.key}
                                onChange={(next) => handleToggle(a.key, next)}
                                onLabel="SOC Allowed" offLabel="Admin Only"
                            />
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
        </>
    );
}

function ToggleRow({ k, label, description, enabled, saving, onChange, firstRow, onLabel, offLabel }) {
    return (
        <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '16px 20px',
            borderTop: firstRow ? 'none' : '1px solid var(--border-subtle)',
        }}>
            <div style={{ flex: 1, paddingRight: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {enabled
                        ? <Unlock size={14} style={{ color: 'var(--success)' }} />
                        : <Lock size={14} style={{ color: 'var(--text-muted)' }} />}
                    <span style={{ fontWeight: 600 }}>{label}</span>
                    <code style={{ fontSize: 11, color: 'var(--text-muted)' }}>{k}</code>
                </div>
                <div className="text-xs text-muted" style={{ marginTop: 4, paddingLeft: 22 }}>{description}</div>
            </div>
            <label style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '8px 14px',
                background: enabled ? 'rgba(34,197,94,0.12)' : 'var(--bg-secondary)',
                border: `1px solid ${enabled ? 'rgba(34,197,94,0.4)' : 'var(--border-subtle)'}`,
                borderRadius: 8, cursor: saving ? 'wait' : 'pointer',
                opacity: saving ? 0.6 : 1,
            }}>
                <input
                    type="checkbox" checked={enabled} disabled={saving}
                    onChange={e => onChange(e.target.checked)}
                    style={{ width: 16, height: 16, accentColor: 'var(--purple-500)' }}
                />
                <span className="text-xs" style={{ fontWeight: 700, textTransform: 'uppercase' }}>
                    {enabled ? onLabel : offLabel}
                </span>
            </label>
        </div>
    );
}

// ══════════════════════════════════════════════════════
//  UsersTab — analyst account CRUD
// ══════════════════════════════════════════════════════
function UsersTab() {
    const { user: currentUser } = usePermissions();
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [status, setStatus] = useState('');
    const [error, setError] = useState('');
    const [showCreate, setShowCreate] = useState(false);
    const [editing, setEditing] = useState(null);   // user object being edited
    const [resetting, setResetting] = useState(null); // user object whose password is being reset

    const refresh = async () => {
        setLoading(true);
        try {
            const data = await listUsers();
            setUsers(data.users || []);
        } catch (e) {
            setError('Failed to load users: ' + e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { refresh(); }, []);

    const flash = (msg) => {
        setStatus(msg);
        setTimeout(() => setStatus(''), 3000);
    };

    const handleToggleActive = async (u) => {
        try {
            if (u.is_active) {
                await deactivateUser(u.id);
                flash(`Deactivated ${u.username}.`);
            } else {
                await updateUser(u.id, { is_active: true });
                flash(`Reactivated ${u.username}.`);
            }
            await refresh();
        } catch (e) {
            setError(e.message);
        }
    };

    return (
        <>
            {status && (
                <div className="card mb-20" style={{ padding: '10px 16px', borderColor: 'var(--border-accent)' }}>
                    <span className="text-sm">{status}</span>
                </div>
            )}
            {error && (
                <div className="card mb-20" style={{ padding: '10px 16px', borderColor: 'var(--error)' }}>
                    <span className="text-sm" style={{ color: 'var(--error)' }}>{error}</span>
                </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12, gap: 8 }}>
                <button className="btn btn-secondary btn-sm" onClick={refresh}>
                    <RefreshCw size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Refresh
                </button>
                <button className="btn btn-primary btn-sm" onClick={() => setShowCreate(true)}>
                    <UserPlus size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Add user
                </button>
            </div>

            {loading ? (
                <div className="loading"><div className="loading-spinner" />Loading users…</div>
            ) : (
                <div className="card" style={{ overflowX: 'auto' }}>
                    <table className="table" style={{ width: '100%' }}>
                        <thead>
                            <tr>
                                <th style={{ textAlign: 'left' }}>Username</th>
                                <th style={{ textAlign: 'left' }}>Full Name</th>
                                <th style={{ textAlign: 'left' }}>Role</th>
                                <th style={{ textAlign: 'left' }}>Status</th>
                                <th style={{ textAlign: 'left' }}>Last login</th>
                                <th style={{ textAlign: 'right' }}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {users.map(u => {
                                const isSelf = currentUser?.id === u.id;
                                return (
                                    <tr key={u.id}>
                                        <td><code>{u.username}</code></td>
                                        <td>{u.full_name}</td>
                                        <td>
                                            <span className="badge" style={{
                                                background: u.role === 'ADMIN' ? 'rgba(124,58,237,0.18)' : 'rgba(34,197,94,0.12)',
                                                color:      u.role === 'ADMIN' ? 'var(--purple-400)'      : 'var(--success)',
                                                padding: '2px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700,
                                            }}>
                                                {u.role}
                                            </span>
                                        </td>
                                        <td>
                                            {u.is_active
                                                ? <span style={{ color: 'var(--success)' }}>● Active</span>
                                                : <span style={{ color: 'var(--text-muted)' }}>○ Disabled</span>}
                                        </td>
                                        <td className="text-xs text-muted">
                                            {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : '—'}
                                        </td>
                                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                            <button
                                                className="btn btn-secondary btn-sm"
                                                title="Edit name / role"
                                                onClick={() => setEditing(u)}
                                                style={{ marginRight: 6 }}
                                            >
                                                <Pencil size={11} />
                                            </button>
                                            <button
                                                className="btn btn-secondary btn-sm"
                                                title="Reset password"
                                                onClick={() => setResetting(u)}
                                                style={{ marginRight: 6 }}
                                            >
                                                <KeyRound size={11} />
                                            </button>
                                            <button
                                                className="btn btn-secondary btn-sm"
                                                title={u.is_active ? 'Deactivate' : 'Reactivate'}
                                                onClick={() => handleToggleActive(u)}
                                                disabled={isSelf}
                                            >
                                                {u.is_active ? <PowerOff size={11} /> : <Power size={11} />}
                                            </button>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            )}

            {showCreate && (
                <UserFormModal
                    title="Create user"
                    onClose={() => setShowCreate(false)}
                    onSubmit={async (payload) => {
                        await createUser(payload);
                        setShowCreate(false);
                        flash(`Created ${payload.username}.`);
                        await refresh();
                    }}
                />
            )}
            {editing && (
                <UserFormModal
                    title={`Edit ${editing.username}`}
                    initial={editing}
                    editMode
                    onClose={() => setEditing(null)}
                    onSubmit={async (payload) => {
                        await updateUser(editing.id, payload);
                        setEditing(null);
                        flash(`Updated ${editing.username}.`);
                        await refresh();
                    }}
                />
            )}
            {resetting && (
                <PasswordResetModal
                    user={resetting}
                    onClose={() => setResetting(null)}
                    onSubmit={async (password) => {
                        await updateUser(resetting.id, { password });
                        setResetting(null);
                        flash(`Password reset for ${resetting.username}.`);
                    }}
                />
            )}
        </>
    );
}

function UserFormModal({ title, initial, editMode, onClose, onSubmit }) {
    const [username, setUsername]  = useState(initial?.username  || '');
    const [fullName, setFullName]  = useState(initial?.full_name || '');
    const [password, setPassword]  = useState('');
    const [role, setRole]          = useState(initial?.role      || 'SOC');
    const [submitting, setSubmitting] = useState(false);
    const [err, setErr] = useState('');

    const handle = async (e) => {
        e.preventDefault();
        setErr('');
        setSubmitting(true);
        try {
            const payload = editMode
                ? { full_name: fullName, role }   // username + password edited via separate flows
                : { username: username.trim().toLowerCase(), full_name: fullName, password, role };
            await onSubmit(payload);
        } catch (e) {
            setErr(e.message);
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <ModalShell title={title} onClose={onClose}>
            <form onSubmit={handle}>
                {!editMode && (
                    <div className="form-group">
                        <label className="form-label">Username</label>
                        <input
                            className="form-input"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="jane.doe"
                            autoFocus
                        />
                        <div className="text-xs text-muted">Lowercase, 3–64 chars, letters/digits/. _ -</div>
                    </div>
                )}
                <div className="form-group">
                    <label className="form-label">Full name</label>
                    <input
                        className="form-input"
                        value={fullName}
                        onChange={(e) => setFullName(e.target.value)}
                        placeholder="Jane Doe"
                    />
                    <div className="text-xs text-muted">
                        Shown in webhooks &amp; the audit log. Used for CRM case attribution.
                    </div>
                </div>
                {!editMode && (
                    <div className="form-group">
                        <label className="form-label">Initial password</label>
                        <input
                            type="password"
                            className="form-input"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="At least 8 characters"
                            autoComplete="new-password"
                        />
                    </div>
                )}
                <div className="form-group">
                    <label className="form-label">Role</label>
                    <select className="form-input" value={role} onChange={(e) => setRole(e.target.value)}>
                        <option value="SOC">SOC (analyst)</option>
                        <option value="ADMIN">ADMIN (full control)</option>
                    </select>
                </div>

                {err && (
                    <div className="text-sm" style={{ color: 'var(--error)', marginBottom: 12 }}>{err}</div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                    <button type="button" className="btn btn-secondary" onClick={onClose} disabled={submitting}>
                        Cancel
                    </button>
                    <button type="submit" className="btn btn-primary" disabled={submitting}>
                        {submitting ? 'Saving…' : 'Save'}
                    </button>
                </div>
            </form>
        </ModalShell>
    );
}

function PasswordResetModal({ user, onClose, onSubmit }) {
    const [password, setPassword] = useState('');
    const [submitting, setSubmitting] = useState(false);
    const [err, setErr] = useState('');

    const handle = async (e) => {
        e.preventDefault();
        setErr('');
        setSubmitting(true);
        try {
            await onSubmit(password);
        } catch (e) {
            setErr(e.message);
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <ModalShell title={`Reset password — ${user.username}`} onClose={onClose}>
            <form onSubmit={handle}>
                <div className="form-group">
                    <label className="form-label">New password</label>
                    <input
                        type="password"
                        className="form-input"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="At least 8 characters"
                        autoComplete="new-password"
                        autoFocus
                    />
                    <div className="text-xs text-muted">
                        The user's active sessions will be dropped — they must log in again with the new password.
                    </div>
                </div>

                {err && (
                    <div className="text-sm" style={{ color: 'var(--error)', marginBottom: 12 }}>{err}</div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                    <button type="button" className="btn btn-secondary" onClick={onClose} disabled={submitting}>
                        Cancel
                    </button>
                    <button type="submit" className="btn btn-primary" disabled={submitting}>
                        {submitting ? 'Saving…' : 'Reset password'}
                    </button>
                </div>
            </form>
        </ModalShell>
    );
}

function ModalShell({ title, onClose, children }) {
    return (
        <div
            onClick={onClose}
            style={{
                position: 'fixed', inset: 0, zIndex: 1000,
                background: 'rgba(0,0,0,0.65)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                padding: 20,
            }}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                className="card"
                style={{
                    maxWidth: 460, width: '100%',
                    padding: 24,
                    border: '1px solid var(--border-accent)',
                    boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
                }}
            >
                <h2 style={{ marginTop: 0, marginBottom: 16 }}>{title}</h2>
                {children}
            </div>
        </div>
    );
}

// ══════════════════════════════════════════════════════
//  AuditTab — read-only audit log viewer
// ══════════════════════════════════════════════════════
const AUDIT_ACTIONS = [
    '', // any
    'auth.login.success', 'auth.login.failure', 'auth.logout',
    'user.create', 'user.update', 'user.deactivate', 'user.reactivate', 'user.password_reset',
    'toggle.change',
    'rule.create', 'rule.update', 'rule.delete', 'rule.refine',
    'alert.close',
];

function AuditTab() {
    const [entries, setEntries] = useState([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);
    const [err, setErr] = useState('');
    const [filterAction, setFilterAction] = useState('');
    const [offset, setOffset] = useState(0);
    const PAGE_SIZE = 50;

    const fetchPage = async (params) => {
        setLoading(true);
        setErr('');
        try {
            const data = await getAuditLog({
                limit: PAGE_SIZE,
                offset: params.offset ?? offset,
                action: params.action ?? filterAction,
            });
            setEntries(data.entries || []);
            setTotal(data.total || 0);
        } catch (e) {
            setErr(e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchPage({}); /* initial */ }, []);

    const applyFilter = async (action) => {
        setFilterAction(action);
        setOffset(0);
        await fetchPage({ action, offset: 0 });
    };

    const nextPage = async () => {
        const next = offset + PAGE_SIZE;
        if (next >= total) return;
        setOffset(next);
        await fetchPage({ offset: next });
    };

    const prevPage = async () => {
        const prev = Math.max(0, offset - PAGE_SIZE);
        setOffset(prev);
        await fetchPage({ offset: prev });
    };

    const colorFor = (action) => {
        if (action.startsWith('auth.login.failure')) return 'var(--error)';
        if (action.startsWith('auth.'))              return 'var(--purple-400)';
        if (action.startsWith('user.'))              return 'var(--success)';
        if (action.startsWith('rule.delete'))        return 'var(--error)';
        if (action.startsWith('rule.'))              return 'var(--purple-400)';
        if (action.startsWith('toggle.'))            return 'var(--text-muted)';
        return 'var(--text)';
    };

    return (
        <>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 12 }}>
                <label className="form-label" style={{ marginBottom: 0 }}>Filter</label>
                <select
                    className="form-input"
                    value={filterAction}
                    onChange={(e) => applyFilter(e.target.value)}
                    style={{ maxWidth: 240 }}
                >
                    {AUDIT_ACTIONS.map(a => (
                        <option key={a} value={a}>{a || '— all actions —'}</option>
                    ))}
                </select>
                <button className="btn btn-secondary btn-sm" onClick={() => fetchPage({})}>
                    <RefreshCw size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Refresh
                </button>
                <div className="text-xs text-muted" style={{ marginLeft: 'auto' }}>
                    {loading ? 'Loading…' : `${entries.length} of ${total} entries`}
                </div>
            </div>

            {err && (
                <div className="card mb-20" style={{ padding: '10px 16px', borderColor: 'var(--error)' }}>
                    <span className="text-sm" style={{ color: 'var(--error)' }}>{err}</span>
                </div>
            )}

            <div className="card" style={{ overflowX: 'auto' }}>
                <table className="table" style={{ width: '100%' }}>
                    <thead>
                        <tr>
                            <th style={{ textAlign: 'left' }}>Time</th>
                            <th style={{ textAlign: 'left' }}>Actor</th>
                            <th style={{ textAlign: 'left' }}>Action</th>
                            <th style={{ textAlign: 'left' }}>Target</th>
                            <th style={{ textAlign: 'left' }}>Details</th>
                            <th style={{ textAlign: 'left' }}>IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        {entries.map(e => (
                            <tr key={e.id}>
                                <td className="text-xs">{new Date(e.occurred_at).toLocaleString()}</td>
                                <td className="text-xs">{e.actor_name || <em style={{ color: 'var(--text-muted)' }}>—</em>}</td>
                                <td>
                                    <code style={{ color: colorFor(e.action), fontSize: 11 }}>{e.action}</code>
                                </td>
                                <td className="text-xs text-muted">
                                    {e.target_type ? `${e.target_type}:${e.target_id}` : ''}
                                </td>
                                <td className="text-xs">
                                    {e.metadata ? (
                                        <code style={{
                                            fontSize: 10, color: 'var(--text-muted)',
                                            display: 'inline-block', maxWidth: 320,
                                            whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                                        }}
                                            title={JSON.stringify(e.metadata)}
                                        >
                                            {JSON.stringify(e.metadata)}
                                        </code>
                                    ) : null}
                                </td>
                                <td className="text-xs text-muted">{e.ip_address || ''}</td>
                            </tr>
                        ))}
                        {!loading && entries.length === 0 && (
                            <tr>
                                <td colSpan={6} className="text-sm text-muted" style={{ padding: 16, textAlign: 'center' }}>
                                    No audit entries match the current filter.
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}>
                <button className="btn btn-secondary btn-sm" onClick={prevPage} disabled={offset === 0 || loading}>
                    ← Newer
                </button>
                <div className="text-xs text-muted">
                    page {Math.floor(offset / PAGE_SIZE) + 1} / {Math.max(1, Math.ceil(total / PAGE_SIZE))}
                </div>
                <button className="btn btn-secondary btn-sm" onClick={nextPage} disabled={offset + PAGE_SIZE >= total || loading}>
                    Older →
                </button>
            </div>
        </>
    );
}
