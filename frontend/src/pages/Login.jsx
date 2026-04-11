import React, { useState } from 'react';
import { ShieldCheck, User, Lock } from 'lucide-react';
import { usePermissions } from '../permissions';

// ── AbuseSuite Login Page ─────────────────────────
// Two authentication modes backed by the same endpoint:
//   admin — requires a password (ADMIN role)
//   soc   — password optional (SOC role, read-mostly access)
//
// Successful login hands back a short-lived token that the API
// client then attaches to every request via the X-Auth-Token header.

export default function Login() {
    const { login } = usePermissions();
    const [username, setUsername] = useState('admin');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const isAdmin = username.trim().toLowerCase() === 'admin';
    const isSoc = username.trim().toLowerCase() === 'soc';

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            await login(username.trim(), password);
            // PermissionsProvider updates user state → app will re-render.
        } catch (err) {
            setError(err.message || 'Login failed.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{
            minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'radial-gradient(ellipse at center, rgba(124,58,237,0.12), transparent 70%), var(--bg-primary, #0a0a14)',
            padding: 20,
        }}>
            <div className="card" style={{
                maxWidth: 440, width: '100%', padding: 32,
                border: '1px solid var(--border-accent)',
                boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
            }}>
                <div style={{ textAlign: 'center', marginBottom: 24 }}>
                    <ShieldCheck size={44} style={{ color: 'var(--purple-400)' }} />
                    <h1 style={{ fontSize: 22, marginTop: 8, marginBottom: 4 }}>AbuseSuite</h1>
                    <p className="text-sm text-muted">Sign in to the CTI Platform</p>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label className="form-label">
                            <User size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Username
                        </label>
                        <input
                            className="form-input"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="admin or soc"
                            autoFocus
                        />
                    </div>

                    {isAdmin && (
                        <div className="form-group">
                            <label className="form-label">
                                <Lock size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Password
                            </label>
                            <input
                                type="password"
                                className="form-input"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Enter admin password"
                            />
                        </div>
                    )}

                    {isSoc && (
                        <div className="card mb-20" style={{ padding: '10px 14px', borderColor: 'var(--border-accent)' }}>
                            <span className="text-xs text-muted">
                                SOC analysts may sign in without a password. Write operations
                                (delete, integrations, webhook management) are disabled.
                            </span>
                        </div>
                    )}

                    {error && (
                        <div className="text-sm" style={{ color: 'var(--error)', marginBottom: 12 }}>{error}</div>
                    )}

                    <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
                        {loading ? 'Signing in…' : 'Sign In'}
                    </button>
                </form>

                <div className="text-xs text-muted" style={{ textAlign: 'center', marginTop: 18 }}>
                    AbuseSuite v3.2 · Role-based access
                </div>
            </div>
        </div>
    );
}
