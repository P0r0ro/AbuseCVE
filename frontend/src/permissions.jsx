import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { loginUser, getCurrentUser, logoutUser, setAuthToken, getAuthToken, getAdminToggles } from './api';

// ── Auth / RBAC context ─────────────────────────
// The suite supports two roles:
//   ADMIN — full access, requires a password at login
//   SOC   — restricted, password-less login
//
// Restrictions for SOC users:
//   • Cannot delete Knowledge Articles
//   • Cannot delete / create rules
//   • Cannot manage webhooks or integrations
//   • Cannot change admin component toggles
//
// Admins can enable/disable individual suite components via the
// "Admin Toggles" API — SOC users see disabled components grayed out.

const PermissionsContext = createContext(null);

export function PermissionsProvider({ children }) {
    const [user, setUser] = useState(null);
    const [toggles, setToggles] = useState({});
    const [loading, setLoading] = useState(true);

    const refresh = useCallback(async () => {
        if (!getAuthToken()) {
            setUser(null);
            setLoading(false);
            return;
        }
        try {
            const me = await getCurrentUser();
            setUser(me);
            try {
                const t = await getAdminToggles();
                setToggles(t.toggles || {});
            } catch (_) { /* optional */ }
        } catch (e) {
            setAuthToken(null);
            setUser(null);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { refresh(); }, [refresh]);

    const login = async (username, password) => {
        const res = await loginUser({ username, password: password || '' });
        setAuthToken(res.token);
        setUser(res.user);
        try {
            const t = await getAdminToggles();
            setToggles(t.toggles || {});
        } catch (_) { /* no-op */ }
        return res.user;
    };

    const logout = async () => {
        try { await logoutUser(); } catch (_) { /* ignore */ }
        setAuthToken(null);
        setUser(null);
    };

    const isAdmin = user?.role === 'ADMIN';
    const isSoc = user?.role === 'SOC';
    const isAuthenticated = !!user;

    // Component-level access check used by SOC restrictions
    const canAccess = (component) => {
        if (!user) return false;
        if (isAdmin) return true;
        // SOC-blocked suite surfaces
        const socBlocked = new Set(['integrations', 'webhooks', 'admin_toggles']);
        if (socBlocked.has(component)) return false;
        // Honor admin-configured toggle (default: enabled)
        if (toggles[component] === false) return false;
        return true;
    };

    // Action-level RBAC — admins always pass; SOC only if the
    // matching `soc_<action>` toggle is explicitly enabled.
    //   action: 'rule_create' | 'rule_refine' | 'rule_edit'
    //         | 'rule_delete' | 'ka_delete'
    const canPerform = (action) => {
        if (!user) return false;
        if (isAdmin) return true;
        return toggles[`soc_${action}`] === true;
    };

    const canDelete = (resource) => {
        if (!isAuthenticated) return false;
        if (isAdmin) return true;
        if (resource === 'knowledge_article') return canPerform('ka_delete');
        if (resource === 'rule') return canPerform('rule_delete');
        return true;
    };

    return (
        <PermissionsContext.Provider value={{
            user, isAdmin, isSoc, isAuthenticated, loading,
            toggles, setToggles, refresh, login, logout,
            canAccess, canDelete, canPerform,
        }}>
            {children}
        </PermissionsContext.Provider>
    );
}

export function usePermissions() {
    const ctx = useContext(PermissionsContext);
    if (!ctx) throw new Error('usePermissions must be used inside PermissionsProvider');
    return ctx;
}
