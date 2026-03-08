/**
 * AbuseCVE API client — centralized fetch wrapper for all backend calls.
 */

const API_BASE = '/api';

async function request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const config = {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options,
    };

    if (config.body && typeof config.body === 'object') {
        config.body = JSON.stringify(config.body);
    }

    const res = await fetch(url, config);
    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
}

async function requestRaw(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const res = await fetch(url, options);
    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res;
}

// ── Dashboard ────────────────────────────────
export const getDashboardOverview = () => request('/dashboard/overview');
export const initializeDB = () =>
    request('/dashboard/initialize-db', { method: 'POST', body: {} });
export const initializeDBLocal = (mitreDir, nvdDir) =>
    request('/dashboard/initialize-db-local', {
        method: 'POST',
        body: { mitre_dir: mitreDir || null, nvd_dir: nvdDir || null },
    });
export const triggerScan = () => request('/dashboard/trigger-scan', { method: 'POST' });
export const getTaskStatus = (taskId) => request(`/dashboard/task-status/${taskId}`);

// ── Filters (read-only, file-based rules) ───
export const getFilters = () => request('/filters');
export const getFilter = (id) => request(`/filters/${id}`);
export const testFilterRule = (data) => request('/filters/test', { method: 'POST', body: data });
export const reloadFilterRules = () => request('/filters/reload', { method: 'POST' });
export const getQueryHelp = () => request('/filters/query-help');

// ── CVEs ─────────────────────────────────────
export const getCVEs = (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== '' && v !== null) qs.set(k, v); });
    return request(`/cves?${qs.toString()}`);
};
export const getCVE = (cveId) => request(`/cves/${cveId}`);
export const searchCVEs = (query, page = 1, perPage = 50) =>
    request('/cves/search', { method: 'POST', body: { query, page, per_page: perPage } });
export const searchCVEsByPQL = (pql, page = 1, perPage = 50) =>
    request('/cves/search/pql', { method: 'POST', body: { pql, page, per_page: perPage } });

// ── Alerts ───────────────────────────────────
export const getAlerts = (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== '' && v !== null) qs.set(k, v);
    });
    return request(`/alerts?${qs.toString()}`);
};
export const getAlertStats = (period) => {
    const qs = period ? `?period=${encodeURIComponent(period)}` : '';
    return request(`/alerts/stats${qs}`);
};

// ── Knowledge Articles ───────────────────────
export const getKAs = () => request('/knowledge-articles');
export const getKA = (id) => request(`/knowledge-articles/${id}`);
export const createKA = (data) => request('/knowledge-articles', { method: 'POST', body: data });
export const updateKA = (id, data) => request(`/knowledge-articles/${id}`, { method: 'PUT', body: data });
export const deleteKA = (id) => request(`/knowledge-articles/${id}`, { method: 'DELETE' });
export const generateKA = (cveId, aiProvider = 'auto') =>
    request(`/knowledge-articles/generate/${cveId}`, {
        method: 'POST',
        body: { ai_provider: aiProvider },
    });
export const getAIStatus = () => request('/knowledge-articles/ai-status');
export const generateBatchKA = (cveIds, aiProvider = 'auto') =>
    request('/knowledge-articles/generate-batch', {
        method: 'POST',
        body: { cve_ids: cveIds, ai_provider: aiProvider },
    });
export const exportKA = async (kaId) => {
    const res = await requestRaw(`/knowledge-articles/${kaId}/export`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `KA_${kaId}.txt`;
    a.click();
    URL.revokeObjectURL(url);
};

// ── Export ───────────────────────────────────
export const exportCVEsExcel = async (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== '' && v !== null && v !== false) qs.set(k, v);
    });
    const res = await requestRaw(`/export/cves?${qs.toString()}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const disposition = res.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename=(.+)/);
    const filename = match ? match[1] : 'AbuseCVE_CVEs.xlsx';
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
};

export const exportAlertsExcel = async (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== '' && v !== null && v !== false) qs.set(k, v);
    });
    const res = await requestRaw(`/export/alerts?${qs.toString()}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const disposition = res.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename=(.+)/);
    const filename = match ? match[1] : 'AbuseCVE_Alerts.xlsx';
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
};

// ── Config ───────────────────────────────────
export const getConfig = () => request('/config');
export const updateConfig = (data) => request('/config', { method: 'PUT', body: data });

// ── Test ─────────────────────────────────────
export const testSMTP = () => request('/test/smtp', { method: 'POST' });
export const testFetch = () => request('/test/fetch', { method: 'POST' });
export const testFilterEndpoint = () => request('/test/filter', { method: 'POST' });
export const testPipeline = () => request('/test/pipeline', { method: 'POST' });
export const testFullChain = () => request('/test/full-chain', { method: 'POST' });

// ── Health Reports ───────────────────────────
export const getHealthReports = () => request('/health-reports');
export const getComponentStatus = () => request('/health-reports/status');
export const generateHealthReport = () => request('/health-reports/generate', { method: 'POST' });
export const sendHealthReport = () => request('/health-reports/send', { method: 'POST' });

// ── Health Check ─────────────────────────────
export const healthCheck = () => request('/health');

// ── MITRE Upload ─────────────────────────────
export const uploadMitreData = async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const url = `${API_BASE}/dashboard/upload-mitre`;
    const res = await fetch(url, { method: 'POST', body: formData });
    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
};

// ── Logs ─────────────────────────────────────
export const getLogs = (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== '' && v !== null) qs.set(k, String(v)); });
    return request(`/logs?${qs.toString()}`);
};
export const getWorkerTypes = () => request('/logs/worker-types');
export const clearLogs = (workerType) =>
    request(`/logs/clear${workerType ? `?worker_type=${workerType}` : ''}`, { method: 'DELETE' });
export const getRedisInfo = () => request('/logs/redis');
export const getSchedule = () => request('/logs/schedule');


// ── Integrations ─────────────────────────────
export const getIntegrations = () => request('/integrations');
export const getIntegration = (id) => request(`/integrations/${id}`);
export const createIntegration = (data) => request('/integrations', { method: 'POST', body: data });
export const updateIntegration = (id, data) => request(`/integrations/${id}`, { method: 'PUT', body: data });
export const deleteIntegration = (id) => request(`/integrations/${id}`, { method: 'DELETE' });
export const toggleIntegration = (id) => request(`/integrations/${id}/toggle`, { method: 'POST' });
export const testIntegration = (id) => request(`/integrations/${id}/test`, { method: 'POST' });

