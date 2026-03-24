import React, { useState } from 'react';
import { Mail, Search, Filter, Zap, CheckCircle2, XCircle, AlertTriangle, Circle, Loader2, Link, Play } from 'lucide-react';
import { testSMTP, testFetch, testFilterEndpoint as testFilter, testPipeline, testFullChain } from '../api';

const STEPS = [
    { key: 'smtp', label: 'SMTP Connection', icon: <Mail size={18} />, fn: testSMTP, description: 'Verify SMTP server connectivity and send test email' },
    { key: 'fetch', label: 'CVE Fetching', icon: <Search size={18} />, fn: testFetch, description: 'Fetch recent CVEs from NVD API' },
    { key: 'filter', label: 'Filter Engine', icon: <Filter size={18} />, fn: testFilter, description: 'Apply filter rules to fetched CVEs' },
    { key: 'pipeline', label: 'Full Pipeline', icon: <Zap size={18} />, fn: testPipeline, description: 'Run complete fetch → filter → dedup pipeline' },
];

export default function TestPage() {
    const [results, setResults] = useState({});
    const [running, setRunning] = useState(null);
    const [chainResult, setChainResult] = useState(null);
    const [chainRunning, setChainRunning] = useState(false);

    const runTest = async (step) => {
        setRunning(step.key);
        try {
            const result = await step.fn();
            setResults(r => ({ ...r, [step.key]: { status: 'ok', data: result } }));
        } catch (e) {
            setResults(r => ({ ...r, [step.key]: { status: 'error', error: e.message } }));
        } finally {
            setRunning(null);
        }
    };

    const runFullChain = async () => {
        setChainRunning(true);
        setChainResult(null);
        try {
            const result = await testFullChain();
            setChainResult(result);
        } catch (e) {
            setChainResult({ overall: 'error', error: e.message });
        } finally {
            setChainRunning(false);
        }
    };

    const getStepStatus = (key) => {
        const r = results[key];
        if (!r) return 'pending';
        return r.status === 'ok' ? 'pass' : 'fail';
    };

    const statusIcon = (status) => {
        switch (status) {
            case 'pass': case 'ok': case 'sent': return <CheckCircle2 size={14} />;
            case 'fail': case 'error': case 'failed': return <XCircle size={14} />;
            case 'partial': case 'warning': return <AlertTriangle size={14} />;
            default: return <Circle size={14} />;
        }
    };

    return (
        <div className="main-content animate-in">
            <div style={{ marginBottom: 24 }}>
                <h1 className="header-title">Test Chain</h1>
                <p className="text-sm text-muted" style={{ marginTop: 4 }}>Validate that the entire process chain works end-to-end</p>
            </div>

            {/* Individual Tests */}
            <div className="card mb-24">
                <div className="card-header">
                    <div className="card-title">Individual Component Tests</div>
                </div>
                <div className="test-steps">
                    {STEPS.map(step => (
                        <div key={step.key} className={`test-step ${getStepStatus(step.key)}`}>
                            <div className="test-step-icon">{step.icon}</div>
                            <div style={{ flex: 1 }}>
                                <div className="test-step-name">{step.label}</div>
                                <div className="text-xs text-muted">{step.description}</div>
                                {results[step.key]?.data && (
                                    <pre className="text-xs text-muted" style={{ marginTop: 8, background: 'var(--bg-primary)', padding: 8, borderRadius: 6, overflowX: 'auto', maxHeight: 120 }}>
                                        {JSON.stringify(results[step.key].data, null, 2)}
                                    </pre>
                                )}
                                {results[step.key]?.error && (
                                    <div className="text-xs" style={{ color: 'var(--error)', marginTop: 4 }}>{results[step.key].error}</div>
                                )}
                            </div>
                            <div className="flex items-center gap-12">
                                <span className="test-step-status">{statusIcon(getStepStatus(step.key))}</span>
                                <button className="btn btn-secondary btn-sm"
                                    disabled={running === step.key}
                                    onClick={() => runTest(step)}>
                                    {running === step.key ? <Loader2 size={14} className="spinning" /> : <><Play size={14} /> Run</>}
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Full Chain Test */}
            <div className="card">
                <div className="card-header">
                    <div className="card-title"><Link size={18} /> Full Chain Test</div>
                    <button className="btn btn-primary" onClick={runFullChain} disabled={chainRunning}>
                        {chainRunning ? <><Loader2 size={14} className="spinning" /> Running...</> : <><Play size={14} /> Run Full Chain Test</>}
                    </button>
                </div>
                <p className="text-sm text-muted mb-16">Tests the complete flow: SMTP → Fetch → Filter → Database → Redis connectivity</p>

                {chainResult && (
                    <div>
                        <div className="flex items-center gap-12 mb-16">
                            <span style={{ fontSize: 24 }}>{statusIcon(chainResult.overall)}</span>
                            <span className="font-bold" style={{ fontSize: 18, color: chainResult.overall === 'pass' ? 'var(--success)' : 'var(--warning)' }}>
                                {chainResult.overall === 'pass' ? 'All Tests Passed!' : chainResult.overall === 'error' ? 'Test Failed' : 'Partial Pass'}
                            </span>
                        </div>
                        {chainResult.steps && (
                            <div className="test-steps">
                                {chainResult.steps.map((step, i) => (
                                    <div key={i} className={`test-step ${step.status === 'ok' || step.status === 'sent' ? 'pass' : 'fail'}`}>
                                        <span className="test-step-icon">{statusIcon(step.status)}</span>
                                        <div style={{ flex: 1 }}>
                                            <div className="test-step-name" style={{ textTransform: 'capitalize' }}>{step.step}</div>
                                            {step.count !== undefined && <span className="text-xs text-muted">Count: {step.count}</span>}
                                            {step.matches !== undefined && <span className="text-xs text-muted"> | Matches: {step.matches}</span>}
                                            {step.total_cves !== undefined && <span className="text-xs text-muted"> | Total CVEs: {step.total_cves}</span>}
                                            {step.error && <div className="text-xs" style={{ color: 'var(--error)' }}>{step.error}</div>}
                                        </div>
                                        <span className="test-step-status">{step.status}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                        {chainResult.error && (
                            <div className="text-sm" style={{ color: 'var(--error)', marginTop: 12 }}>{chainResult.error}</div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
