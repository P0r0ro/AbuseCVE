import React, { useState, useEffect } from 'react';
import { getFilter, refineFilterRule } from '../api';

/**
 * Rule Refinement Wizard — reduces false positives by appending
 * AND NOT negation logic to a rule's PQL.
 *
 * Props:
 *   ruleId      — numeric rule ID to refine (required)
 *   ruleName    — display name of the rule (optional, for header)
 *   cveId       — CVE ID context if opened from Alerts (optional)
 *   cveDetail   — full CVE object for pre-filling fields (optional)
 *   onClose     — called when modal is dismissed
 *   onSuccess   — called after successful refinement
 */
export default function RefineModal({ ruleId, ruleName, cveId, cveDetail, onClose, onSuccess }) {
    const [ruleData, setRuleData] = useState(null);
    const [loadingRule, setLoadingRule] = useState(true);
    // Multi-keyword exclusion — each chip becomes a separate
    // { type: 'keyword', value } negation when the rule is saved.
    const [keywordChips, setKeywordChips] = useState([]);
    const [keywordDraft, setKeywordDraft] = useState('');
    const [productVal, setProductVal] = useState('');
    const [versionVal, setVersionVal] = useState('');
    const [cvssVal, setCvssVal] = useState('');
    const [useKeyword, setUseKeyword] = useState(false);
    const [useProduct, setUseProduct] = useState(false);
    const [useVersion, setUseVersion] = useState(false);
    const [useCvss, setUseCvss] = useState(false);
    const [preview, setPreview] = useState(null);
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);

    const commitKeywordDraft = () => {
        const raw = keywordDraft.trim();
        if (!raw) return;
        // Support pasting multiple comma-separated keywords at once
        const pieces = raw.split(',').map(s => s.trim()).filter(Boolean);
        if (!pieces.length) return;
        setKeywordChips(prev => {
            const seen = new Set(prev.map(k => k.toLowerCase()));
            const next = [...prev];
            for (const p of pieces) {
                if (!seen.has(p.toLowerCase())) {
                    next.push(p);
                    seen.add(p.toLowerCase());
                }
            }
            return next;
        });
        setKeywordDraft('');
    };

    const removeKeywordChip = (idx) => {
        setKeywordChips(prev => prev.filter((_, i) => i !== idx));
    };

    const handleKeywordKeyDown = (e) => {
        if (e.key === 'Enter' || e.key === ',') {
            e.preventDefault();
            commitKeywordDraft();
        } else if (e.key === 'Backspace' && !keywordDraft && keywordChips.length) {
            // Pop the last chip on backspace from an empty input
            setKeywordChips(prev => prev.slice(0, -1));
        }
    };

    // Pre-fill product from CVE detail
    useEffect(() => {
        if (cveDetail?.product) setProductVal(cveDetail.product);
    }, [cveDetail]);

    // Load the rule
    useEffect(() => {
        if (!ruleId) { setLoadingRule(false); return; }
        (async () => {
            try {
                const r = await getFilter(ruleId);
                setRuleData(r);
            } catch (e) {
                setError(`Could not load rule: ${e.message}`);
            } finally {
                setLoadingRule(false);
            }
        })();
    }, [ruleId]);

    const buildNegations = () => {
        const negs = [];
        if (useKeyword) {
            // Commit any pending draft and emit one negation per chip.
            const pending = keywordDraft.trim();
            const allChips = [...keywordChips];
            if (pending && !allChips.some(k => k.toLowerCase() === pending.toLowerCase())) {
                allChips.push(pending);
            }
            for (const kw of allChips) {
                if (kw) negs.push({ type: 'keyword', value: kw });
            }
        }
        if (useProduct && productVal.trim()) negs.push({ type: 'product', value: productVal.trim() });
        if (useVersion && versionVal.trim()) negs.push({ type: 'version', value: versionVal.trim() });
        if (useCvss && cvssVal.trim()) negs.push({ type: 'cvss', value: cvssVal.trim() });
        return negs;
    };

    const handlePreview = async () => {
        const negations = buildNegations();
        if (!negations.length) { setError('Select at least one negation criterion.'); return; }
        setError(null);
        setSubmitting(true);
        try {
            const res = await refineFilterRule({ rule_id: ruleId, negations, preview_only: true });
            setPreview(res);
        } catch (e) {
            setError(e.message);
        } finally {
            setSubmitting(false);
        }
    };

    const handleApply = async () => {
        const negations = buildNegations();
        if (!negations.length) { setError('Select at least one negation criterion.'); return; }
        setError(null);
        setSubmitting(true);
        try {
            await refineFilterRule({ rule_id: ruleId, negations, preview_only: false });
            setSuccess(true);
            setTimeout(() => { onSuccess?.(); onClose(); }, 1500);
        } catch (e) {
            setError(e.message);
        } finally {
            setSubmitting(false);
        }
    };

    const overlayStyle = {
        position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
        background: 'rgba(0,0,0,0.92)', zIndex: 1000,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        backdropFilter: 'blur(6px)',
    };
    const modalStyle = {
        background: 'var(--bg, #1a1a2e)', border: '1px solid rgba(124,58,237,0.4)',
        borderRadius: 12, padding: 24, width: '90%', maxWidth: 680,
        maxHeight: '85vh', overflowY: 'auto', boxShadow: '0 16px 48px rgba(0,0,0,0.8)',
    };
    const sectionStyle = {
        padding: '10px 14px', marginBottom: 10, borderRadius: 8,
        background: 'rgba(124,58,237,0.06)', border: '1px solid rgba(124,58,237,0.15)',
    };
    const checkRow = { display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 };
    const inputStyle = {
        flex: 1, padding: '6px 10px', fontSize: 13,
        background: 'var(--card-bg)', border: '1px solid var(--border)',
        color: 'var(--text-primary)', borderRadius: 6,
    };

    return (
        <div style={overlayStyle} onClick={onClose}>
            <div style={modalStyle} onClick={e => e.stopPropagation()}>
                {/* Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                    <h2 style={{ margin: 0, fontSize: 18 }}>Refine Filter &mdash; Reduce False Positives</h2>
                    <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 20, cursor: 'pointer' }}>&#10005;</button>
                </div>

                {/* Context info */}
                <div style={sectionStyle}>
                    {cveId && <div className="text-sm"><strong>Alert CVE:</strong> {cveId}</div>}
                    <div className="text-sm">
                        <strong>Target Rule:</strong> {ruleName || ruleData?.name || '...'} (ID: {ruleId})
                    </div>
                    {cveDetail?.description && (
                        <div className="text-xs text-muted" style={{ marginTop: 4 }}>
                            {cveDetail.description.slice(0, 200)}{cveDetail.description.length > 200 ? '...' : ''}
                        </div>
                    )}
                </div>

                {loadingRule ? (
                    <div className="loading" style={{ padding: 20 }}><div className="loading-spinner" />Loading rule...</div>
                ) : !ruleId ? (
                    <div className="text-sm text-muted" style={{ padding: 20, textAlign: 'center' }}>
                        No rule ID available. Cannot refine.
                    </div>
                ) : (
                    <>
                        {/* Current PQL */}
                        {ruleData && (
                            <div style={{ ...sectionStyle, fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>
                                <div className="text-xs text-muted" style={{ marginBottom: 4 }}>Current PQL:</div>
                                {ruleData.pql || '(none)'}
                            </div>
                        )}

                        {/* Negation options */}
                        <div style={{ marginBottom: 16 }}>
                            <div className="text-sm" style={{ fontWeight: 600, marginBottom: 8 }}>Negation Criteria:</div>

                            <div style={{ ...checkRow, alignItems: 'flex-start' }}>
                                <input
                                    type="checkbox"
                                    checked={useKeyword}
                                    onChange={e => setUseKeyword(e.target.checked)}
                                    id="neg-kw"
                                    style={{ marginTop: 6 }}
                                />
                                <label htmlFor="neg-kw" className="text-sm" style={{ whiteSpace: 'nowrap', marginTop: 4 }}>
                                    Exclude keywords in description:
                                </label>
                                <div style={{ flex: 1 }}>
                                    <div
                                        onClick={() => {
                                            if (!useKeyword) return;
                                            const el = document.getElementById('neg-kw-input');
                                            if (el) el.focus();
                                        }}
                                        style={{
                                            display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center',
                                            padding: '6px 8px', minHeight: 32,
                                            background: 'var(--card-bg)', border: '1px solid var(--border)',
                                            borderRadius: 6, cursor: useKeyword ? 'text' : 'not-allowed',
                                            opacity: useKeyword ? 1 : 0.5,
                                        }}
                                    >
                                        {keywordChips.map((kw, i) => (
                                            <span
                                                key={`${kw}-${i}`}
                                                style={{
                                                    display: 'inline-flex', alignItems: 'center', gap: 6,
                                                    padding: '3px 8px', fontSize: 12,
                                                    background: 'rgba(124,58,237,0.18)',
                                                    border: '1px solid rgba(124,58,237,0.4)',
                                                    borderRadius: 999, color: 'var(--text-primary)',
                                                }}
                                            >
                                                {kw}
                                                {useKeyword && (
                                                    <button
                                                        type="button"
                                                        onClick={(e) => { e.stopPropagation(); removeKeywordChip(i); }}
                                                        style={{
                                                            background: 'none', border: 'none', padding: 0,
                                                            color: 'var(--text-muted)', cursor: 'pointer',
                                                            fontSize: 14, lineHeight: 1,
                                                        }}
                                                        aria-label={`Remove ${kw}`}
                                                    >
                                                        &times;
                                                    </button>
                                                )}
                                            </span>
                                        ))}
                                        <input
                                            id="neg-kw-input"
                                            type="text"
                                            value={keywordDraft}
                                            onChange={e => setKeywordDraft(e.target.value)}
                                            onKeyDown={handleKeywordKeyDown}
                                            onBlur={commitKeywordDraft}
                                            disabled={!useKeyword}
                                            placeholder={keywordChips.length ? '' : 'e.g. print spooler, legacy — Enter or comma to add'}
                                            style={{
                                                flex: 1, minWidth: 140, border: 'none', outline: 'none',
                                                background: 'transparent', color: 'var(--text-primary)',
                                                fontSize: 13, padding: '2px 4px',
                                            }}
                                        />
                                    </div>
                                    {useKeyword && keywordChips.length > 0 && (
                                        <div className="text-xs text-muted" style={{ marginTop: 4 }}>
                                            {keywordChips.length} keyword{keywordChips.length === 1 ? '' : 's'} — each added as a separate <code>NOT description:"..."</code> clause.
                                        </div>
                                    )}
                                </div>
                            </div>

                            <div style={checkRow}>
                                <input type="checkbox" checked={useProduct} onChange={e => setUseProduct(e.target.checked)} id="neg-prod" />
                                <label htmlFor="neg-prod" className="text-sm" style={{ whiteSpace: 'nowrap' }}>Exclude product:</label>
                                <input style={inputStyle} placeholder="e.g. FortiSwitch"
                                    value={productVal} onChange={e => setProductVal(e.target.value)} disabled={!useProduct} />
                            </div>

                            <div style={checkRow}>
                                <input type="checkbox" checked={useVersion} onChange={e => setUseVersion(e.target.checked)} id="neg-ver" />
                                <label htmlFor="neg-ver" className="text-sm" style={{ whiteSpace: 'nowrap' }}>Exclude version string:</label>
                                <input style={inputStyle} placeholder="e.g. 6.4.0, before 7.2"
                                    value={versionVal} onChange={e => setVersionVal(e.target.value)} disabled={!useVersion} />
                            </div>

                            <div style={checkRow}>
                                <input type="checkbox" checked={useCvss} onChange={e => setUseCvss(e.target.checked)} id="neg-cvss" />
                                <label htmlFor="neg-cvss" className="text-sm" style={{ whiteSpace: 'nowrap' }}>Only alert if CVSS &ge;:</label>
                                <input style={{ ...inputStyle, maxWidth: 80 }} type="number" step="0.1" min="0" max="10"
                                    placeholder="7.0" value={cvssVal} onChange={e => setCvssVal(e.target.value)} disabled={!useCvss} />
                            </div>
                        </div>

                        {/* Before vs After preview */}
                        {preview && (
                            <div style={{ marginBottom: 16 }}>
                                <div className="text-sm" style={{ fontWeight: 600, marginBottom: 6 }}>Before vs. After:</div>
                                <div style={{ ...sectionStyle, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
                                    <div className="text-xs text-muted" style={{ marginBottom: 2 }}>BEFORE:</div>
                                    <code style={{ fontSize: 11, wordBreak: 'break-all' }}>{preview.original_pql}</code>
                                </div>
                                <div style={{ ...sectionStyle, background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)' }}>
                                    <div className="text-xs text-muted" style={{ marginBottom: 2 }}>AFTER:</div>
                                    <code style={{ fontSize: 11, wordBreak: 'break-all' }}>{preview.refined_pql}</code>
                                </div>
                            </div>
                        )}

                        {/* Error / Success feedback */}
                        {error && (
                            <div style={{ padding: '8px 12px', marginBottom: 12, borderRadius: 6, background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: 'var(--error)', fontSize: 13 }}>
                                {error}
                            </div>
                        )}
                        {success && (
                            <div style={{ padding: '8px 12px', marginBottom: 12, borderRadius: 6, background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', color: 'var(--success)', fontSize: 13 }}>
                                Rule refined successfully! Reloading...
                            </div>
                        )}

                        {/* Action buttons */}
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                            <button className="btn btn-secondary" onClick={onClose} disabled={submitting}>Cancel</button>
                            <button className="btn btn-secondary" onClick={handlePreview} disabled={submitting || success}>
                                {submitting && !preview ? 'Loading...' : 'Preview'}
                            </button>
                            <button className="btn btn-primary" onClick={handleApply}
                                disabled={submitting || success || !buildNegations().length}>
                                {submitting ? 'Applying...' : 'Apply Refinement'}
                            </button>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}
