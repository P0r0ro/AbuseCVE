import React, { useEffect, useRef, useState } from 'react';
import { getPqlAutocomplete } from '../api';

// ── PQL Auto-complete Input ────────────────────────
// A drop-in replacement for PQL text fields that shows a dropdown of
// field / value / operator suggestions as the analyst types. The
// suggestion list is fetched once from /api/filters/autocomplete and
// then filtered locally based on the current token under the cursor.
//
// Used by CVEDatabase (PQL search bar) and RulesManager (Advanced
// Mode editor). Works for both <input> and multiline <textarea> modes.

const STATIC_SUGGESTIONS = {
    keywords: [
        'vendor:', 'product:', 'severity:', 'cvss:', 'description:',
        'kev:', 'cve_id:', 'source:',
    ],
    values: {
        severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        kev: ['true', 'false'],
        source: ['NVD', 'MITRE', 'CISA_KEV', 'REDHAT'],
    },
    operators: ['AND', 'OR', 'NOT'],
};

let _cachedSuggestions = null;

async function loadSuggestions() {
    if (_cachedSuggestions) return _cachedSuggestions;
    try {
        const res = await getPqlAutocomplete();
        _cachedSuggestions = {
            keywords: res.keywords || STATIC_SUGGESTIONS.keywords,
            values: res.values || STATIC_SUGGESTIONS.values,
            operators: res.operators || STATIC_SUGGESTIONS.operators,
        };
    } catch (_) {
        _cachedSuggestions = STATIC_SUGGESTIONS;
    }
    return _cachedSuggestions;
}

export default function PqlInput({
    value,
    onChange,
    onEnter,
    placeholder = '',
    multiline = false,
    rows = 3,
    style = {},
    className = '',
}) {
    const ref = useRef(null);
    const [suggestions, setSuggestions] = useState(STATIC_SUGGESTIONS);
    const [dropdown, setDropdown] = useState({ open: false, items: [], highlight: 0 });

    useEffect(() => {
        loadSuggestions().then(setSuggestions);
    }, []);

    const computeToken = () => {
        const el = ref.current;
        if (!el) return { token: '', start: 0 };
        const pos = el.selectionStart ?? value.length;
        const upto = value.slice(0, pos);
        const m = upto.match(/([\w:<>=!~]*)$/);
        const token = m ? m[1] : '';
        return { token, start: pos - token.length };
    };

    const computeItems = (token) => {
        if (!token) return [];
        const lower = token.toLowerCase();
        const items = [];

        // After "field:" — suggest values for that field
        const colonIdx = token.indexOf(':');
        if (colonIdx > 0) {
            const field = token.slice(0, colonIdx).toLowerCase();
            const partial = token.slice(colonIdx + 1).toUpperCase();
            const fieldValues = suggestions.values?.[field];
            if (fieldValues) {
                fieldValues.forEach(v => {
                    if (v.toUpperCase().startsWith(partial)) {
                        items.push({ insert: `${field}:${v}`, label: `${field}:${v}`, kind: 'value' });
                    }
                });
            }
        } else {
            // Token is a bare word — match keywords and operators
            suggestions.keywords?.forEach(k => {
                if (k.toLowerCase().startsWith(lower)) {
                    items.push({ insert: k, label: k, kind: 'field' });
                }
            });
            suggestions.operators?.forEach(op => {
                if (op.toLowerCase().startsWith(lower)) {
                    items.push({ insert: op + ' ', label: op, kind: 'op' });
                }
            });
        }
        return items.slice(0, 12);
    };

    const handleChange = (e) => {
        const v = e.target.value;
        onChange(v);
        // Recompute dropdown next tick so selectionStart is up-to-date
        setTimeout(() => {
            const { token } = computeToken();
            const items = computeItems(token);
            setDropdown({ open: items.length > 0, items, highlight: 0 });
        }, 0);
    };

    const applySuggestion = (item) => {
        const el = ref.current;
        if (!el) return;
        const { token, start } = computeToken();
        const before = value.slice(0, start);
        const after = value.slice(start + token.length);
        const next = before + item.insert + after;
        onChange(next);
        setDropdown({ open: false, items: [], highlight: 0 });
        requestAnimationFrame(() => {
            if (ref.current) {
                const pos = before.length + item.insert.length;
                ref.current.focus();
                ref.current.setSelectionRange(pos, pos);
            }
        });
    };

    const handleKeyDown = (e) => {
        if (dropdown.open && dropdown.items.length > 0) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                setDropdown(d => ({ ...d, highlight: (d.highlight + 1) % d.items.length }));
                return;
            }
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                setDropdown(d => ({ ...d, highlight: (d.highlight - 1 + d.items.length) % d.items.length }));
                return;
            }
            if (e.key === 'Tab' || (e.key === 'Enter' && !e.shiftKey && !multiline)) {
                // In single-line mode, Enter with dropdown open picks suggestion
                // In multiline mode, Tab picks suggestion (Enter stays as newline)
                if (e.key === 'Tab' || (e.key === 'Enter' && !multiline && dropdown.open)) {
                    e.preventDefault();
                    applySuggestion(dropdown.items[dropdown.highlight]);
                    return;
                }
            }
            if (e.key === 'Escape') {
                setDropdown({ open: false, items: [], highlight: 0 });
                return;
            }
        }
        if (e.key === 'Enter' && !e.shiftKey && !multiline && onEnter) {
            e.preventDefault();
            onEnter();
        }
    };

    const handleBlur = () => {
        // Delay to allow click events to register
        setTimeout(() => setDropdown({ open: false, items: [], highlight: 0 }), 150);
    };

    const commonProps = {
        ref,
        value,
        onChange: handleChange,
        onKeyDown: handleKeyDown,
        onBlur: handleBlur,
        placeholder,
        className: `form-input ${className}`,
        style: { fontFamily: 'monospace', fontSize: 13, ...style },
    };

    return (
        <div style={{ position: 'relative' }}>
            {multiline ? (
                <textarea rows={rows} {...commonProps} />
            ) : (
                <input type="text" {...commonProps} />
            )}
            {dropdown.open && (
                <div style={{
                    position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 50,
                    marginTop: 2, background: 'var(--card-bg, #1a1a24)', border: '1px solid var(--border-accent)',
                    borderRadius: 6, maxHeight: 220, overflowY: 'auto',
                    boxShadow: '0 6px 18px rgba(0,0,0,0.5)',
                }}>
                    {dropdown.items.map((item, i) => (
                        <div key={i}
                            onMouseDown={(e) => { e.preventDefault(); applySuggestion(item); }}
                            style={{
                                padding: '6px 12px', cursor: 'pointer', fontSize: 13, fontFamily: 'monospace',
                                background: i === dropdown.highlight ? 'rgba(124,58,237,0.25)' : 'transparent',
                                color: item.kind === 'op' ? '#C084FC' : 'var(--text-primary, #E0E0E0)',
                            }}>
                            {item.label}
                            <span className="text-xs text-muted" style={{ marginLeft: 8, opacity: 0.6 }}>
                                {item.kind}
                            </span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
