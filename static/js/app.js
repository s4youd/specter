let allResults = [];
let currentSessionId = null;
let expandedRows = new Set();
let expandedSecrets = new Set();   // secKeyOf(s) -> survives re-renders
let streamingActive = false;
let activeTabs = {};

function extractSecretValue(matchedText) {
    // JS port of validators.extract_value: longest quoted segment,
    // bare key=value fallback, else the trimmed whole match (Telegram /
    // webhook style where the match IS the secret). Fail-open: never drop.
    let value = String(matchedText || '').trim();
    if (!value) return '';
    let best = '';
    for (const q of ['"', "'", '`']) {
        const qi = value.indexOf(q);
        if (qi >= 0) {
            const qe = value.lastIndexOf(q);
            if (qe > qi) {
                const cand = value.slice(qi + 1, qe);
                if (cand.length > best.length) best = cand;
            }
        }
    }
    if (best) return best.trim();
    if (value.includes('=') && !/\s/.test(value.trim())) {
        const parts = value.split('=');
        if (parts.length === 2 && parts[1].trim()) {
            return parts[1].trim().replace(/^["'`]|["'`]$/g, '');
        }
    }
    return value;
}
function canonicalSecretKey(type, match) {
    return (type || '').trim() + '||' + extractSecretValue(match).trim().substring(0, 300);
}
function normalizeEndpointUrl(url) {
    if (!url) return '';
    const u = String(url).trim();
    if (!u) return '';
    if (u.includes('/graphql#')) return u; // op name is identity
    try {
        // Relative path (no scheme/host): normalize trailing slash, keep query.
        if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(u)) {
            const hashIx = u.indexOf('#');
            const noFrag = hashIx >= 0 ? u.slice(0, hashIx) : u;
            const qIx = noFrag.indexOf('?');
            let path = qIx >= 0 ? noFrag.slice(0, qIx) : noFrag;
            const q = qIx >= 0 ? noFrag.slice(qIx) : '';
            if (path.length > 1 && path.endsWith('/')) path = path.replace(/\/+$/, '');
            return (path || '/') + q;
        }
        const parsed = new URL(u);
        const scheme = parsed.protocol.replace(':', '').toLowerCase();
        let host = (parsed.hostname || '').toLowerCase();
        if (!host) return u;
        const port = parsed.port;
        if (port && !((scheme === 'https' && port === '443') || (scheme === 'http' && port === '80'))) {
            host = host + ':' + port;
        }
        let path = parsed.pathname || '/';
        if (path.length > 1 && path.endsWith('/')) path = path.replace(/\/+$/, '');
        let out = scheme + '://' + host + path;
        if (parsed.search) out += parsed.search;
        return out;
    } catch { return u; }
}
function canonicalEndpointKey(ep) {
    const raw = (ep && (ep.absolute_url || ep.path)) || '';
    return normalizeEndpointUrl(raw);
}
function secKeyOf(s) {
    return canonicalSecretKey(s.type, s.match).substring(0, 300);
}
let abortController = null;
let isScanning = false;

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function isFileClean(f) {
    return !(f.secrets && f.secrets.length > 0) && !(f.endpoints && f.endpoints.length > 0);
}
function getVisibleFiles() { return allResults.filter(f => !isFileClean(f)); }
function consolidateSecrets(files) {
    // Same secret (type + normalized value) found in 3+ files (main or
    // sub-files) -> keep it once, with also_found_in listing the other file
    // URLs + also_found_details carrying line numbers. Survivor prefers a
    // main-file entry so its accordion stays visible. Mutates in place.
    const groups = new Map();
    files.forEach(f => {
        (f.secrets || []).forEach(s => {
            const k = canonicalSecretKey(s.type, s.match);
            if (!groups.has(k)) groups.set(k, []);
            groups.get(k).push({ arr: f.secrets, s, url: f.url, line: s.line || 0,
                                 rank: (f.file_id || 0) * 1e6 + (s.line || 0), main: true, sub: false });
        });
        (f.sub_files || []).forEach(sf => {
            (sf.secrets || []).forEach(s => {
                const k = canonicalSecretKey(s.type, s.match);
                if (!groups.has(k)) groups.set(k, []);
                groups.get(k).push({ arr: sf.secrets, s, url: sf.url || f.url, line: s.line || 0,
                                     rank: (f.file_id || 0) * 1e6 + 5e5 + (s.line || 0), main: false, sub: true });
            });
        });
    });
    groups.forEach(g => {
        const urls = [...new Set(g.map(x => x.url).filter(Boolean))];
        if (urls.length < 3) {
            // Idempotent re-runs: a lone survivor carrying prior
            // also_found_in means an earlier pass already consolidated;
            // leave it intact. Only clear when genuine duplicates are
            // present below threshold (they must display separately).
            if (g.length > 1) g.forEach(x => { delete x.s.also_found_in; delete x.s.also_found_details; });
            return;
        }
        g.sort((a, b) => (a.main === b.main ? a.rank - b.rank : (a.main ? -1 : 1)));
        g[0].s.also_found_in = urls.filter(u => u !== g[0].url);
        const seen = new Set();
        const details = [];
        g.slice(1).forEach(x => {
            const dk = x.url + '||' + x.line + '||' + (x.sub ? '1' : '0');
            if (!seen.has(dk)) { seen.add(dk); details.push({ url: x.url, line: x.line, sub_file: x.sub }); }
        });
        g[0].s.also_found_details = details;
        for (let i = 1; i < g.length; i++) {
            const ix = g[i].arr.indexOf(g[i].s);
            if (ix >= 0) g[i].arr.splice(ix, 1);
        }
    });
    return files;
}

function consolidateEndpoints(files, threshold) {
    // Same endpoint (normalized URL, method-agnostic) found in 2+ files ->
    // keep once with also_found_in + merged methods list. Query strings keep
    // rows distinct; fragments dropped except graphql#Op. Mutates in place.
    const th = threshold || 2;
    const groups = new Map();
    files.forEach(f => {
        (f.endpoints || []).forEach(e => {
            const k = canonicalEndpointKey(e);
            if (!k) return;
            if (!groups.has(k)) groups.set(k, []);
            groups.get(k).push({ arr: f.endpoints, e, url: f.url, line: e.line || 0,
                                 method: e.method || '', rank: (f.file_id || 0) * 1e6 + (e.line || 0),
                                 main: true, sub: false });
        });
        (f.sub_files || []).forEach(sf => {
            (sf.endpoints || []).forEach(e => {
                const k = canonicalEndpointKey(e);
                if (!k) return;
                if (!groups.has(k)) groups.set(k, []);
                groups.get(k).push({ arr: sf.endpoints, e, url: sf.url || f.url, line: e.line || 0,
                                     method: e.method || '', rank: (f.file_id || 0) * 1e6 + 5e5 + (e.line || 0),
                                     main: false, sub: true });
            });
        });
    });
    groups.forEach(g => {
        const urls = [...new Set(g.map(x => x.url).filter(Boolean))];
        if (urls.length < th) {
            if (g.length > 1) g.forEach(x => { delete x.e.also_found_in; delete x.e.also_found_details; delete x.e.methods; });
            return;
        }
        g.sort((a, b) => (a.main === b.main ? a.rank - b.rank : (a.main ? -1 : 1)));
        const survivor = g[0].e;
        const methods = [];
        g.forEach(x => { const m = (x.method || '').trim(); if (m && !methods.includes(m)) methods.push(m); });
        if (methods.length > 1) survivor.methods = methods; else delete survivor.methods;
        survivor.also_found_in = urls.filter(u => u !== g[0].url);
        const seen = new Set();
        const details = [];
        g.slice(1).forEach(x => {
            const dk = x.url + '||' + x.line + '||' + x.method + '||' + (x.sub ? '1' : '0');
            if (!seen.has(dk)) { seen.add(dk); details.push({ url: x.url, line: x.line, method: x.method, sub_file: x.sub }); }
        });
        survivor.also_found_details = details;
        for (let i = 1; i < g.length; i++) {
            const ix = g[i].arr.indexOf(g[i].e);
            if (ix >= 0) g[i].arr.splice(ix, 1);
        }
    });
    return files;
}

function consolidateDuplicates() { consolidateSecrets(allResults); consolidateEndpoints(allResults, 2); }

document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-body').forEach(c => c.classList.add('hidden'));
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.remove('hidden');
    });
});

document.getElementById('analyzeBtn').addEventListener('click', analyzeSingle);
document.getElementById('jsUrl').addEventListener('keydown', e => { if (e.key === 'Enter') analyzeSingle(); });
document.getElementById('analyzeMultipleBtn').addEventListener('click', analyzeMultiple);
document.getElementById('urlFile').addEventListener('change', handleFileSelect);
document.getElementById('analyzeFileBtn').addEventListener('click', analyzeFile);
document.getElementById('exportBtn').addEventListener('click', exportAllResults);
document.getElementById('toggleAllBtn').addEventListener('click', toggleAllRows);
document.getElementById('stopScanBtn').addEventListener('click', stopScan);
document.getElementById('searchInput').addEventListener('input', renderOutput);
document.getElementById('severityFilter').addEventListener('change', renderOutput);
document.getElementById('sortSelect').addEventListener('change', renderOutput);
document.getElementById('validateAllBtn').addEventListener('click', validateAllSecrets);


function handleFileSelect(e) {
    const file = e.target.files[0];
    if (file) {
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileName').classList.remove('hidden');
        document.getElementById('analyzeFileBtn').disabled = false;
    }
}

async function analyzeSingle() {
    const url = document.getElementById('jsUrl').value.trim();
    if (!url) return showError('Enter a URL');
    try { new URL(url); } catch { return showError('Invalid URL'); }
    let finalUrl = url;
    if (url.includes('0.0.0.0')) {
        finalUrl = url.replace('0.0.0.0', 'localhost');
        document.getElementById('jsUrl').value = finalUrl;
    }
    await analyze([finalUrl]);
}

async function analyzeMultiple() {
    const urls = document.getElementById('multipleUrls').value.split('\n')
        .map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    if (!urls.length) return showError('Enter at least one URL');
    await analyze(urls.map(u => u.includes('0.0.0.0') ? u.replace('0.0.0.0', 'localhost') : u));
}

async function analyzeFile() {
    const file = document.getElementById('urlFile').files[0];
    if (!file) return showError('Select a file');
    const text = await file.text();
    const urls = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    await analyze(urls);
}

function showLoading(show) { document.getElementById('loading').classList.toggle('hidden', !show); }

function setScanning(scanning) {
    isScanning = scanning;
    document.getElementById('stopScanBtn').classList.toggle('hidden', !scanning);
    document.querySelectorAll('.btn[data-scan]').forEach(b => {
        b.disabled = scanning;
        b.classList.toggle('scanning', scanning);
    });
    if (!scanning) abortController = null;
}

function stopScan() { if (abortController) { abortController.abort(); abortController = null; } }

function setProgress(percent, text, detail) {
    document.getElementById('loading-percent').textContent = Math.round(percent) + '%';
    document.getElementById('loading-text').textContent = text || 'Scanning...';
    document.getElementById('progress-fill').style.width = percent + '%';
    if (detail !== undefined) document.getElementById('progress-detail').textContent = detail || '';
}

async function analyze(urls) {
    const error = document.getElementById('error');
    const output = document.getElementById('output');
    error.classList.add('hidden');
    output.classList.add('hidden');
    hidePanel('validationPanel');
    showLoading(true);
    setScanning(true);
    allResults = [];
    expandedRows.clear();
    expandedSecrets.clear();
    streamingActive = false;
    activeTabs = {};
    setActionHint('Run a scan first, then validate with one click.');
    setProgress(0, 'Starting scan...', `${urls.length} file(s) to analyze`);
    abortController = new AbortController();

    try {
        if (urls.length > 1) {
            await analyzeStream(urls);
        } else {
            setProgress(10, 'Scanning...');
            const resp = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls }),
                signal: abortController.signal,
            });
            if (!resp.ok) {
                let msg = 'Analysis failed';
                try { msg = (await resp.json()).error || msg; } catch {}
                throw new Error(msg);
            }
            const data = await resp.json();
            if (!data || !data.results) throw new Error('Invalid response');
            currentSessionId = data.session_id;
            allResults = data.results;
            setProgress(100, 'Complete', `${data.results.length} file(s) analyzed`);
            consolidateDuplicates();
            renderOutput();
            output.classList.remove('hidden');
            updateActionHint();
        }
    } catch (err) {
        if (err.name === 'AbortError') {
            if (allResults.length > 0) {
                setProgress(100, 'Scan stopped', `${allResults.length} file(s) analyzed`);
                consolidateDuplicates();
                renderOutput();
                output.classList.remove('hidden');
                updateActionHint();
            } else {
                showError('Scan stopped. No files were analyzed.');
            }
        } else {
            showError(err.message || 'Failed');
        }
    } finally {
        setScanning(false);
        setTimeout(() => showLoading(false), 600);
    }
}

async function analyzeStream(urls) {
    const output = document.getElementById('output');
    streamingActive = true;
    const resp = await fetch('/api/analyze/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls }),
        signal: abortController.signal,
    });
    if (!resp.ok) {
        let msg = 'Analysis failed';
        try { msg = (await resp.json()).error || msg; } catch {}
        throw new Error(msg);
    }
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop();
            for (const line of lines) {
                if (!line.startsWith('data: ')) continue;
                try {
                    const event = JSON.parse(line.slice(6));
                    if (event.type === 'progress') {
                        setProgress(event.percent, `Scanning ${event.current + 1} of ${event.total}`, event.url);
                    } else if (event.type === 'file_result') {
                        allResults.push(event.result);
                        renderOutput(true); // arrival order, no consolidation yet
                        output.classList.remove('hidden');
                    } else if (event.type === 'complete') {
                        streamingActive = false;
                        allResults = event.results;
                        setProgress(100, 'Complete', `${allResults.length} file(s) analyzed`);
                        consolidateDuplicates();
                        renderOutput();
                        output.classList.remove('hidden');
                        updateActionHint();
                    }
                } catch {}
            }
        }
    } catch (err) {
        if (err.name !== 'AbortError') throw err;
        streamingActive = false;
        if (allResults.length > 0) {
            setProgress(100, 'Scan stopped', `${allResults.length} file(s) analyzed`);
            consolidateDuplicates();
            renderOutput();
            output.classList.remove('hidden');
            updateActionHint();
        }
    }
}

// ---------------- Validate All Secrets ----------------

function collectAllSecrets() {
    const out = [];
    getVisibleFiles().forEach(f => {
        (f.secrets || []).forEach(s => {
            out.push({ type: s.type, match: s.match, file: f.url, line: s.line,
                       also_found_in: s.also_found_in || [] });
        });
        (f.sub_files || []).forEach(sf => {
            (sf.secrets || []).forEach(s => {
                out.push({ type: s.type, match: s.match, file: sf.url, line: s.line,
                           also_found_in: s.also_found_in || [] });
            });
        });
    });
    return out;
}

function updateActionHint() {
    const nS = collectAllSecrets().length;
    let nU = 0;
    getVisibleFiles().forEach(f => { nU += (f.endpoints || []).length; });
    setActionHint(`${nS} secret${nS === 1 ? '' : 's'} found, ${nU} URL${nU === 1 ? '' : 's'} discovered (status, title & word count probed during scan) — validate secrets with one click. Safe read-only checks only.`);
}

function setActionHint(t) {
    const el = document.getElementById('actionHint');
    if (el) el.textContent = t;
}

function setBtnBusy(idOrEl, busy, label) {
    const btn = typeof idOrEl === 'string' ? document.getElementById(idOrEl) : idOrEl;
    if (!btn) return;
    btn.classList.toggle('busy', busy);
    if (busy) {
        btn.dataset.orig = btn.innerHTML;
        btn.innerHTML = `<span class="spin"></span><span>${label}</span>`;
    } else if (btn.dataset.orig) {
        btn.innerHTML = btn.dataset.orig;
        delete btn.dataset.orig;
    }
}

function secretsOfFile(f) {
    const out = [];
    (f.secrets || []).forEach(s => {
        out.push({ type: s.type, match: s.match, file: f.url, line: s.line });
    });
    return out;
}

async function validateSecrets(secrets, scopeName, busyBtn) {
    if (!secrets.length) return showError('No secrets found to validate yet - run a scan first.');
    const panel = document.getElementById('validationPanel');
    if (busyBtn) setBtnBusy(busyBtn, true, 'Validating…');
    panel.classList.remove('hidden');
    panel.innerHTML = `<div class="panel-head"><span class="panel-title">Validating ${secrets.length} secret(s) · ${esc(scopeName)}…</span><span class="spin"></span></div>
        <div class="panel-body"><div class="file-empty">Running safe read-only identity checks. Paired secrets are marked for manual review.</div></div>`;
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    try {
        const resp = await fetch('/api/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secrets }),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Validation failed');
        // Merge by file so per-file runs refresh only their own file's badges.
        const files = new Set(secrets.map(s => s.file));
        window._lastValidation = (window._lastValidation || [])
            .filter(r => !files.has(r.file))
            .concat(data.results || []);
        renderValidationPanel(data, scopeName);
        renderOutput(); // annotate secret rows with badges
        setActionHint(`Validation complete (${scopeName}): ${data.summary.valid} valid, ${data.summary.invalid} dead, ${data.summary.manual} need manual review, ${data.summary.unknown} inconclusive.`);
    } catch (err) {
        panel.innerHTML = `<div class="panel-head"><span class="panel-title">Validation failed</span>
            <button class="panel-close" data-close="validationPanel">&times;</button></div>
            <div class="panel-body"><div class="file-empty">${esc(err.message)}</div></div>`;
    } finally {
        if (busyBtn) setBtnBusy(busyBtn, false);
    }
}

async function validateAllSecrets() {
    await validateSecrets(collectAllSecrets(), 'all files', 'validateAllBtn');
}

async function validateFile(fid, btn) {
    const f = allResults.find(x => x.file_id === fid);
    if (!f) return;
    await validateSecrets(secretsOfFile(f), getFileName(f), btn || null);
}

function vBadgeClass(s) {
    return 'vbadge-' + (s || 'unknown');
}

function renderValidationPanel(data, scopeName) {
    const panel = document.getElementById('validationPanel');
    const s = data.summary;
    const rows = (data.results || []).map(r => `
        <div class="vrow">
            <div>
                <div class="vtype">${esc(r.type)}</div>
                <div class="vfile">${esc(r.file || '')}${r.line ? ' · L' + r.line : ''}</div>
            </div>
            <div>
                <div class="vmatch"><code>${esc(r.masked || '')}</code></div>
                <div class="vdetail">${esc(r.detail || '')}${r.status_code ? ' · HTTP ' + r.status_code : ''}</div>
                ${r.indicator ? `<div class="vdetail" style="opacity:.8">How to read: ${esc(r.indicator)}</div>` : ''}
                ${r.command ? `<div class="vcurl"><code>${esc(r.command)}</code><button class="copy-btn" data-copy="${escAttr(r.command)}">Copy</button></div>` : ''}
            </div>
            <div><span class="vbadge ${vBadgeClass(r.status)}">${esc(statusLabel(r.status))}</span></div>
        </div>`).join('');
    panel.innerHTML = `
        <div class="panel-head">
            <span class="panel-title">Secret validation · ${esc(scopeName || 'all files')} — what's valid, what's dead, what needs hands</span>
            <button class="panel-close" data-close="validationPanel">&times;</button>
        </div>
        <div class="vchips">
            <span class="vchip vchip-valid">● Valid <b>${s.valid}</b></span>
            <span class="vchip vchip-invalid">● Invalid / dead <b>${s.invalid}</b></span>
            <span class="vchip vchip-manual">● Needs manual <b>${s.manual}</b></span>
            <span class="vchip vchip-unknown">● Inconclusive <b>${s.unknown}</b></span>
        </div>
        <div class="panel-body">${rows || '<div class="file-empty">No results</div>'}</div>`;
}

function statusLabel(s) {
    if (s === 'valid') return 'Valid · live';
    if (s === 'invalid') return 'Invalid · dead';
    if (s === 'manual') return 'Needs hands';
    return 'Unknown';
}

// ---------------- Liveness ----------------

function hidePanel(id) {
    const el = document.getElementById(id);
    if (el) { el.classList.add('hidden'); el.innerHTML = ''; }
}

// ---------------- misc UI ----------------

function showError(msg) {
    const el = document.getElementById('error');
    el.textContent = msg;
    el.classList.remove('hidden');
    el.style.animation = 'shake 0.4s ease';
    setTimeout(() => el.style.animation = '', 400);
}

function esc(text) {
    if (text == null) return '';
    const d = document.createElement('div');
    d.textContent = String(text);
    return d.innerHTML;
}

function escAttr(text) {
    // esc() leaves " and ' intact, which terminates data-copy="..."/title="..."
    // attributes early (copy then truncates at the first quote). Entities are
    // decoded back automatically when read via dataset/getAttribute.
    return esc(text).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function getFileName(f) {
    try {
        const u = new URL(f.url);
        const parts = u.pathname.split('/').filter(Boolean);
        return parts[parts.length - 1] || u.hostname;
    } catch { return f.url; }
}

function getFileDir(f) {
    try {
        const u = new URL(f.url);
        const parts = u.pathname.split('/').filter(Boolean);
        parts.pop();
        return parts.length > 0 ? parts.join('/') : u.hostname;
    } catch { return ''; }
}

function getFileSeverity(f) {
    if ((f.secrets || []).length > 0) {
        return f.secrets.reduce((w, s) => {
            const o = SEVERITY_ORDER[s.severity] ?? 5;
            return o < (SEVERITY_ORDER[w] ?? 5) ? s.severity : w;
        }, 'info');
    }
    if ((f.internal_refs || []).length > 0) return 'warn';
    return 'ok';
}

function renderOutput(keepOrder) {
    // keepOrder=true during live streaming: preserve arrival order so rows
    // don't reshuffle under the user; sorting applies on completion.
    const qEl = document.getElementById('searchInput');
    const query = qEl ? qEl.value.trim().toLowerCase() : '';
    const sevFilter = document.getElementById('severityFilter').value;
    const sortBy = document.getElementById('sortSelect').value;

    renderSummary();
    let files = getVisibleFiles();

    if (query) {
        files = files.filter(f => {
            if (getFileName(f).toLowerCase().includes(query)) return true;
            if ((f.secrets || []).some(s => (s.type || '').toLowerCase().includes(query) || (s.match || '').toLowerCase().includes(query))) return true;
            if ((f.endpoints || []).some(ep => (ep.absolute_url || ep.path || '').toLowerCase().includes(query))) return true;
            return false;
        });
    }

    if (sevFilter !== 'all') {
        files = files.filter(f => (f.secrets || []).some(s => s.severity === sevFilter));
    }

    if (!keepOrder) {
        files.sort((a, b) => {
            switch (sortBy) {
                case 'severity':
                    return (SEVERITY_ORDER[getFileSeverity(a)] ?? 5) - (SEVERITY_ORDER[getFileSeverity(b)] ?? 5);
                case 'secrets':
                    return ((b.secrets || []).length) - ((a.secrets || []).length);
                case 'endpoints':
                    return ((b.endpoints || []).length) - ((a.endpoints || []).length);
                case 'type':
                    return getFileName(a).localeCompare(getFileName(b));
                case 'file':
                    return (a.url || '').localeCompare(b.url || '');
                default: return 0;
            }
        });
    }

    renderFileRows(files);
}

function renderSummary() {
    const el = document.getElementById('output-summary');
    const visible = getVisibleFiles();
    const totalSecrets = visible.reduce((s, f) => s + (f.secrets?.length || 0), 0);
    const totalEndpoints = visible.reduce((s, f) => s + (f.endpoints?.length || 0), 0);
    const totalInternal = visible.reduce((s, f) => s + (f.internal_refs?.length || 0), 0);
    const totalEmails = visible.reduce((s, f) => s + (f.emails?.length || 0), 0);

    const items = [
        { val: visible.length, lbl: 'Files', cls: '', key: null },
        { val: totalSecrets, lbl: 'Secrets', cls: totalSecrets > 0 ? 'danger' : '', key: 'secrets' },
        { val: totalEndpoints, lbl: 'Endpoints', cls: '', key: 'endpoints' },
        { val: totalInternal, lbl: 'Internal', cls: totalInternal > 0 ? 'warn' : '', key: 'internals' },
        { val: totalEmails, lbl: 'Emails', cls: '', key: 'emails' },
    ];

    el.innerHTML = items.map(i => {
        const clickable = i.key && i.val > 0;
        return `<div class="summary-stat ${i.cls} ${clickable ? 'clickable' : ''}" ${clickable ? `data-panel="${i.key}"` : ''}>
            <span class="summary-val">${i.val}</span>
            <span class="summary-lbl">${i.lbl}</span>
        </div>`;
    }).join('');

    el.querySelectorAll('.summary-stat[data-panel]').forEach(stat => {
        stat.addEventListener('click', () => toggleGlobalPanel(stat.dataset.panel));
    });
}

let activeGlobalPanel = null;

function toggleGlobalPanel(type) {
    const panel = document.getElementById('globalPanel');
    if (activeGlobalPanel === type) {
        panel.classList.add('hidden');
        activeGlobalPanel = null;
        document.querySelectorAll('.summary-stat').forEach(s => s.classList.remove('active'));
        return;
    }
    activeGlobalPanel = type;
    document.querySelectorAll('.summary-stat').forEach(s => {
        s.classList.toggle('active', s.dataset.panel === type);
    });
    renderGlobalPanel(type);
    panel.classList.remove('hidden');
}

function renderGlobalPanel(type) {
    const panel = document.getElementById('globalPanel');
    const visible = getVisibleFiles();
    let html = '';

    if (type === 'secrets') {
        const allSecrets = [];
        visible.forEach(f => {
            (f.secrets || []).forEach(s => { allSecrets.push({ ...s, _file: getFileName(f), _url: f.url }); });
        });
        allSecrets.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
        html = `<div class="global-panel-header">
            <span class="global-panel-title">All Secrets (${allSecrets.length})</span>
            <button class="global-panel-close" onclick="closeGlobalPanel()">&times;</button>
        </div>
        <div class="global-panel-body">
            ${allSecrets.length === 0 ? '<div class="file-empty">No secrets found</div>' : `
            <table class="secrets-tbl">
                <thead><tr><th>Type</th><th>Match</th><th>Severity</th><th>File</th><th>Line</th></tr></thead>
                <tbody>${allSecrets.map(s => {
                    const dupN = Array.isArray(s.also_found_in) ? s.also_found_in.length + 1 : 0;
                    return `
                    <tr>
                        <td class="sec-type">${esc(s.type)}${dupN >= 3 ? `<span class="dup-badge" title="Same secret found in ${dupN} files">×${dupN}</span>` : ''}</td>
                        <td class="sec-match"><code>${esc((s.match || '').substring(0, 90))}${(s.match || '').length > 90 ? '…' : ''}</code>
                            <button class="mini-copy mini-copy-inline" data-copy="${escAttr(s.match || '')}" title="Copy secret value">
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2 2v1"/></svg>
                            </button>
                            ${dupN >= 3 ? `<span class="dup-wrap dup-wrap-row">
                                <button class="dup-toggle" data-dup-toggle aria-expanded="false"
                                        title="Show every file containing this secret">
                                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                                    <span>also in ${dupN} files</span>
                                </button>
                                <span class="dup-files">${(s.also_found_in || []).map(u => `<a href="${escAttr(u)}" target="_blank" rel="noopener" title="${escAttr(u)}">${esc(shortFileName(u))}</a>`).join('')}</span>
                            </span>` : ''}
                        </td>
                        <td><span class="severity severity-${s.severity}">${esc(s.severity)}</span></td>
                        <td class="sec-file"><a href="${escAttr(s._url)}" target="_blank" rel="noopener">${esc(s._file)}</a></td>
                        <td class="sec-line">L${s.line}</td>
                    </tr>`; }).join('')}</tbody>
            </table>`}
        </div>`;
    } else if (type === 'endpoints') {
        const allEps = [];
        visible.forEach(f => {
            (f.endpoints || []).forEach(ep => { allEps.push({ ...ep, _file: getFileName(f), _url: f.url }); });
        });
        html = `<div class="global-panel-header">
            <span class="global-panel-title">All Endpoints (${allEps.length})</span>
            <button class="global-panel-close" onclick="closeGlobalPanel()">&times;</button>
        </div>
        <div class="global-panel-body">
            ${allEps.length === 0 ? '<div class="file-empty">No endpoints found</div>' : `
            <div class="endpoints-list">${allEps.map(ep => endpointRow(ep, null)).join('')}</div>`}
        </div>`;
    } else if (type === 'internals') {
        const allInt = [];
        visible.forEach(f => {
            (f.internal_refs || []).forEach(r => { allInt.push({ ...r, _file: getFileName(f), _url: f.url }); });
        });
        html = `<div class="global-panel-header">
            <span class="global-panel-title">All Internal References (${allInt.length})</span>
            <button class="global-panel-close" onclick="closeGlobalPanel()">&times;</button>
        </div>
        <div class="global-panel-body">
            <table class="secrets-tbl">
                <thead><tr><th>Type</th><th>Match</th><th>Severity</th><th>File</th><th>Line</th></tr></thead>
                <tbody>${allInt.map(r => `
                    <tr>
                        <td class="sec-type">${esc(r.type)}</td>
                        <td class="sec-match"><code>${esc((r.match || '').substring(0, 120))}</code></td>
                        <td><span class="severity severity-${r.severity}">${esc(r.severity)}</span></td>
                        <td class="sec-file"><a href="${escAttr(r._url)}" target="_blank" rel="noopener">${esc(r._file)}</a></td>
                        <td class="sec-line">L${r.line}</td>
                    </tr>`).join('')}</tbody>
            </table>
        </div>`;
    } else if (type === 'emails') {
        const allEmails = [];
        visible.forEach(f => {
            (f.emails || []).forEach(e => { allEmails.push({ ...e, _file: getFileName(f), _url: f.url }); });
        });
        html = `<div class="global-panel-header">
            <span class="global-panel-title">All Emails (${allEmails.length})</span>
            <button class="global-panel-close" onclick="closeGlobalPanel()">&times;</button>
        </div>
        <div class="global-panel-body">
            <table class="secrets-tbl">
                <thead><tr><th>Email</th><th>Type</th><th>File</th><th>Line</th></tr></thead>
                <tbody>${allEmails.map(e => `
                    <tr>
                        <td class="sec-match"><code>${esc(e.match)}</code></td>
                        <td class="sec-type">${esc(e.type)}</td>
                        <td class="sec-file"><a href="${escAttr(e._url)}" target="_blank" rel="noopener">${esc(e._file)}</a></td>
                        <td class="sec-line">L${e.line}</td>
                    </tr>`).join('')}</tbody>
            </table>
        </div>`;
    }
    panel.innerHTML = html;
}

function closeGlobalPanel() {
    const panel = document.getElementById('globalPanel');
    panel.classList.add('hidden');
    activeGlobalPanel = null;
    document.querySelectorAll('.summary-stat').forEach(s => s.classList.remove('active'));
}
window.closeGlobalPanel = closeGlobalPanel;

function endpointRow(ep, live) {
    const url = ep.absolute_url || ep.path;
    const probe = (live || ep.probe || {});
    const status = probe.status;
    const title = probe.title || '';
    const wc = probe.word_count || 0;
    let statusCls = 'ep-status';
    if (status) {
        if (status >= 200 && status < 300) statusCls += ' status-ok';
        else if (status >= 300 && status < 400) statusCls += ' status-redirect';
        else if (status >= 400 && status < 500) statusCls += ' status-client-err';
        else if (status >= 500) statusCls += ' status-server-err';
        else statusCls += ' status-unknown';
    }
    const methodCls = 'method-' + (ep.method || 'get').toLowerCase().replace(/[^a-z]/g, '');
    const dupN = Array.isArray(ep.also_found_in) ? ep.also_found_in.length + 1 : 0;
    const methods = Array.isArray(ep.methods) && ep.methods.length > 1
        ? `<span class="ep-title" title="Seen as: ${escAttr(ep.methods.join(', '))}">${esc(ep.methods.join(' · '))}</span>` : '';
    const dupNote = dupN >= 2
        ? `<span class="dup-wrap dup-wrap-row">
            <button class="dup-toggle" data-dup-toggle aria-expanded="false"
                    title="Show every file containing this endpoint">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                <span>also in ${dupN} files</span>
            </button>
            <span class="dup-files">${(ep.also_found_in || []).map(u => `<a href="${escAttr(u)}" target="_blank" rel="noopener" title="${escAttr(u)}">${esc(shortFileName(u))}</a>`).join('')}</span>
        </span>` : '';
    return `<div class="endpoint-item">
        <span class="method-tag ${methodCls}">${esc(ep.method || 'GET')}</span>
        <a class="endpoint-url" href="${escAttr(url)}" target="_blank" rel="noopener">${esc(url)}</a>
        ${dupN >= 2 ? `<span class="dup-badge" title="Same endpoint found in ${dupN} files">×${dupN}</span>` : ''}
        ${status ? `<span class="${statusCls}">${status}</span>` : ''}
        ${title ? `<span class="ep-title" title="${escAttr(title)}">${esc(title)}</span>` : ''}
        ${methods}
        ${wc ? `<span class="ep-wc">${Number(wc).toLocaleString()}w</span>` : ''}
        <span class="endpoint-line">L${ep.line}</span>
        ${dupNote}
    </div>`;
}

function renderFileRows(files) {
    const container = document.getElementById('fileCards');
    container.className = 'file-rows';
    container.innerHTML = '';

    if (!files.length) {
        container.innerHTML = '<div class="empty-state"><p class="empty-title">No findings</p><p class="empty-desc">All analyzed files are clean</p></div>';
        return;
    }

    files.forEach(f => {
        const row = document.createElement('div');
        row.className = 'file-row';
        const severity = getFileSeverity(f);
        const secCount = f.secrets?.length || 0;
        const epCount = f.endpoints?.length || 0;
        const intCount = f.internal_refs?.length || 0;
        const hasErrors = f.errors?.length > 0;
        const hasSubs = (f.sub_files || []).length > 0;
        const isExpanded = expandedRows.has(f.file_id);
        const activeTab = activeTabs[f.file_id] || 'secrets';

        const counts = [];
        if (secCount > 0) counts.push(`<span class="file-count count-critical">${secCount} secret${secCount !== 1 ? 's' : ''}</span>`);
        if (epCount > 0) counts.push(`<span class="file-count count-endpoint">${epCount} ep${epCount !== 1 ? 's' : ''}</span>`);
        if (intCount > 0) counts.push(`<span class="file-count count-warn">${intCount} int</span>`);
        if (hasErrors) counts.push(`<span class="file-count count-critical">error</span>`);
        if (!counts.length) counts.push(`<span class="file-count count-ok">clean</span>`);

        row.innerHTML = `
            <div class="file-row-header" data-fid="${f.file_id}">
                <span class="file-expand ${isExpanded ? 'expanded' : ''}">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                </span>
                <span class="file-sev-dot ${severity}"></span>
                <span class="file-name" title="${escAttr(f.url)}">${f.url && f.url.startsWith('http') ? `<a href="${escAttr(f.url)}" target="_blank" rel="noopener">${esc(getFileName(f))}</a>` : esc(getFileName(f))}</span>
                <span class="file-url">${esc(getFileDir(f))}</span>
                <div class="file-counts">${counts.join('')}</div>
                <div class="row-actions">
                    ${secCount > 0 ? `<button class="row-btn" data-validate-file="${f.file_id}" title="Validate this file's secrets only">Validate</button>` : ''}
                </div>
            </div>
            <div class="file-row-body ${isExpanded ? 'expanded' : ''}" data-fid="${f.file_id}">
              <div class="file-row-inner">
                <div class="dropdown-tabs">
                    <button class="dropdown-tab ${activeTab === 'secrets' ? 'active' : ''}" data-fid="${f.file_id}" data-tab="secrets">Secrets (${secCount})</button>
                    <button class="dropdown-tab ${activeTab === 'endpoints' ? 'active' : ''}" data-fid="${f.file_id}" data-tab="endpoints">Endpoints (${epCount})</button>
                    ${hasSubs ? `<button class="dropdown-tab ${activeTab === 'subfiles' ? 'active' : ''}" data-fid="${f.file_id}" data-tab="subfiles">Sub Files (${f.sub_files.length})</button>` : ''}
                </div>
                <div class="dropdown-panel ${activeTab === 'secrets' ? 'active' : ''}" data-fid="${f.file_id}" data-panel="secrets">
                    ${secCount > 0 ? renderSecretsTable(f.secrets) : '<div class="file-empty">No secrets detected</div>'}
                </div>
                <div class="dropdown-panel ${activeTab === 'endpoints' ? 'active' : ''}" data-fid="${f.file_id}" data-panel="endpoints">
                    ${epCount > 0 ? renderEndpointsList(f.endpoints) : '<div class="file-empty">No endpoints detected</div>'}
                </div>
                ${hasSubs ? `<div class="dropdown-panel ${activeTab === 'subfiles' ? 'active' : ''}" data-fid="${f.file_id}" data-panel="subfiles">
                    ${renderSubFiles(f.sub_files)}
                </div>` : ''}
              </div>
            </div>
        `;

        row.querySelector('.file-row-header').addEventListener('click', (e) => {
            if (e.target.closest('a') || e.target.closest('.row-btn')) return;
            toggleRow(f.file_id);
        });
        row.querySelectorAll('.dropdown-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.stopPropagation();
                const fid = parseInt(tab.dataset.fid);
                const tabName = tab.dataset.tab;
                activeTabs[fid] = tabName;
                const body = tab.closest('.file-row-body');
                body.querySelectorAll('.dropdown-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabName));
                body.querySelectorAll('.dropdown-panel').forEach(p => p.classList.toggle('active', p.dataset.panel === tabName));
            });
        });

        container.appendChild(row);
    });
}

function inlineValidationBadge(s) {
    const list = window._lastValidation || [];
    if (!list.length) return '';
    const sameType = list.filter(x => x.type === s.type);
    if (sameType.length !== 1) return '';
    const r = sameType[0];
    return ` <span class="secbadge vbadge-${r.status}">${esc(statusLabel(r.status))}</span>`;
}

function renderExcerpt(s) {
    const ex = (Array.isArray(s.excerpt) && s.excerpt.length)
        ? s.excerpt
        : [{ n: s.line, text: s.line_content || s.match || '', hit: true }];
    const match = s.match || '';
    return ex.map(L => {
        const text = String(L.text == null ? '' : L.text);
        let html;
        if (L.hit && match && text.includes(match)) {
            const i = text.indexOf(match);
            html = esc(text.slice(0, i)) + '<span class="ctx-hl">'
                + esc(match) + '</span>' + esc(text.slice(i + match.length));
        } else {
            html = esc(text) || ' ';
        }
        return `<div class="codeline${L.hit ? ' hit' : ''}"><span class="lineno">${L.n}</span><span class="codetext">${html}</span></div>`;
    }).join('');
}

function excerptRange(s) {
    if (Array.isArray(s.excerpt) && s.excerpt.length) {
        const ns = s.excerpt.map(L => L.n);
        return Math.min(...ns) + '–' + Math.max(...ns);
    }
    return s.line;
}

function shortFileName(url) {
    try {
        const u = new URL(url);
        const parts = u.pathname.split('/').filter(Boolean);
        return parts[parts.length - 1] || u.hostname;
    } catch { return url; }
}

function toggleDup(btn) {
    // Open/close an Also-found-in file list. Pure DOM toggle so it stays
    // working after every re-render; returns the new open state.
    const wrap = btn.closest('.dup-wrap');
    const open = wrap ? wrap.classList.toggle('open') : false;
    if (btn.setAttribute) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    return open;
}
function renderAlsoFound(s) {
    const extra = Array.isArray(s.also_found_in) ? s.also_found_in : [];
    if (!extra.length) return '';
    return `
        <div class="sec-block-label">Duplicate secret</div>
        <div class="dup-wrap">
            <button class="dup-toggle" data-dup-toggle aria-expanded="false"
                    title="Show every file containing this secret">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                <span>Also found in ${extra.length + 1} files</span>
            </button>
            <div class="dup-files">${extra.map(u => `
                <a href="${escAttr(u)}" target="_blank" rel="noopener" title="${escAttr(u)}">${esc(shortFileName(u))}</a>`).join('')}
            </div>
        </div>`;
}

function renderSecretsTable(secrets) {
    if (!secrets.length) return '';
    return `<div class="secrets-list">${secrets.map((s, i) => {
        const v = s.validation || {};
        const short = (s.match || '').substring(0, 96);
        const cmdShort = v.command && v.command.length > 140
            ? v.command.substring(0, 140) + '…' : (v.command || '');
        const dupN = Array.isArray(s.also_found_in) ? s.also_found_in.length + 1 : 0;
        const skey = secKeyOf(s);
        return `
        <div class="sec-item${expandedSecrets.has(skey) ? ' open' : ''}" data-sec="${i}" data-skey="${escAttr(skey)}">
            <div class="sec-head" data-sec-toggle role="button" tabindex="0"
                 title="Expand to see value, context and validation">
                <span class="sev-dot sev-${s.severity}"></span>
                <span class="sec-head-main">
                    <span class="sec-head-type">${esc(s.type)}${inlineValidationBadge(s)}${dupN >= 3 ? `<span class="dup-badge" title="Same secret found in ${dupN} files">×${dupN} files</span>` : ''}</span>
                    <span class="sec-head-match"><code>${esc(short)}${(s.match || '').length > 96 ? '…' : ''}</code></span>
                </span>
                <span class="severity severity-${s.severity}">${esc(s.severity)}</span>
                <span class="sec-line">L${s.line}</span>
                <button class="mini-copy" data-copy="${escAttr(s.match || '')}" title="Copy secret value">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2 2v1"/></svg>
                    <span>Copy</span>
                </button>
                <span class="sec-chev">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                </span>
            </div>
            <div class="sec-body"><div class="sec-body-inner">
                <div class="sec-block-label">Secret value</div>
                <div class="sec-value-row">
                    <code class="sec-value">${esc(s.match || '')}</code>
                    <button class="copy-btn" data-copy="${escAttr(s.match || '')}">Copy secret</button>
                </div>
                ${renderAlsoFound(s)}
                <div class="sec-block-label">Found in context <span class="sec-lines">lines ${esc(String(excerptRange(s)))}</span></div>
                <div class="sec-code">${renderExcerpt(s)}</div>
                ${v.command ? `
                <div class="sec-block-label">Validate ${v.requires_pairing ? '<span class="sec-lines">needs a paired value — manual</span>' : ''}</div>
                <div class="vcurl"><code>${esc(cmdShort)}</code><button class="copy-btn" data-copy="${escAttr(v.command)}">Copy</button></div>
                ${v.indicator ? `<div class="vdetail">${esc(v.indicator)}</div>` : ''}` : ''}
            </div></div>
        </div>`;
    }).join('')}</div>`;
}

function renderEndpointsList(endpoints) {
    if (!endpoints.length) return '';
    return `<div class="endpoints-list">${endpoints.map(ep => endpointRow(ep)).join('')}</div>`;
}

function renderSubFiles(subFiles) {
    if (!subFiles.length) return '<div class="file-empty">No sub-files found</div>';
    return `<div class="sub-files-section">
        <div class="sub-files-header">Recursively Analyzed JS Files</div>
        ${subFiles.map(sf => {
            const secCount = (sf.secrets || []).length;
            const epCount = (sf.endpoints || []).length;
            return `<div class="sub-file-card">
                <div class="sub-file-url">${esc(sf.url)}</div>
                <div class="sub-file-stats">
                    ${secCount > 0 ? `<span class="count-critical">${secCount} secrets</span>` : ''}
                    ${epCount > 0 ? `<span class="count-endpoint">${epCount} endpoints</span>` : ''}
                    ${secCount === 0 && epCount === 0 ? '<span class="count-ok">clean</span>' : ''}
                </div>
            </div>`;
        }).join('')}
    </div>`;
}

function toggleRow(fileId) {
    if (expandedRows.has(fileId)) expandedRows.delete(fileId);
    else expandedRows.add(fileId);
    const body = document.querySelector(`.file-row-body[data-fid="${fileId}"]`);
    const icon = document.querySelector(`.file-row-header[data-fid="${fileId}"] .file-expand`);
    if (body) body.classList.toggle('expanded');
    if (icon) icon.classList.toggle('expanded');
}

let allExpanded = false;
function toggleAllRows() {
    allExpanded = !allExpanded;
    const btn = document.getElementById('toggleAllBtn');
    btn.textContent = allExpanded ? 'Collapse All' : 'Expand All';
    getVisibleFiles().forEach(f => {
        if (allExpanded) expandedRows.add(f.file_id);
        else expandedRows.delete(f.file_id);
        const body = document.querySelector(`.file-row-body[data-fid="${f.file_id}"]`);
        const icon = document.querySelector(`.file-row-header[data-fid="${f.file_id}"] .file-expand`);
        if (body) body.classList.toggle('expanded', allExpanded);
        if (icon) icon.classList.toggle('expanded', allExpanded);
    });
}

document.addEventListener('click', e => {
    const closeBtn = e.target.closest('[data-close]');
    if (closeBtn) { hidePanel(closeBtn.dataset.close); return; }
    const copyBtn = e.target.closest('[data-copy]');
    if (copyBtn) {
        e.stopPropagation();
        const txt = copyBtn.dataset.copy || '';
        const done = () => {
            if (copyBtn.dataset.orig === undefined) {
                copyBtn.dataset.orig = copyBtn.innerHTML;
            }
            copyBtn.innerHTML = 'Copied';
            copyBtn.classList.add('copied');
            setTimeout(() => {
                copyBtn.innerHTML = copyBtn.dataset.orig;
                delete copyBtn.dataset.orig;
                copyBtn.classList.remove('copied');
            }, 1200);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(txt).then(done).catch(() => fallbackCopy(txt, done));
        } else {
            fallbackCopy(txt, done);
        }
        return;
    }
    const valBtn = e.target.closest('[data-validate-file]');
    if (valBtn) {
        validateFile(parseInt(valBtn.dataset.validateFile), valBtn);
        return;
    }
    const dupBtn = e.target.closest('[data-dup-toggle]');
    if (dupBtn) {
        e.stopPropagation();
        toggleDup(dupBtn);
        return;
    }
    const secHead = e.target.closest('[data-sec-toggle]');
    if (secHead) {
        const item = secHead.closest('.sec-item');
        if (item) {
            const key = item.dataset.skey;
            if (item.classList.toggle('open')) { if (key) expandedSecrets.add(key); }
            else if (key) { expandedSecrets.delete(key); }
        }
        return;
    }
});

// Keyboard access for secret accordion headers (Enter / Space).
document.addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target && e.target.matches
        && e.target.matches('[data-sec-toggle]')) {
        e.preventDefault();
        const item = e.target.closest('.sec-item');
        if (item) {
            const key = item.dataset.skey;
            if (item.classList.toggle('open')) { if (key) expandedSecrets.add(key); }
            else if (key) { expandedSecrets.delete(key); }
        }
    }
});

function fallbackCopy(text, done) {
    try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    } catch {}
    if (done) done();
}

function buildExportData() {
    const visible = getVisibleFiles();
    return {
        session_id: currentSessionId,
        total_files: visible.length,
        exported_at: new Date().toISOString(),
        validation: window._lastValidation || [],
        liveness: [],
        files: visible.map(f => ({
            file_id: f.file_id,
            url: f.url,
            file_size: f.file_size,
            analysis_timestamp: f.analysis_timestamp,
            errors: f.errors || [],
            summary: {
                total_secrets: (f.secrets || []).length,
                total_endpoints: (f.endpoints || []).length,
                total_internal_refs: (f.internal_refs || []).length,
                total_emails: (f.emails || []).length,
                total_comments: (f.comments || []).length,
                total_source_maps: (f.source_maps || []).length,
            },
            secrets: (f.secrets || []).map(s => ({
                type: s.type, severity: s.severity, match: s.match,
                line: s.line, line_content: s.line_content, context: s.context || null,
                beautified_context: s.beautified_context || null,
                excerpt: s.excerpt || null,
                excerpt_pretty: s.excerpt_pretty || null,
                also_found_in: s.also_found_in || null,
                also_found_details: s.also_found_details || null,
                validation: s.validation || null,
            })),
            endpoints: (f.endpoints || []).map(ep => {
                return {
                    method: ep.method, methods: ep.methods || null,
                    path: ep.path, absolute_url: ep.absolute_url,
                    line: ep.line, line_content: ep.line_content, full_match: ep.full_match,
                    probe: ep.probe || null,
                    also_found_in: ep.also_found_in || null,
                    also_found_details: ep.also_found_details || null,
                };
            }),
            internal_refs: f.internal_refs || [],
            emails: f.emails || [],
            comments: f.comments || [],
            source_maps: f.source_maps || [],
            sub_files: f.sub_files || [],
        })),
    };
}

function exportAllResults() {
    if (!allResults.length) return;
    const data = buildExportData();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `specter-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

document.addEventListener('click', e => {
    const clearBtn = e.target.closest('.clear-btn');
    if (!clearBtn || clearBtn.hasAttribute('data-copy')) return;
    const targetId = clearBtn.dataset.clear;
    if (!targetId) return;
    const el = document.getElementById(targetId);
    if (!el) return;
    el.value = '';
    el.focus();
    el.dispatchEvent(new Event('input', { bubbles: true }));
});
