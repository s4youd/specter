#!/usr/bin/env python3
"""
Specter - JavaScript Security Analyzer (v3 consolidated).
Flask server: analyze JS, validate-all secrets, check liveness of URLs.
"""

import os
import json
import time
import threading
import ipaddress
from urllib.parse import urlparse
from collections import defaultdict
import concurrent.futures

from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from flask_cors import CORS
from specter import JavaScriptAnalyzer

try:
    from validators import (live_validate_secret, extract_value,
                            get_validation, render_curl)
    HAS_VALIDATORS = True
except ImportError:
    HAS_VALIDATORS = False

    def live_validate_secret(_l, _v, timeout=8):
        return {"checked": False, "reason": "validators unavailable"}

    def extract_value(m):
        return m

    def get_validation(_):
        return None

    def render_curl(_a, _b):
        return None

app = Flask(__name__)
CORS(app)

analyzer = JavaScriptAnalyzer()

sessions = {}
sessions_lock = threading.Lock()

rate_limits = defaultdict(list)
rate_lock = threading.Lock()
RATE_LIMIT = 20
RATE_WINDOW = 60

SESSION_TTL = 1800
MAX_SESSIONS = 100

# Opt-in for local testing only: allow private/loopback targets through the
# SSRF guard (/api/analyze + /api/liveness). NEVER enable on a public server.
ALLOW_PRIVATE = os.environ.get('SPECTER_ALLOW_PRIVATE', 'false').lower() == 'true'
if ALLOW_PRIVATE:
    print('[!] SPECTER_ALLOW_PRIVATE=true: private/loopback targets allowed. '
          'Local testing only - do not expose this server publicly.')


def cleanup_sessions():
    while True:
        time.sleep(300)
        now = time.time()
        with sessions_lock:
            expired = [k for k, v in sessions.items() if now - v.get('created', 0) > SESSION_TTL]
            for k in expired:
                del sessions[k]


cleanup_thread = threading.Thread(target=cleanup_sessions, daemon=True)
cleanup_thread.start()


def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')


def check_rate_limit(ip):
    now = time.time()
    with rate_lock:
        rate_limits[ip] = [t for t in rate_limits[ip] if now - t < RATE_WINDOW]
        if len(rate_limits[ip]) >= RATE_LIMIT:
            return False
        rate_limits[ip].append(now)
        return True


def is_safe_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                return False
        except ValueError:
            pass
        blocked = ('localhost', '127.0.0.1', '0.0.0.0', '[::1]')
        if hostname in blocked:
            return False
        return True
    except Exception:
        return False


def parse_urls_from_request():
    """Return (urls, error_response)."""
    if request.is_json:
        data = request.get_json()
        if not data:
            return None, (jsonify({'error': 'Invalid JSON'}), 400)
        urls = data.get('urls', [])
        if isinstance(urls, str):
            urls = [urls]
        if not urls:
            url = (data.get('url') or '').strip()
            if url:
                urls = [url]
        if not urls:
            return None, (jsonify({'error': 'URL(s) required'}), 400)
    else:
        if 'file' in request.files:
            file = request.files['file']
            if file.filename:
                content = file.read().decode('utf-8', errors='ignore')
                urls = [line.strip() for line in content.split('\n')
                        if line.strip() and not line.strip().startswith('#')]
                if not urls:
                    return None, (jsonify({'error': 'No valid URLs in file'}), 400)
            else:
                return None, (jsonify({'error': 'No file uploaded'}), 400)
        else:
            return None, (jsonify({'error': 'No data provided'}), 400)
    urls = [u.strip() for u in urls if u and u.strip()]
    return urls, None


def result_to_dict(result, idx):
    return {
        'file_id': idx + 1,
        'url': result.url,
        'secrets': result.secrets or [],
        'endpoints': result.endpoints or [],
        'internal_refs': result.internal_refs or [],
        'comments': result.comments or [],
        'emails': result.emails or [],
        'source_maps': result.source_maps or [],
        'errors': result.errors or [],
        'file_size': result.file_size,
        'analysis_timestamp': result.analysis_timestamp,
        'sub_files': result.sub_files or [],
    }


def error_result(url, idx, error_msg):
    return {
        'file_id': idx + 1,
        'url': url,
        'errors': [error_msg],
        'secrets': [], 'endpoints': [],
        'internal_refs': [], 'comments': [],
        'emails': [], 'source_maps': [],
        'file_size': 0, 'analysis_timestamp': '',
        'sub_files': [],
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    ip = get_client_ip()
    if not check_rate_limit(ip):
        return jsonify({'error': 'Rate limit exceeded. Try again shortly.'}), 429
    try:
        urls, err = parse_urls_from_request()
        if err:
            return err
        invalid = [] if ALLOW_PRIVATE else [u for u in urls if not is_safe_url(u)]
        if invalid:
            return jsonify({
                'error': f'Blocked {len(invalid)} unsafe URL(s). Only public HTTP/HTTPS URLs allowed.',
                'blocked': invalid[:5]
            }), 400

        with sessions_lock:
            if len(sessions) >= MAX_SESSIONS:
                oldest = min(sessions.keys(), key=lambda k: sessions[k].get('created', 0))
                del sessions[oldest]

        import uuid
        session_id = str(uuid.uuid4())
        with sessions_lock:
            sessions[session_id] = {
                'files': [], 'total': len(urls), 'completed': 0,
                'created': time.time()
            }

        results = []
        for idx, url in enumerate(urls):
            url = url.strip()
            if not url:
                continue
            try:
                # Defer probing in batch mode so each distinct URL is
                # probed once across all files (see probe_across_files).
                # Single-file scans behave exactly as before.
                result = analyzer.analyze(url, probe=(len(urls) == 1))
                rd = result_to_dict(result, idx)
                results.append(rd)
            except Exception as e:
                er = error_result(url, idx, f'Analysis failed: {str(e)}')
                results.append(er)

        try:
            # Fill probes once across the batch (no-op when already probed).
            analyzer.probe_across_files(results)
        except Exception:
            pass
        if len(results) > 1:
            try:
                analyzer.consolidate_secrets_cross_file(results, threshold=3)
                analyzer.consolidate_endpoints_cross_file(results, threshold=2)
            except Exception:
                pass
        with sessions_lock:
            sessions[session_id]['files'] = results
            sessions[session_id]['completed'] = len(results)

        return jsonify({
            'session_id': session_id,
            'total_files': len(results),
            'results': results,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analyze/stream', methods=['POST'])
def analyze_stream():
    ip = get_client_ip()
    if not check_rate_limit(ip):
        return jsonify({'error': 'Rate limit exceeded.'}), 429
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        urls = data.get('urls', [])
        if isinstance(urls, str):
            urls = [urls]
        if not urls:
            url = (data.get('url') or '').strip()
            if url:
                urls = [url]
        if not urls:
            return jsonify({'error': 'URL(s) required'}), 400

        urls = [u.strip() for u in urls if u.strip()]
        invalid = [] if ALLOW_PRIVATE else [u for u in urls if not is_safe_url(u)]
        if invalid:
            return jsonify({'error': f'Blocked {len(invalid)} unsafe URL(s).'}), 400

        def generate():
            total = len(urls)
            results = []
            for idx, url in enumerate(urls):
                progress = int((idx / total) * 100)
                yield f"data: {json.dumps({'type': 'progress', 'current': idx, 'total': total, 'percent': progress, 'url': url})}\n\n"
                try:
                    # Keep per-file probing here so live rows show status
                    # during streaming (no behavior change vs before).
                    result = analyzer.analyze(url)
                    rd = result_to_dict(result, idx)
                except Exception as e:
                    rd = error_result(url, idx, str(e))
                results.append(rd)
                yield f"data: {json.dumps({'type': 'file_result', 'result': rd})}\n\n"
            if len(results) > 1:
                try:
                    analyzer.consolidate_secrets_cross_file(results, threshold=3)
                    analyzer.consolidate_endpoints_cross_file(results, threshold=2)
                except Exception:
                    pass
            yield f"data: {json.dumps({'type': 'complete', 'total': total, 'results': results})}\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Validate-all-secrets: safe read-only live checks for every found secret.
# POST /api/validate  { secrets: [{type, match, file?, line?}] }
# -> { summary: {valid, invalid, manual, unknown, total}, results: [...] }
# ---------------------------------------------------------------------------

def _mask(value: str) -> str:
    v = value or ""
    if len(v) <= 10:
        return v[:4] + "..."
    return v[:6] + "..." + v[-4:]


@app.route('/api/validate', methods=['POST'])
def validate_all():
    ip = get_client_ip()
    if not check_rate_limit(ip):
        return jsonify({'error': 'Rate limit exceeded.'}), 429
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({'error': 'Invalid JSON'}), 400
    secrets = data.get('secrets', [])
    if not isinstance(secrets, list) or not secrets:
        return jsonify({'error': 'Provide secrets: [{type, match}]'}), 400
    if len(secrets) > 300:
        return jsonify({'error': 'Too many secrets in one batch (max 300).'}), 400

    # De-duplicate by canonical (type + extracted value) so the same
    # secret in different assignment styles validates once. Origin files
    # are preserved for attribution.
    seen = set()
    queue = []
    for s in secrets:
        if not isinstance(s, dict):
            continue
        label = (s.get('type') or '').strip()
        match = (s.get('match') or '').strip()
        if not label or not match:
            continue
        try:
            key = analyzer.canonical_secret_key(label, match)
        except Exception:
            key = (label, match[:200])
        if key in seen:
            continue
        seen.add(key)
        queue.append({'type': label, 'match': match[:300],
                      'file': s.get('file', ''), 'line': s.get('line', ''),
                      'also_found_in': s.get('also_found_in') or []})

    def _check(item):
        label, match = item['type'], item['match']
        value = extract_value(match)
        entry = get_validation(label)
        command = render_curl(label, value) if entry else None
        indicator = entry.get('indicator') if entry else None
        manual = True if not entry else bool(entry.get('manual', False))
        # Paired types are always manual even if entry says otherwise.
        if label in getattr(analyzer, 'PAIRED_SECRET_TYPES', set()):
            manual = True
        if manual:
            return {
                'type': label, 'file': item['file'], 'line': item['line'],
                'also_found_in': item.get('also_found_in') or [],
                'masked': _mask(value), 'status': 'manual',
                'detail': 'Needs a paired value / manual step - see curl command.',
                'command': command, 'indicator': indicator,
            }
        live = live_validate_secret(label, value)
        if not live.get('checked'):
            return {
                'type': label, 'file': item['file'], 'line': item['line'],
                'also_found_in': item.get('also_found_in') or [],
                'masked': _mask(value), 'status': 'manual',
                'detail': live.get('reason', 'Manual validation required.'),
                'command': command, 'indicator': indicator,
            }
        valid = live.get('valid')
        code = live.get('status_code')
        if valid is True:
            status, detail = 'valid', f'LIVE - issuer accepted it (HTTP {code}). Rotate immediately.'
        elif valid is False:
            status, detail = 'invalid', f'Dead/revoked - issuer rejected it (HTTP {code}).'
        else:
            status = 'unknown'
            detail = live.get('error') or f'Inconclusive (HTTP {code}). Retry or validate manually.'
        return {
            'type': label, 'file': item['file'], 'line': item['line'],
            'also_found_in': item.get('also_found_in') or [],
            'masked': _mask(value), 'status': status, 'status_code': code,
            'detail': detail, 'command': command, 'indicator': indicator,
        }

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(queue))) as ex:
        for r in ex.map(_check, queue):
            results.append(r)

    # Order: valid first, then invalid, manual, unknown.
    order = {'valid': 0, 'invalid': 1, 'manual': 2, 'unknown': 3}
    results.sort(key=lambda r: (order.get(r['status'], 4), r['type']))
    summary = {
        'total': len(results),
        'valid': sum(1 for r in results if r['status'] == 'valid'),
        'invalid': sum(1 for r in results if r['status'] == 'invalid'),
        'manual': sum(1 for r in results if r['status'] == 'manual'),
        'unknown': sum(1 for r in results if r['status'] == 'unknown'),
    }
    return jsonify({'summary': summary, 'results': results})


# ---------------------------------------------------------------------------
# Liveness check: re-probe every discovered URL (status code + title).
# POST /api/liveness { urls: [...] } -> { results: [{url,status,title,...}] }
# ---------------------------------------------------------------------------

@app.route('/api/liveness', methods=['POST'])
def liveness():
    ip = get_client_ip()
    if not check_rate_limit(ip):
        return jsonify({'error': 'Rate limit exceeded.'}), 429
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({'error': 'Invalid JSON'}), 400
    urls = data.get('urls', [])
    if isinstance(urls, str):
        urls = [urls]
    urls = [u.strip() for u in urls if isinstance(u, str) and u.strip()]
    # De-dupe, cap batch.
    seen, queue = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            queue.append(u)
    queue = queue[:300]
    if not queue:
        return jsonify({'error': 'Provide urls: [...]'}), 400
    # SSRF guard: same policy as /api/analyze (public hosts only, unless
    # the operator explicitly opted into private targets for local testing).
    if not ALLOW_PRIVATE:
        blocked = [u for u in queue if not is_safe_url(u)]
        if blocked:
            return jsonify({
                'error': f'Blocked {len(blocked)} unsafe URL(s). Only public HTTP/HTTPS URLs allowed '
                         f'(or set SPECTER_ALLOW_PRIVATE=true for local testing).',
                'blocked': blocked[:5],
            }), 400

    def _probe(u):
        try:
            p = analyzer.probe_endpoint(u)
            code = p.get('status')
            if code is None:
                alive = 'dead'
            elif 200 <= code < 300:
                alive = 'live'
            elif 300 <= code < 400:
                alive = 'redirect'
            elif code in (401, 403):
                alive = 'protected'
            elif 400 <= code < 500:
                alive = 'not-found'
            else:
                alive = 'server-error'
            return {'url': u, 'status': code,
                    'title': p.get('title', '') or '',
                    'word_count': p.get('word_count', 0),
                    'content_length': p.get('content_length', 0),
                    'final_url': p.get('final_url', u) or u,
                    'content_type': p.get('content_type', '') or '',
                    'liveness': alive}
        except Exception as e:
            return {'url': u, 'status': None, 'title': '',
                    'word_count': 0, 'content_length': 0,
                    'final_url': u, 'content_type': '',
                    'liveness': 'error', 'error': str(e)[:200]}

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(queue))) as ex:
        for r in ex.map(_probe, queue):
            results.append(r)

    def _key(r):
        s = r['status']
        return (0 if s and 200 <= s < 300 else 1 if s else 2, -(s or 0))
    results.sort(key=_key)
    summary = {
        'total': len(results),
        'live': sum(1 for r in results if r['liveness'] == 'live'),
        'redirect': sum(1 for r in results if r['liveness'] == 'redirect'),
        'protected': sum(1 for r in results if r['liveness'] == 'protected'),
        'dead': sum(1 for r in results if r['liveness'] in ('dead', 'error', 'not-found', 'server-error')),
    }
    return jsonify({'summary': summary, 'results': results})


@app.route('/api/export/<session_id>', methods=['GET'])
def export_results(session_id):
    with sessions_lock:
        if session_id not in sessions:
            return jsonify({'error': 'Session not found'}), 404
        data = sessions[session_id]
    return jsonify(data), 200, {
        'Content-Disposition': f'attachment; filename=specter-{session_id[:8]}.json'
    }


@app.route('/api/results/<session_id>', methods=['GET'])
def get_results(session_id):
    with sessions_lock:
        if session_id not in sessions:
            return jsonify({'error': 'Session not found'}), 404
        return jsonify(sessions[session_id])


if __name__ == '__main__':
    debug = os.environ.get('SPECTER_DEBUG', 'false').lower() == 'true'
    port = int(os.environ.get('SPECTER_PORT', '5000'))
    app.run(debug=debug, host='0.0.0.0', port=port)
