"""Regression suite for the Specter engine + server guards.

Run:  python -m pytest tests/ -q   (from the Specter/ directory)
"""
import os
import random
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from specter import JavaScriptAnalyzer
from validators import get_validation, render_curl, extract_value
import run as appmod

_rng = random.Random(11)


def rnd(n, alpha=string.ascii_letters + string.digits):
    return "".join(_rng.choice(alpha) for _ in range(n))


def hex_(n):
    return rnd(n, "0123456789abcdef")


def scan_hits(analyzer, js, label):
    """All matches for EVERY pattern row carrying this label (union).

    Several labels share rows (Supabase x2, Secret Generic x3, ...);
    testing only the first row would silently skip the rest.
    """
    import re
    out = []
    for pat, l, _ in analyzer.secret_patterns:
        if l != label:
            continue
        out.extend(m for m in re.finditer(pat, js, re.MULTILINE | re.IGNORECASE)
                   if not analyzer._is_false_positive_secret(m.group(0), label, js))
    return out


# ---------------------------------------------------------------- true positives

TP_CASES = {
    "GitHub Personal Access Token": lambda: 'ghp_' + rnd(36),
    "Stripe Live Secret Key": lambda: 'sk_live_' + rnd(24),
    "Stripe Live Publishable Key": lambda: 'pk_live_' + rnd(24),
    "Stripe Test Publishable Key": lambda: 'pk_test_' + rnd(24),
    "OpenAI API Key": lambda: 'sk-proj-' + rnd(48, string.ascii_letters + string.digits + '_-'),
    "Telegram Bot Token": lambda: rnd(9, '0123456789') + ':' + rnd(35),
    "AWS Access Key ID": lambda: 'AKIA' + rnd(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'),
    "Mailgun API Key": lambda: 'key-' + rnd(32),
    "SendGrid API Key": lambda: 'SG.' + rnd(22, string.ascii_letters + string.digits + '_-')
                                + '.' + rnd(43, string.ascii_letters + string.digits + '_-'),
    "Groq API Key": lambda: 'gsk_' + rnd(48, string.ascii_letters + string.digits),
    "Replicate API Token": lambda: 'r8_' + rnd(40),
    "Hugging Face Token": lambda: 'hf_' + rnd(34),
    "Snyk Token": lambda: f'snyk_token = "{hex_(8)}-{hex_(4)}-{hex_(4)}-{hex_(4)}-{hex_(12)}";',
    "Heroku API Key": lambda: f'heroku_api_key = "{hex_(8)}-{hex_(4)}-{hex_(4)}-{hex_(4)}-{hex_(12)}";',
    "Twilio App SID": lambda: f'twilio_app_sid = "AP{hex_(32)}";',
    "WakaTime API Key": lambda: f'wakatime_api_key = "{hex_(8)}-{hex_(4)}-{hex_(4)}-{hex_(4)}-{hex_(12)}";',
    "Sonarcloud Token": lambda: f'sonarcloud_token = "{hex_(40)}";',
    "GitHub Token (Generic)": lambda: f'github_token = "{rnd(40)}";',
    "Google Service Account Config": lambda: 'const c={"type": "service_account"};',
    "Google reCAPTCHA Site Key": lambda: f'const k="6L{rnd(38, string.ascii_letters + string.digits + "-_")}";',
    "Firebase Realtime Database URL": lambda: '"https://myapp-9f8k.firebaseio.com"',
    "AWS S3 Bucket Reference": lambda: '"https://assets-prod.s3.amazonaws.com/img.png"',
    "Postmark API Key": lambda: f'postmark_server_token = "{hex_(8)}-{hex_(4)}-{hex_(4)}-{hex_(4)}-{hex_(12)}";',
    "AMQP Connection String": lambda: '"amqp://svc:9f8K2xQ7mZ@broker.internal:5672/vhost"',
    "JWT Token": lambda: ('"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ%s.%s"'
                          % (rnd(27, string.ascii_letters + string.digits + '_-'),
                             rnd(40, string.ascii_letters + string.digits + '_-'))),
    "Supabase Service Key": lambda: ('supabase_service_role_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.%s.%s";'
                                     % (rnd(40, string.ascii_letters + string.digits + '_-'),
                                        rnd(40, string.ascii_letters + string.digits + '_-'))),
    # ---- Tier-1 additions ----
    "Anthropic OAuth Token": lambda: 'sk-ant-oat01-' + rnd(93, string.ascii_letters + string.digits + '_-'),
    "OpenAI Admin Key": lambda: 'sk-admin-' + rnd(48, string.ascii_letters + string.digits + '_-'),
    "Google OAuth Client Secret": lambda: 'GOCSPX-' + rnd(24, string.ascii_letters + string.digits + '_-'),
    "Supabase Secret Key": lambda: 'sb_secret_' + rnd(24, string.ascii_letters + string.digits + '_-'),
    "Supabase Publishable Key": lambda: 'sb_publishable_' + rnd(24, string.ascii_letters + string.digits + '_-'),
    "Notion Token": lambda: 'ntn_' + rnd(44),
    "Mapbox Secret Token": lambda: ('sk.eyJ' + rnd(12, string.ascii_letters + string.digits + '_-')
                                    + '.' + rnd(12, string.ascii_letters + string.digits + '_-')
                                    + '.' + rnd(16, string.ascii_letters + string.digits + '_-')),
    "Cloudinary URL": lambda: '"cloudinary://123456789012345:AbCdEfGhIjKlMnOp@mycloud"',
    "Discord Webhook URL": lambda: '"https://discord.com/api/webhooks/123456789012345678/%s"' % rnd(60),
    "Teams Webhook URL": lambda: '"https://myapp.webhook.office.com/webhookb2/abc123/IncomingWebhook/def456"',
    "Apify Token": lambda: 'apify_api_' + rnd(32),
    "Tavily API Key": lambda: 'tvly-' + rnd(32, string.ascii_letters + string.digits + '_-'),
    "LangSmith API Key": lambda: 'lsv2_' + rnd(24, string.ascii_letters + string.digits + '_-'),
    "Langfuse Secret Key": lambda: 'sk-lf-' + rnd(24, string.ascii_letters + string.digits + '_-'),
    "Cerebras API Key": lambda: 'csk-' + rnd(32, string.ascii_letters + string.digits + '_-'),
    "Docker Personal Access Token": lambda: 'dckr_pat_' + rnd(24, string.ascii_letters + string.digits + '_-'),
    "PyPI API Token": lambda: 'pypi-' + rnd(24, string.ascii_letters + string.digits + '_-'),
    "Terraform Cloud Token": lambda: 'atlasv1.' + rnd(24, string.ascii_letters + string.digits + '_-'),
    "Pulumi Access Token": lambda: 'pul-' + rnd(32, string.ascii_letters + string.digits + '_-'),
    "Netlify Token": lambda: 'nfp_' + rnd(32),
    "Grafana Service Token": lambda: 'glsa_' + rnd(32, string.ascii_letters + string.digits + '_-'),
    "Secret Key (Generic)": lambda: ('admin_secret="%s"; auth_secret="%s"; private_token="%s"; refresh_token="%s";'
                                     'api_secret="%s"; app_secret="%s"; master_key="%s"; session_secret="%s"; encryption_key="%s";'
                                     % (rnd(32), rnd(28), rnd(30), rnd(26), rnd(32), rnd(28), rnd(24), rnd(26), rnd(30))),
}


def _b64(n):
    return rnd(n, string.ascii_letters + string.digits + '+/=')


def test_framework_secrets_fire_as_generic():
    """Laravel APP_KEY + WordPress salts land on the entropy-gated generic label."""
    a = JavaScriptAnalyzer()
    js = 'APP_KEY=base64:%s;\ndefine(\'AUTH_KEY\', \'%s\');' % (_b64(44), rnd(64))
    assert scan_hits(a, js, "Secret Key (Generic)"), "framework secrets missed"


def test_docs_example_keys_suppressed():
    """Famous documentation example keys must never fire as findings.

    Regression: the suppression set is compared against the LOWERCASED
    match, so entries must be stored fully lowercase or they silently
    stop working (and Stripe's mixed-case docs keys would false-positive).
    """
    a = JavaScriptAnalyzer()
    # NOTE: keys assembled from parts - a single literal here would itself
    # trip secret push-protection (that's the point of this test).
    for prefix, body, label in [
        ('sk_test_', '4eC39HqLyjWDarjtT1zdp7dc', 'Stripe Test Secret Key'),
        ('sk_live_', '4eC39HqLyjWDarjtT1zdp7dc', 'Stripe Live Secret Key'),
        ('AKIA', 'IOSFODNN7EXAMPLE', 'AWS Access Key ID'),
    ]:
        real = prefix + body
        assert real.lower() in a.KNOWN_EXAMPLE_KEYS, f"set missing lower({real})"
        assert a._is_false_positive_secret(real, label, ''), f"docs example not suppressed: {real}"


def test_terraform_requires_dot():
    """atlasv1 without the literal dot must not match (prefix-only FP guard)."""
    a = JavaScriptAnalyzer()
    assert not scan_hits(a, 'const t="atlasv1_abcdef1234567890";', "Terraform Cloud Token")


def test_publishable_is_info_severity():
    a = JavaScriptAnalyzer()
    sev = dict((l, s) for _, l, s in a.secret_patterns)
    assert sev["Supabase Publishable Key"] == "info"
    assert sev["Stripe Test Publishable Key"] == "low"


def test_true_positives_combined_blob():
    """All TPs must fire even side-by-side (catches context over-suppression)."""
    a = JavaScriptAnalyzer()
    parts = []
    for label, make in TP_CASES.items():
        v = make()
        parts.append(v if ('=' in v or v.startswith('"') or v.startswith('const')) else f'k="{v}";')
    js = "\n".join(parts)
    missing = [l for l in TP_CASES if not scan_hits(a, js, l)]
    assert not missing, f"missing TPs: {missing}"


# ---------------------------------------------------------------- false positives

FP_JS = '\n'.join([
    '// TODO: add api_key_here later',
    'const api_key = "your_api_key";',
    'const token = "test";',
    'const password = "password";',
    'const key = "production";',
    'const cfg = process.env.STRIPE_KEY;',
    'var x = "extremelySecret123";',
    '// example: apiKey="my_cool_api_123"',
    '// @example token="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"',
    'const sentry = "https://abc123@example.com/1";',
    # NOTE: example keys below are assembled at runtime (never as one single
    # literal) so this file itself never trips secret push-protection.
    'const awsExample = "AKIAIOSFODNN7' + 'EXAMPLE";',
    'const mgFake = "key-' + 'A' * 32 + '";',
    'const id="123e4567-e89b-12d3-a456-426614174000";',  # bare UUID: not Postmark
    'const q="amqp://guest:guest@localhost/";',          # localhost broker
    'const parts = data.split(","); const latest = "v2"; const contest = "win";',
    'describe("auth", () => { it("logs in", () => { expect(true).toBe(true); }); });',
])


def test_no_false_positives():
    import re
    a = JavaScriptAnalyzer()
    hits = [(l, m.group(0)[:60]) for pat, l, _ in a.secret_patterns
            for m in re.finditer(pat, FP_JS, re.MULTILINE | re.IGNORECASE)
            if not a._is_false_positive_secret(m.group(0), l, FP_JS)]
    assert not hits, f"false positives: {hits}"


def test_boundary_words_do_not_suppress():
    """pk_test_ / .split( / latest_ / contest( must not read as test context."""
    a = JavaScriptAnalyzer()
    js = 'const p="pk_test_%s";\nconst k="ghp_%s";' % (rnd(24), rnd(36))
    assert scan_hits(a, js, "Stripe Test Publishable Key"), "pk_test_ self-suppressed"
    assert scan_hits(a, js, "GitHub Personal Access Token"), "neighbor suppressed by pk_test_"


# ---------------------------------------------------------------- same-brand scoping

def test_same_brand_scoping():
    a = JavaScriptAnalyzer()
    f = "https://app.uber.com/static/main.js"
    keep = ["https://app.uber.com/api", "https://uber.com/a", "https://cdn.uber.net/x.js",
            "https://uber.something.com/y", "https://app.uber.com/graphql#GetUser"]
    drop = ["https://www.facebook.com/tr", "https://maps.googleapis.com/maps/api/js",
            "https://api.stripe.com/v1/charges", "https://notlyft.com/x"]
    for u in keep:
        assert a._is_in_scope_url(u, f), f"wrongly dropped: {u}"
    assert a._is_in_scope_url("/api/v1/local", f), "relative URL dropped"
    for u in drop:
        assert not a._is_in_scope_url(u, f), f"wrongly kept: {u}"


def test_scope_ip_and_short_core():
    a = JavaScriptAnalyzer()
    assert a._is_in_scope_url("https://api.stripe.com/x", "http://127.0.0.1:9/app.js")
    assert a._is_in_scope_url("https://x.io/a", "https://x.io/app.js")
    assert a._is_in_scope_url("https://cdn.x.io/a", "https://x.io/app.js")
    assert not a._is_in_scope_url("https://other.io/a", "https://x.io/app.js")


def test_analyze_filters_third_party():
    a = JavaScriptAnalyzer()
    a.fetch_js_file = lambda url: ('fetch("/api/v1/users");\n'
                                   'fetch("https://app.uber.com/api/trips");\n'
                                   'fetch("https://www.facebook.com/tr");\n')
    a.probe_endpoints = lambda eps, max_workers=8: None
    res = a.analyze("https://app.uber.com/static/main.js")
    hosts = [e["absolute_url"] for e in res.endpoints]
    assert hosts and all("uber" in h for h in hosts), hosts


# ---------------------------------------------------------------- dedupe + validators

def test_generic_dedupe_prefers_specific():
    a = JavaScriptAnalyzer()
    g = {'type': 'API Key (Generic)', 'severity': 'high', 'match': 'apiKey = "AIza' + 'ABCDEF1234567890abcdef"',
         'line': 2, 'line_content': '', 'context': '', 'excerpt': [], 'excerpt_pretty': ''}
    o = {'type': 'Google API Key', 'severity': 'critical', 'match': 'AIza' + 'ABCDEF1234567890abcdef',
         'line': 2, 'line_content': '', 'context': '', 'excerpt': [], 'excerpt_pretty': ''}
    out = a._dedupe_secrets([g, o])
    assert [s['type'] for s in out] == ['Google API Key'], out


def test_every_pattern_label_has_validator():
    a = JavaScriptAnalyzer()
    orphans = sorted({l for _, l, _ in a.secret_patterns if not get_validation(l)})
    assert not orphans, f"labels without validator entry: {orphans}"


def test_render_curl_fills_value():
    cmd = render_curl("GitHub Personal Access Token", "ghp_DEMO")
    assert cmd and "ghp_DEMO" in cmd and "{value}" not in cmd
    assert extract_value('github_token = "abc123"') == "abc123"


# ---------------------------------------------------------------- server guards

def test_liveness_blocks_private_by_default():
    client = appmod.app.test_client()
    r = client.post("/api/liveness", json={"urls": ["http://169.254.169.254/latest/meta-data/"]})
    assert r.status_code == 400, r.get_data(as_text=True)[:200]
    body = r.get_json()
    assert "blocked" in body


def test_liveness_allows_private_with_opt_out(monkeypatch):
    monkeypatch.setattr(appmod, "ALLOW_PRIVATE", True)
    client = appmod.app.test_client()
    # unroutable test IP: must pass the guard (then fail to connect -> dead, not 400)
    r = client.post("/api/liveness", json={"urls": ["http://192.0.2.1:9/nope"]})
    assert r.status_code == 200, r.get_data(as_text=True)[:200]


def test_analyze_still_blocks_private(monkeypatch):
    monkeypatch.setattr(appmod, "ALLOW_PRIVATE", False)
    client = appmod.app.test_client()
    r = client.post("/api/analyze", json={"urls": ["http://127.0.0.1:9/app.js"]})
    assert r.status_code == 400


# ---------------------------------------------------------------- source maps

import json as _json  # noqa: E402
import sourcemap as _sm  # noqa: E402


def _map_text():
    return _json.dumps({
        "version": 3,
        "file": "app.js",
        "sources": ["webpack://app/src/secret-config.ts", "webpack://app/src/tiny.ts",
                    "webpack://app/src/empty.ts"],
        "sourcesContent": [
            ('export const API_KEY = "ghp_%s";\n'
             '// configuration for the admin dashboard bootstrap module\n'
             'fetch("/api/v1/admin");\n') % rnd(36),
            'x',
            None,
        ],
        "mappings": "AAAA",
    })


def test_parse_sourcemap_valid_and_invalid():
    assert _sm.parse_sourcemap(_map_text()) is not None
    assert _sm.parse_sourcemap('{"a": 1}') is None
    assert _sm.parse_sourcemap('not json{{{') is None
    assert _sm.parse_sourcemap('') is None
    assert _sm.source_paths(_map_text()) == [
        "webpack://app/src/secret-config.ts",
        "webpack://app/src/tiny.ts",
        "webpack://app/src/empty.ts",
    ]


def test_iter_original_sources_skips_tiny_and_nully():
    got = _sm.iter_original_sources(_map_text())
    assert len(got) == 1
    assert got[0]['path'] == "webpack://app/src/secret-config.ts"
    assert 'ghp_' in got[0]['content']


def test_analyze_recovers_embedded_sources():
    a = JavaScriptAnalyzer()
    main_js = 'var x = 1;\n//# sourceMappingURL=app.js.map\n'
    by_url = {
        "https://target.com/main.js": main_js,
        "https://target.com/app.js.map": _map_text(),
    }
    a.fetch_js_file = lambda url: by_url.get(url)
    a.probe_endpoints = lambda eps, max_workers=8: None
    res = a.analyze("https://target.com/main.js")
    urls = [s['url'] for s in res.sub_files]
    assert any(u.endswith('#webpack://app/src/secret-config.ts') for u in urls), urls
    # no raw-map double scan
    assert not any(u == "https://target.com/app.js.map" for u in urls), urls
    embedded = [s for s in res.sub_files if 'secret-config' in s['url']][0]
    types = [x['type'] for x in embedded['secrets']]
    assert "GitHub Personal Access Token" in types, types
    assert all(x.get('validation') for x in embedded['secrets'])
    assert any('/api/v1/admin' in e['absolute_url'] for e in embedded['endpoints'])
    paths = [r for r in res.internal_refs if r['type'] == 'Exposed Source Paths']
    assert len(paths) == 1 and '3 original source paths' in paths[0]['match']
    sm = [m for m in res.source_maps if m['match'] == 'app.js.map'][0]
    assert sm['embedded_sources'] == 1 and sm['source_paths'] == 3


def test_analyze_legacy_non_map_subfile():
    a = JavaScriptAnalyzer()
    by_url = {
        "https://target.com/main.js": 'import x from "./chunk.js";\n//# sourceMappingURL=bundle.map\n',
        "https://target.com/bundle.map": 'var not_a_map = 1;',
        "https://target.com/chunk.js": 'var y = 2;',
    }
    a.fetch_js_file = lambda url: by_url.get(url)
    a.probe_endpoints = lambda eps, max_workers=8: None
    res = a.analyze("https://target.com/main.js")
    assert any(s['url'] == "https://target.com/bundle.map" for s in res.sub_files)


# ---------------------------------------------------------------- env leftovers

def test_env_references_secretish_only():
    a = JavaScriptAnalyzer()
    js = ('const k = process.env.STRIPE_SECRET_KEY;\n'
          'const t = import.meta.env.VITE_API_TOKEN;\n'
          'const e = process.env.NODE_ENV;\n'
          'const p = process.env.PORT;\n'
          'const u = process.env.PUBLIC_URL;\n'
          'const d = process.env.DATABASE_URL;\n')
    a.fetch_js_file = lambda url: js
    a.probe_endpoints = lambda eps, max_workers=8: None
    res = a.analyze("https://target.com/app.js")
    got = sorted(r['match'] for r in res.internal_refs if r['type'] == 'Exposed Env Reference')
    assert got == ['import.meta.env.VITE_API_TOKEN', 'process.env.STRIPE_SECRET_KEY'], got


# ---------------------------------------------------------------- obfuscation flag

def test_obfuscation_flag_and_singularity():
    a = JavaScriptAnalyzer()
    obf = ('var _0x1a2b=["hello","world","test"];'
           'function _0x3c4d(_0x5e6f,_0x7a8b){return _0x1a2b[_0x5e6f];}'
           '_0x3c4d(_0x1a2b,_0x9c8d);')
    a.fetch_js_file = lambda url: obf
    a.probe_endpoints = lambda eps, max_workers=8: None
    res = a.analyze("https://target.com/app.js")
    flags = [r for r in res.internal_refs if r['type'] == 'Obfuscated Bundle']
    assert len(flags) == 1, flags
    a.fetch_js_file = lambda url: 'function hello(name){ return "hi " + name; }'
    res2 = a.analyze("https://target.com/app.js")
    assert not [r for r in res2.internal_refs if r['type'] == 'Obfuscated Bundle']


# ---------------------------------------------------------------- backoff + verdicts

class _FakeResp:
    def __init__(self, code, headers=None, url='https://x/', body=b''):
        self.status_code = code
        self.headers = headers or {}
        self.url = url
        self.content = body
        self.closed = False

    def close(self):
        self.closed = True


def test_probe_retries_429_then_succeeds(monkeypatch):
    import requests as _rq
    import time as _time
    calls, sleeps = [], []
    monkeypatch.setattr(_rq, 'get', lambda *a, **k: (calls.append(1),
        _FakeResp(429, {}, 'https://x/') if len(calls) == 1
        else _FakeResp(200, {'Content-Type': 'text/html'}, 'https://x/',
                        b'<html><head><title>T</title></head></html>'))[1])
    monkeypatch.setattr(_time, 'sleep', lambda s: sleeps.append(s))
    a = JavaScriptAnalyzer()
    out = a.probe_endpoint('https://x/')
    assert out['status'] == 200 and out['title'] == 'T', out
    assert len(calls) == 2 and len(sleeps) == 1


def test_probe_records_persistent_429(monkeypatch):
    import requests as _rq
    import time as _time
    monkeypatch.setattr(_rq, 'get', lambda *a, **k: _FakeResp(429, {}, 'https://x/'))
    monkeypatch.setattr(_time, 'sleep', lambda s: None)
    a = JavaScriptAnalyzer()
    out = a.probe_endpoint('https://x/')
    assert out['status'] == 429, out


def test_probe_honors_retry_after(monkeypatch):
    import requests as _rq
    import time as _time
    sleeps = []
    monkeypatch.setattr(_rq, 'get', lambda *a, **k: _FakeResp(429, {'Retry-After': '2'}, 'https://x/'))
    monkeypatch.setattr(_time, 'sleep', lambda s: sleeps.append(s))
    a = JavaScriptAnalyzer()
    a.probe_endpoint('https://x/')
    assert sleeps and abs(sleeps[0] - 2.0) < 0.45, sleeps  # + jitter <= 0.4


def test_safe_get_verdicts(monkeypatch):
    import requests as _rq
    from validators import _safe_get, _safe_post
    import time as _time
    monkeypatch.setattr(_time, 'sleep', lambda s: None)
    monkeypatch.setattr(_rq, 'get', lambda *a, **k: _FakeResp(429, {}, 'https://x/'))
    assert _safe_get('https://x/')['valid'] is None
    monkeypatch.setattr(_rq, 'get', lambda *a, **k: _FakeResp(503, {}, 'https://x/'))
    assert _safe_get('https://x/')['valid'] is None
    monkeypatch.setattr(_rq, 'get', lambda *a, **k: _FakeResp(401, {}, 'https://x/'))
    assert _safe_get('https://x/')['valid'] is False
    monkeypatch.setattr(_rq, 'get', lambda *a, **k: _FakeResp(
        200, {'Content-Type': 'application/json'}, 'https://x/', b'{}'))
    out = _safe_get('https://x/')
    assert out['valid'] is True and out['status_code'] == 200
    monkeypatch.setattr(_rq, 'post', lambda *a, **k: _FakeResp(429, {}, 'https://x/'))
    assert _safe_post('https://x/', {}, {})['valid'] is None


# ---------------------------------------------------------------- wordlist

def test_build_wordlist_basics():
    a = JavaScriptAnalyzer()
    js = ('const API_URL = "https://api.target.com/v1/admin_users";\n'
          'function fetchAdminUsers(userId){ return fetch(API_URL + "/" + userId); }\n'
          'var x = 1; const ok = true;\n')
    wl = a.build_wordlist(js)
    for tok in ('API_URL', 'admin_users', 'fetchAdminUsers', 'userId',
                'api.target.com/v1/admin_users', 'admin', 'users', 'target'):
        assert tok in wl, (tok, wl[:20])
    assert 'v1' not in wl, "2-char segments are noise by design"
    for tok in ('const', 'function', 'return', 'true', 'var'):
        assert tok not in wl, tok
    assert len(wl) == len(set(t.lower() for t in wl)), "case-insensitive dedupe"
    assert len(a.build_wordlist(js, limit=3)) == 3


def test_build_wordlist_empty():
    assert JavaScriptAnalyzer().build_wordlist('') == []
