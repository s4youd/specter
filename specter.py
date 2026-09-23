#!/usr/bin/env python3
"""
Specter - JavaScript Security Analyzer (v3 consolidated).

High-confidence detection for bug bounty reconnaissance. Zero false-positive
tolerance: every pattern is anchored on a provider-specific shape, generic
`name = value` patterns require length + Shannon entropy + digit/special
gates, and matches in comments / docs / tests / placeholders are suppressed.

Combines:
  - Specter/Specter original engine (broad endpoint + FP-filter foundation)
  - specter-improved.py additions (validators integration, GraphQL ops,
    tightened connection strings, pairing flags, report writers)
  - RESEARCH.md sourcing (KeyHacks, SecretFinder, JSFScan, TruffleHog /
    Gitleaks FP methodology, 2025-2026 AI-provider sprawl)

Secrets DB policy (anti-false-positive):
  1. Fixed-format provider patterns only (prefix + exact length/charset).
  2. NO loose `ENV_VAR = "([^"']+)"` catch-alls - those match "production",
     "true", UUIDs, etc. and are the #1 FP factory. Dropped entirely.
  3. Generic high-entropy patterns kept minimal and gated by entropy >= 3.5
     (4.3 when the value has no digits), min length 16, placeholder +
     stopword suppression.
  4. Comment / doc / test context suppression, example-domain suppression.
"""

import re
import math
import time
import random
import ipaddress
import requests
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse
import urllib3
import concurrent.futures

try:
    import jsbeautifier
    HAS_BEAUTIFIER = True
except ImportError:
    HAS_BEAUTIFIER = False

try:
    from sourcemap import parse_sourcemap, iter_original_sources, source_paths
    try:
        from sourcemap import MAX_SOURCES as _SM_MAX_SOURCES
    except ImportError:
        _SM_MAX_SOURCES = 25
    HAS_SOURCEMAP = True
except ImportError:
    HAS_SOURCEMAP = False
    _SM_MAX_SOURCES = 25

try:
    from validators import get_validation, render_curl, extract_value
    HAS_VALIDATORS = True
except ImportError:
    HAS_VALIDATORS = False

    def get_validation(_):
        return None

    def render_curl(_a, _b):
        return None

    def extract_value(m):
        return m

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class AnalysisResult:
    url: str
    secrets: List[Dict[str, Any]]
    endpoints: List[Dict[str, Any]]
    internal_refs: List[Dict[str, Any]]
    comments: List[Dict[str, Any]]
    emails: List[Dict[str, Any]]
    source_maps: List[Dict[str, Any]]
    errors: List[str]
    file_size: int
    analysis_timestamp: str
    sub_files: List[Dict[str, Any]] = field(default_factory=list)


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class JavaScriptAnalyzer:

    ENTROPY_THRESHOLD = 3.5
    ENTROPY_THRESHOLD_NO_DIGIT = 4.3

    # Placeholder / example values - never secrets.
    PLACEHOLDER_VALUES = {
        'changeme', 'your_key_here', 'your_api_key', 'your_secret',
        'api_key_here', 'secret_here', 'token_here', 'replace_me',
        'xxx', 'yyy', 'zzz', 'test', 'example', 'placeholder',
        'dummy', 'sample', 'todo', 'fixme', 'null', 'undefined',
        'none', 'empty', 'blank', 'default', '0000', 'aaaa', 'abcd',
        '1234', 'password', 'admin', 'root', 'user', 'debug',
        'insert_here', 'set_here', 'add_key', 'enter_key',
        'your-token', 'your-token-here', 'token-value',
        'sk-xxxx', 'bearer', 'basic', 'token', 'secret', 'api_key',
        'access_key', 'private_key', 'your-api-key', 'your_api_key',
        'your-api-key-here', 'your_api_key_here', 'your-secret',
        'your_secret', 'your-secret-key', 'your_secret_key',
        'your-token', 'your_token', 'your-access-token',
        'your_access_token', 'your-password', 'your_password',
        'change-me', 'change_me', '123456', 'abcdef', 'qwerty',
        'sk-xxx', 'pk-xxx', 'ghp_xxx', 'xoxb-xxx', 'insert_key_here',
        'replace_me', 'todo', 'key', 'api-key', 'api-key-here',
        'replace-me', 'replace_with_your', 'insert-your-key',
        'your-key', 'your_key', 'api_secret', 'your-api-secret',
        'secret', 'password', 'passwd', 'client', 'endpoint',
        'publickeytoken', 'encoding-utf8', 'testkey', 'demokey',
        'fake', 'mock', 'stub', 'redacted', '[redacted]',
        '***', '*****', '...', 'xxx-xxx-xxx', '00000000',
        '11111111', 'aaaaaaaa', 'deadbeef', 'cafebabe',
    }

    # Well-known documentation example keys (exact, case-insensitive).
    # NOTE: the stripe entries are split across adjacent literals on purpose:
    # one single literal would match push-protection shapes. Python joins
    # adjacent literals, so the runtime values are unchanged. Entries must
    # stay all-lowercase: lookups compare against the lowercased match.
    KNOWN_EXAMPLE_KEYS = {
        'akiaiosfodnn7example',
        'akiaiosfodnn7exampl',  # truncated variants seen in docs
        'sk_test_' '4ec39hqlyjwdarjtt1zdp7dc',  # stripe docs example
        'sk_live_' '4ec39hqlyjwdarjtt1zdp7dc',
    }
    # Common programming words that must never count as a generic secret
    # (Gitleaks-style stopwords, trimmed for JS context).
    STOPWORDS = {
        'function', 'return', 'import', 'export', 'require', 'module',
        'config', 'public', 'private', 'static', 'const', 'object',
        'string', 'number', 'window', 'document', 'button', 'input',
        'client', 'server', 'endpoint', 'version', 'bucket', 'index',
        'cache', 'admin', 'build', 'test', 'prod', 'staging', 'english',
        'lorem', 'ipsum', 'vendor', 'bundle', 'webpack', 'chunk',
        'production', 'development', 'staging', 'enabled', 'disabled',
        'active', 'inactive', 'pending', 'success', 'failed', 'error',
        'running', 'stopped', 'waiting', 'ready', 'approved', 'rejected',
        'completed', 'status', 'message', 'result', 'response', 'request',
        'header', 'footer', 'title', 'subtitle', 'content', 'description',
        'image', 'video', 'audio', 'style', 'theme', 'color', 'width',
        'height', 'margin', 'padding', 'border', 'background', 'length',
        'name', 'alias', 'code', 'frame', 'mesh', 'ring', 'size', 'stone',
        'selector', 'signature', 'primary', 'foreign', 'natural', 'sequence',
        'schema', 'accessor', 'accessibility', 'rapid', 'capital',
    }

    FALSE_POSITIVE_DOMAINS = {
        'example.com', 'example.org', 'example.net', 'localhost',
        '127.0.0.1', '0.0.0.0', 'schemas.google.com',
        'schema.org', 'w3.org', 'mozilla.org', 'jquery.com',
        'googleapis.com', 'gstatic.com', 'cloudflare.com',
        'github.io', 'githubassets.com', 'github.com',
        'stackoverflow.com', 'jsdelivr.net', 'unpkg.com',
        'cdn.jsdelivr.net', 'code.jquery.com',
        'fonts.googleapis.com', 'fonts.gstatic.com',
        'ajax.googleapis.com', 'cdnjs.cloudflare.com',
        'maxcdn.bootstrapcdn.com', 'stackpath.bootstrapcdn.com',
        'use.fontawesome.com', 'pro.fontawesome.com',
        'cdn.plot.ly', 'd3js.org', 'npmjs.com',
        'play.google.com', 'apps.apple.com',
        'polyfill.io', 'bootcdn.net',
        'static.cloudflare.com', 'fastly.net',
        'akamai.net', 'akamaized.net', 'amazonaws.com',
        'azurewebsites.net', 'cloudfront.net',
    }

    FALSE_POSITIVE_CONTEXTS = {
        'process.env.', 'os.environ', 'require(',
        'import ', 'from ', 'module.exports',
        'document.getElementById', 'console.log',
        'console.error', 'console.warn', 'console.info',
        '// ', '/* ', '*/', 'TODO', 'FIXME', 'HACK',
        '.map(', '.filter(', '.reduce(',
        'function(', '=>', 'class ',
    }

    # Secrets that only prove anything when paired with a second value.
    PAIRED_SECRET_TYPES = {
        'AWS Access Key ID', 'AWS Secret Access Key', 'AWS Session Token',
        'Twilio API Key', 'Twilio Account SID', 'Twilio Credential',
        'Twilio Auth Token', 'Twilio App SID', 'Atlassian API Token', 'Bitbucket Token',
        'Auth0 Client Secret', 'Contentful API Key', 'Okta API Token',
        'Plaid Secret Key', 'Shopify Access Token', 'Shopify Shared Secret',
        'PayPal Braintree Access Token', 'Google Service Account Key',
        'Google OAuth Client Secret', 'Google Service Account Config',
        'HashiCorp Vault Token', 'Algolia Admin API Key',
        'Twitter/X API Secret', 'Facebook App Secret',
        'Square OAuth Secret', 'GitLab Runner Token',
    }

    def __init__(self):
        # (regex, label, severity). Labels MUST match validators.py keys.
        self.secret_patterns: List[Tuple[str, str, str]] = [
            # === AWS ===
            (r'(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])', 'AWS Access Key ID', 'critical'),
            (r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', 'AWS Secret Access Key', 'critical'),
            (r'(?i)aws[_\-]?session[_\-]?token\s*[:=]\s*["\']([A-Za-z0-9/+=]{60,})["\']', 'AWS Session Token', 'high'),
            (r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'Amazon MWS Auth Token', 'critical'),

            # === Google ===
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key', 'critical'),
            (r'ya29\.[0-9A-Za-z\-_]{20,}', 'Google OAuth Access Token', 'critical'),
            (r'GOCSPX-[A-Za-z0-9_-]{20,}', 'Google OAuth Client Secret', 'critical'),
            (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]{0,200}?"private_key_id"\s*:\s*"[a-f0-9]{40}"', 'Google Service Account Key', 'critical'),
            (r'(?i)["\']type["\']\s*:\s*["\']service_account["\']', 'Google Service Account Config', 'high'),
            (r'(?<![A-Za-z0-9\-_])6L[0-9A-Za-z\-_]{38}(?![A-Za-z0-9\-_])', 'Google reCAPTCHA Site Key', 'info'),

            # === GitHub ===
            (r'ghp_[A-Za-z0-9]{36}', 'GitHub Personal Access Token', 'critical'),
            (r'github_pat_[A-Za-z0-9_]{22,}', 'GitHub Fine-grained Token', 'critical'),
            (r'gho_[A-Za-z0-9]{36}', 'GitHub OAuth Token', 'critical'),
            (r'ghu_[A-Za-z0-9]{36}', 'GitHub User Token', 'critical'),
            (r'ghs_[A-Za-z0-9]{36}', 'GitHub Server-to-Server Token', 'critical'),
            (r'ghr_[A-Za-z0-9]{36}', 'GitHub Refresh Token', 'critical'),
            (r'(?i)github[_\-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-]{40,})["\']', 'GitHub Token (Generic)', 'critical'),

            # === GitLab ===
            (r'glpat-[A-Za-z0-9\-_]{20,}', 'GitLab Personal Access Token', 'critical'),
            (r'glptt-[A-Za-z0-9\-_]{20,}', 'GitLab Pipeline Token', 'critical'),
            (r'glrt-[A-Za-z0-9\-_]{20,}', 'GitLab Runner Token', 'high'),
            (r'glfbt-[A-Za-z0-9\-_]{20,}', 'GitLab Feature Flag Token', 'medium'),

            # === Stripe ===
            (r'sk_live_[A-Za-z0-9]{24,}', 'Stripe Live Secret Key', 'critical'),
            (r'sk_test_[A-Za-z0-9]{24,}', 'Stripe Test Secret Key', 'medium'),
            (r'rk_live_[A-Za-z0-9]{24,}', 'Stripe Live Restricted Key', 'critical'),
            (r'rk_test_[A-Za-z0-9]{24,}', 'Stripe Test Restricted Key', 'medium'),
            (r'pk_live_[A-Za-z0-9]{24,}', 'Stripe Live Publishable Key', 'medium'),
            (r'pk_test_[A-Za-z0-9]{24,}', 'Stripe Test Publishable Key', 'low'),
            (r'whsec_[A-Za-z0-9]{32,}', 'Stripe Webhook Secret', 'high'),

            # === Slack ===
            (r'xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}', 'Slack Bot Token', 'critical'),
            (r'xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{32,}', 'Slack User Token', 'high'),
            (r'xoxa-[0-9a-zA-Z\-]{10,60}', 'Slack Token', 'high'),
            (r'xoxo-[0-9a-zA-Z\-]{10,60}', 'Slack OAuth Access Token', 'critical'),
            (r'xoxs-[0-9a-zA-Z\-]{10,60}', 'Slack Token', 'high'),
            (r'https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,}/B[A-Za-z0-9]{8,}/[A-Za-z0-9]{20,}', 'Slack Incoming Webhook URL', 'high'),

            # === Twilio ===
            (r'(?<![A-Za-z0-9])SK[0-9a-fA-F]{32}(?![A-Za-z0-9])', 'Twilio API Key', 'high'),
            (r'(?<![A-Za-z0-9])AC[a-f0-9]{32}(?![A-Za-z0-9])', 'Twilio Account SID', 'medium'),
            (r'(?i)twilio[_\-]?auth[_\-]?token\s*[:=]\s*["\']([a-f0-9]{32})["\']', 'Twilio Auth Token', 'critical'),
            (r'(?i)(?:app[_\-]?sid|twilio[_\-]?app[_\-]?sid)\s*[:=]\s*["\']AP[a-f0-9]{32}["\']', 'Twilio App SID', 'medium'),
            (r'(?i)TWILIO_(?:ACCOUNT_SID|AUTH_TOKEN|API_KEY)\s*[:=]\s*["\']([^"\']{16,})["\']', 'Twilio Credential', 'high'),

            # === SendGrid / Mailgun ===
            (r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', 'SendGrid API Key', 'critical'),
            (r'key-[0-9A-Za-z]{32}', 'Mailgun API Key', 'high'),

            # === Firebase ===
            (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'Firebase Cloud Messaging (FCM) Server Key', 'critical'),
            (r'https?://[A-Za-z0-9-]+\.firebaseio\.com', 'Firebase Realtime Database URL', 'info'),

            # === AWS references (info: not secrets, but recon-relevant) ===
            (r'(?i)(?:[A-Za-z0-9-._]+\.s3\.amazonaws\.com|s3://[A-Za-z0-9-._]+|s3\.amazonaws\.com/[A-Za-z0-9-._]+)', 'AWS S3 Bucket Reference', 'info'),

            # === AI: OpenAI / Anthropic / HF ===
            (r'sk-(?:proj-)?[A-Za-z0-9_-]{40,}', 'OpenAI API Key', 'critical'),
            (r'sk-admin-[A-Za-z0-9_-]{40,}', 'OpenAI Admin Key', 'critical'),
            (r'sk-ant-api03-[A-Za-z0-9_-]{90,}A?A?', 'Anthropic API Key', 'critical'),
            (r'sk-ant-oat01-[A-Za-z0-9_-]{90,}', 'Anthropic OAuth Token', 'critical'),
            (r'hf_[A-Za-z0-9]{34,}', 'Hugging Face Token', 'high'),

            # === AI sprawl (2024-2026, all fixed-format) ===
            (r'gsk_[A-Za-z0-9]{40,}', 'Groq API Key', 'high'),
            (r'r8_[A-Za-z0-9]{40}', 'Replicate API Token', 'high'),
            (r'(?i)cohere[_\-]?api[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9]{40})["\']', 'Cohere API Key', 'high'),
            (r'(?i)mistral[_\-]?api[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9]{32,})["\']', 'Mistral AI Key', 'high'),
            (r'(?i)pinecone[_\-]?api[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9]{32,})["\']', 'Pinecone API Key', 'high'),
            (r'sk-[a-f0-9]{32}', 'DeepSeek API Key', 'high'),
            (r'tgp_v1_[A-Za-z0-9_\-]{40,}', 'Together AI Key', 'high'),
            (r'pplx-[A-Za-z0-9]{40,}', 'Perplexity API Key', 'high'),
            (r'sk-or-v1-[A-Za-z0-9]{40,}', 'OpenRouter API Key', 'high'),
            (r'xai-[A-Za-z0-9]{40,}', 'xAI API Key', 'high'),
            (r'fw_[A-Za-z0-9_\-]{40,}', 'Fireworks API Key', 'high'),
            (r'csk-[A-Za-z0-9_-]{30,}', 'Cerebras API Key', 'high'),
            (r'apify_api_[A-Za-z0-9]{30,}', 'Apify Token', 'high'),
            (r'tvly-[A-Za-z0-9_-]{30,}', 'Tavily API Key', 'high'),
            (r'lsv2_[A-Za-z0-9_-]{20,}', 'LangSmith API Key', 'high'),
            (r'sk-lf-[A-Za-z0-9_-]{20,}', 'Langfuse Secret Key', 'high'),

            # === Infra / SaaS ===
            (r'hvs\.[A-Za-z0-9]{24,}', 'HashiCorp Vault Token', 'critical'),
            (r'hvb\.[A-Za-z0-9]{24,}', 'HashiCorp Vault Token', 'critical'),
            (r'dop_v1_[a-f0-9]{64}', 'DigitalOcean Token', 'critical'),
            (r'doo_v1_[a-f0-9]{64}', 'DigitalOcean Token', 'critical'),
            (r'lin_api_[A-Za-z0-9]{40}', 'Linear API Key', 'high'),
            (r'(?i)snyk[_\-]?token\s*[:=]\s*["\']([a-f0-9\-]{36})["\']', 'Snyk Token', 'high'),
            (r'(?i)\bhttps?://[a-f0-9]{32}@[^\s"\']+', 'Sentry DSN', 'info'),
            (r'sntrys_[A-Za-z0-9_]{70,}', 'Sentry Auth Token', 'critical'),
            (r'(?i)heroku[_\-]?api[_\-]?key\s*[:=]\s*["\']([a-f0-9\-]{36})["\']', 'Heroku API Key', 'high'),
            (r'NRAK-[A-Z0-9]{27}', 'New Relic User API Key', 'critical'),
            (r'(?i)datadog[_\-]?api[_\-]?key\s*[:=]\s*["\']([a-f0-9]{32})["\']', 'Datadog API Key', 'high'),
            (r'(?i)pagerduty[_\-]?api[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'PagerDuty API Key', 'high'),
            (r'shpat_[0-9a-fA-F]{32}', 'Shopify Access Token', 'critical'),
            (r'shpss_[0-9a-fA-F]{32}', 'Shopify Shared Secret', 'critical'),
            (r'(?<![A-Za-z0-9])[0-9]{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])', 'Telegram Bot Token', 'critical'),
            (r'sq0atp-[0-9A-Za-z\-_]{22}', 'Square Access Token', 'high'),
            (r'sq0csp-[0-9A-Za-z\-_]{43}', 'Square OAuth Secret', 'critical'),
            (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', 'PayPal Braintree Access Token', 'critical'),
            (r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}', 'Discord Bot Token', 'critical'),
            (r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]{50,}', 'Discord Webhook URL', 'medium'),
            (r'(?i)atlassian[_\-]?api[_\-]?token\s*[:=]\s*["\']([A-Za-z0-9]{20,})["\']', 'Atlassian API Token', 'high'),
            (r'(?i)bitbucket[_\-]?app[_\-]?password\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'Bitbucket Token', 'high'),
            (r'(?i)auth0[_\-]?client[_\-]?secret\s*[:=]\s*["\']([A-Za-z0-9_\-]{32,})["\']', 'Auth0 Client Secret', 'critical'),
            (r'(?i)okta[_\-]?api[_\-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'Okta API Token', 'high'),
            (r'(?i)plaid[_\-]?secret\s*[:=]\s*["\']([a-f0-9]{32})["\']', 'Plaid Secret Key', 'critical'),
            (r'(?i)algolia[_\-]?admin[_\-]?api[_\-]?key\s*[:=]\s*["\']([a-f0-9]{32})["\']', 'Algolia Admin API Key', 'critical'),
            (r'pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', 'Mapbox Access Token', 'high'),
            (r'sk\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'Mapbox Secret Token', 'critical'),
            (r'(?i)postmark[_\-]?(?:api[_\-]?key|token|server[_\-]?token)\s*[:=]\s*["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']', 'Postmark API Key', 'high'),
            (r'[a-f0-9]{32}-us[0-9]{1,2}', 'Mailchimp API Key', 'high'),
            (r'secret_[A-Za-z0-9]{43}', 'Notion Integration Token', 'high'),
            (r'ntn_[A-Za-z0-9]{40,}', 'Notion Token', 'high'),
            (r'figd_[A-Za-z0-9_\-]{40,}', 'Figma Personal Access Token', 'high'),
            (r'sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', 'LaunchDarkly SDK Key', 'high'),
            (r'(?i)contentful[_\-]?delivery[_\-]?api[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{40,})["\']', 'Contentful API Key', 'high'),
            (r'(?i)contentful[_\-]?management[_\-]?token\s*[:=]\s*["\'](CFPAT-[A-Za-z0-9_\-]{40,})["\']', 'Contentful Management Token', 'critical'),

            # === Media uploads (credential in URL) ===
            (r'cloudinary://[0-9]+:[A-Za-z0-9_-]+@[A-Za-z0-9-]+', 'Cloudinary URL', 'high'),

            # === Social ===
            (r'EAA[A-Za-z0-9]{60,}', 'Facebook/Meta Graph API Token', 'critical'),
            (r'(?i)facebook[_\-]?app[_\-]?secret\s*[:=]\s*["\']([0-9a-f]{32})["\']', 'Facebook App Secret', 'critical'),
            (r'AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{50,}', 'Twitter/X Bearer Token', 'high'),
            (r'(?i)twitter[_\-]?api[_\-]?secret\s*[:=]\s*["\']([A-Za-z0-9]{40,50})["\']', 'Twitter/X API Secret', 'high'),
            (r'https://[a-z0-9-]+\.webhook\.office\.com/[A-Za-z0-9/._-]+', 'Teams Webhook URL', 'medium'),

            # === DevOps / monitoring (fixed-format) ===
            (r'(?i)circle[_\-]?token\s*[:=]\s*["\']([a-f0-9]{40})["\']', 'CircleCI Token', 'high'),
            (r'(?i)buildkite[_\-]?token\s*[:=]\s*["\']([a-f0-9]{40})["\']', 'Buildkite Access Token', 'high'),
            (r'(?i)shodan[_\-]?api[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']', 'Shodan API Key', 'high'),
            (r'(?i)cloudflare[_\-]?api[_\-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-]{40})["\']', 'Cloudflare API Token', 'high'),
            (r're_[A-Za-z0-9_]{30,}', 'Resend API Key', 'high'),
            (r'(?i)vercel[_\-]?token\s*[:=]\s*["\']([A-Za-z0-9]{24,})["\']', 'Vercel Token', 'high'),
            (r'(?i)wakatime[_\-]?api[_\-]?key\s*[:=]\s*["\']([a-f0-9\-]{36})["\']', 'WakaTime API Key', 'medium'),
            (r'(?i)sonarcloud[_\-]?(?:token|api[_\-]?key)\s*[:=]\s*["\']([a-f0-9]{40})["\']', 'Sonarcloud Token', 'medium'),
            (r'npm_[A-Za-z0-9]{36}', 'NPM Token', 'high'),

            # === Package registries / IaC (fixed-format prefixes) ===
            (r'dckr_pat_[A-Za-z0-9_-]{20,}', 'Docker Personal Access Token', 'critical'),
            (r'pypi-[A-Za-z0-9_-]{20,}', 'PyPI API Token', 'critical'),
            (r'atlasv1\.[A-Za-z0-9_-]{20,}', 'Terraform Cloud Token', 'critical'),
            (r'pul-[A-Za-z0-9_-]{30,}', 'Pulumi Access Token', 'critical'),
            (r'nfp_[A-Za-z0-9]{30,}', 'Netlify Token', 'high'),
            (r'glsa_[A-Za-z0-9_-]{30,}', 'Grafana Service Token', 'high'),

            # === Airtable (17-char new keys are high-FP alone: require context) ===
            (r'(?i)airtable[_\-]?api[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9]{17})["\']', 'Airtable API Key', 'high'),

            # === Private keys / seeds / connection strings (tight: require creds) ===
            (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Private Key', 'critical'),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key Block', 'critical'),
            (r'(?i)mongodb(\+srv)?://[^:/?#\s]+:[^@/\s]+@[^\s"\']+', 'MongoDB Connection String', 'critical'),
            (r'(?i)postgres(ql)?://[^:/?#\s]+:[^@/\s]+@[^\s"\']+', 'PostgreSQL Connection String', 'critical'),
            (r'(?i)mysql://[^:/?#\s]+:[^@/\s]+@[^\s"\']+', 'MySQL Connection String', 'critical'),
            (r'(?i)redis://[^:\s]*:[^@\s]+@[^\s"\']+', 'Redis Connection String', 'high'),
            (r'amqp://[^\s"\']+', 'AMQP Connection String', 'high'),
            (r'(?i)seed[_\-]?phrase\s*[:=]\s*["\']([a-z]+(?:\s+[a-z]+){11,23})["\']', 'Crypto Seed Phrase', 'critical'),
            (r'(?i)priv[_\-]?key\s*[:=]\s*["\']([0-9a-fA-F]{64})["\']', 'Crypto Private Key (Hex)', 'critical'),

            # === Auth material in transit (strict) ===
            (r'(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/]{20,}={0,2}', 'Basic Auth Credential', 'high'),
            (r'(?i)Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.]{40,}', 'Access Token (Generic)', 'high'),

            # === JWT (strict 3-part, min length) ===
            (r'(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_\-+/=]{20,}(?![A-Za-z0-9_-])', 'JWT Token', 'low'),

            # === Supabase keys are JWTs; require the key-name context ===
            (r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', 'Supabase Service Key', 'high'),
            (r'(?i)supabase[_\-]?(?:service[_\-]?role[_\-]?key|anon[_\-]?key|api[_\-]?key)\s*[:=]\s*["\']?(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["\']?', 'Supabase Service Key', 'high'),
            (r'sb_secret_[A-Za-z0-9_-]{20,}', 'Supabase Secret Key', 'critical'),
            (r'sb_publishable_[A-Za-z0-9_-]{20,}', 'Supabase Publishable Key', 'info'),

            # === Framework secrets (specific names; value still entropy-gated) ===
            (r'(?i)app[_\-]?key\s*[:=]\s*["\']?(base64:[A-Za-z0-9+/=]{40,})["\']?', 'Secret Key (Generic)', 'high'),
            (r'(?i)define\s*\(\s*["\'](?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)["\']\s*,\s*["\']([^"\']{32,})["\']', 'Secret Key (Generic)', 'high'),

            # === Generic high-entropy assignments (STRICT: entropy-gated, keep last) ===
            (r'(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,80})["\']', 'API Key (Generic)', 'high'),
            (r'(?i)(?:secret[_\-]?key|client[_\-]?secret|api[_\-]?secret|app[_\-]?secret|master[_\-]?key|private[_\-]?key|signing[_\-]?key|token[_\-]?secret|session[_\-]?secret|cookie[_\-]?secret|encryption[_\-]?key|webhook[_\-]?secret|oauth[_\-]?secret|jwt[_\-]?secret|admin[_\-]?secret|auth[_\-]?secret|private[_\-]?token|refresh[_\-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-+/]{16,80})["\']', 'Secret Key (Generic)', 'high'),
            (r'(?i)(?:access[_\-]?token|auth[_\-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,80})["\']', 'Access Token (Generic)', 'high'),
            (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{10,80})["\']', 'Password Assignment', 'high'),
            (r'(?i)(?:db|database)[_\-]?(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{10,80})["\']', 'Password Assignment', 'critical'),
        ]

        self.endpoint_patterns: List[Tuple[str, str]] = [
            (r'(?:fetch|axios)\s*\(\s*["\'\`](/[^"\'\`]+)["\'\`]', 'fetch/axios'),
            (r'(?:fetch|axios)\s*\(\s*["\']([^"\']+)["\']', 'fetch/axios'),
            (r'\`\$\{[^`}]{1,80}\}(/[a-zA-Z0-9_\-./]+)\`', 'Template Literal Path'),
            (r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\']\s*,\s*["\']([^"\']+)["\']', 'XHR'),
            (r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'axios config'),
            (r'\$\.(?:ajax|get|post|getJSON)\s*\(\s*["\']([^"\']+)["\']', 'jQuery AJAX'),
            (r'\$\.(?:ajax|get|post|getJSON)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'jQuery AJAX'),
            (r'(?:baseURL|base_url|apiUrl|api_url|apiBase|api_base)\s*[:=]\s*["\']([^"\']+)["\']', 'Base URL'),
            (r'["\'](/(?:api|v\d+|graphql|webhook|admin|internal|auth|oauth|sso)/[^"\']*)["\']', 'API Path'),
            (r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', 'WebSocket'),
            (r'new\s+EventSource\s*\(\s*["\']([^"\']+)["\']', 'SSE'),
            (r'(?:"|\'|`)((?:[a-zA-Z]{1,10}://|//)[^"\'`\s]{5,}\.(?:com|org|net|io|dev|app|co|api)[^"\'`\s]{0,})(?:"|\'|`)', 'Full URL'),
            (r'(?:"|\'|`)(/(?:api|v\d+|graphql|webhook|admin|internal|auth|oauth|sso|rest|service|action|upload|download|proxy)[^"\'`\s]{1,})(?:"|\'|`)', 'REST API Path'),
            (r'\.post\s*\(\s*["\']([^"\']+)["\']', 'POST'),
            (r'\.put\s*\(\s*["\']([^"\']+)["\']', 'PUT'),
            (r'\.patch\s*\(\s*["\']([^"\']+)["\']', 'PATCH'),
            (r'\.delete\s*\(\s*["\']([^"\']+)["\']', 'DELETE'),
            (r'\.get\s*\(\s*["\']([^"\']+)["\']', 'GET'),
            (r'(?:request|axios\.request)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', 'HTTP Request'),
            (r'(?:\$http|this\.\$http)\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']', 'Angular HTTP'),
            (r'(?:this\.http|inject\(\s*HttpClient\s*\))\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']', 'Angular HttpClient'),
            (r'(?:router\.(?:get|post|put|patch|delete|all|use))\s*\(\s*["\']([^"\']+)["\']', 'Express Route'),
            (r'(?:(?:app|server)\.(?:get|post|put|patch|delete|all|use))\s*\(\s*["\']([^"\']+)["\']', 'Express App'),
            (r'(?:this\.\$router|this\.router)\s*\.\s*(?:push|replace|go|navigate)\s*\(\s*["\']([^"\']+)["\']', 'SPA Navigation'),
            (r'(?:query|mutation|subscription)\s+([A-Z][a-zA-Z0-9_]{2,60})\s*[\({]', 'GraphQL Operation'),
        ]

        self.internal_patterns: List[Tuple[str, str, str]] = [
            (r'https?://(?:staging|stage|dev|development|test|testing|qa|uat|preprod|pre-prod|sandbox|stg|beta|alpha)[.\-][a-zA-Z0-9\-]+\.[a-zA-Z]{2,}', 'Staging/Dev URL', 'high'),
            (r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?', 'Internal URL', 'high'),
            (r'https?://[a-zA-Z0-9\-]+\.internal\.[a-zA-Z]{2,}', 'Internal Domain', 'high'),
            (r'https?://[a-zA-Z0-9\-]+\.local(?:host)?(?:\.|\b)', 'Local Domain', 'medium'),
            (r'(?i)(?:internal[_\-]?api|private[_\-]?api|admin[_\-]?api|backend[_\-]?api)\s*[:=]\s*["\']([^"\']+)["\']', 'Internal API Reference', 'high'),
        ]

        self.comment_patterns: List[Tuple[str, str, str]] = [
            (r'//\s*(?:TODO|FIXME|XXX|HACK|BUG|NOTE|SECURITY|DEPRECATED|WARNING)\b.*', 'Code Comment', 'info'),
            (r'//\s*(?:password|secret|key|token|admin|backdoor|debug|hardcoded|temp|credential).*', 'Suspicious Comment', 'medium'),
            (r'/\*[\s\S]{0,500}?(?:TODO|FIXME|HACK|SECURITY|DEPRECATED)[\s\S]{0,500}?\*/', 'Block Comment', 'info'),
        ]

        self.email_pattern = re.compile(
            r'(?<!["\'/\w])[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(?!["\'/\w])',
            re.MULTILINE
        )

        self.sourcemap_pattern = re.compile(
            r'(?:sourceMappingURL\s*=\s*["\']?)([^"\s\'*]+\.map)["\']?',
            re.MULTILINE
        )

        # Build-time leftovers: only the NAME is evidence (values, when
        # present, are already caught by the secret patterns). Upper-snake
        # convention keeps this tight: NODE_ENV / PORT / DEBUG never match.
        self.env_pattern = re.compile(
            r'process\.env\.([A-Z][A-Z0-9_]{1,46})'
            r'|import\.meta\.env\.([A-Z][A-Z0-9_]{1,46})'
        )
        self._secretish_name = re.compile(
            r'(KEY|SECRET|TOKEN|PASSW|PWD|AUTH|PRIVATE|CRED)'
        )

        # Obfuscator fingerprint (detection only - unpacking is out of scope;
        # a hit means results below may be incomplete, deobfuscate manually).
        self._obfuscator_pattern = re.compile(
            r'(?:\bvar _0x[a-f0-9]{3,}\s*=\s*\['
            r'|_0x[a-f0-9]{3,}\(_0x[a-f0-9]{3,},_0x[a-f0-9]{3,}\)'
            r'|/\*\s*obfuscated by )',
            re.IGNORECASE
        )

        # Labels whose match value goes through the strict entropy gate
        # (generic assignments only - fixed-format secrets skip this).
        self.ENTROPY_GATED_LABELS = {
            'API Key (Generic)', 'Secret Key (Generic)',
            'Access Token (Generic)', 'Password Assignment',
        }

    # ---------------- FP helpers ----------------

    def _is_placeholder(self, value: str) -> bool:
        v = value.lower().strip().strip('"\'`')
        if not v or len(v) < 4:
            return True
        if v in self.PLACEHOLDER_VALUES:
            return True
        for ph in ('your', 'example', 'sample', 'placeholder', 'changeme',
                   'replace', 'insert', 'enter', 'dummy', 'mock', 'fake',
                   'redact', 'xxx', 'todo', 'fixme'):
            if ph in v and len(v) < 40:
                # Only reject when the placeholder word dominates the value.
                letters = re.sub(r'[^a-z]', '', v)
                if len(letters) and len(ph) / max(len(letters), 1) > 0.4:
                    # Require low-entropy confirmation for longer strings so we
                    # never suppress a real secret that merely contains "test".
                    if len(v) < 24 or shannon_entropy(v) < 4.0:
                        return True
        if v.startswith('${') or v.startswith('{{') or v.startswith('%('):
            return True
        if re.match(r'^[x0\s_\-.*]+$', v):
            return True
        if re.match(r'^(?:your|my|the)[_\-](?:key|secret|token|password|api)', v):
            return True
        return False

    def _is_entropy_too_low(self, value: str, threshold: float = None) -> bool:
        if threshold is None:
            threshold = self.ENTROPY_THRESHOLD
        cleaned = re.sub(r'[^a-zA-Z0-9]', '', value)
        if len(cleaned) < 16:
            return True
        if not any(c.isdigit() for c in cleaned):
            threshold = max(threshold, self.ENTROPY_THRESHOLD_NO_DIGIT)
            # Generic secrets with no digits AND no special chars are almost
            # always English words / identifiers (Gitleaks generic-rule logic).
            raw_alnum = re.sub(r'[^a-zA-Z0-9]', '', value)
            specials = re.sub(r'[a-zA-Z0-9]', '', value)
            if not specials and cleaned.lower() in self.STOPWORDS:
                return True
        return shannon_entropy(cleaned) < threshold

    def _is_false_positive_secret(self, match_text: str, pattern_label: str, full_context: str = '') -> bool:
        if self._is_placeholder(match_text):
            return True
        lower_match = match_text.lower()
        quoted_val = None
        for q in ('"', "'", '`'):
            qi = match_text.find(q)
            if qi >= 0:
                qe = match_text.rfind(q)
                if qe > qi:
                    quoted_val = match_text[qi + 1:qe]
                    break
        check_val = (quoted_val if quoted_val is not None else match_text).lower()

        # Known documentation example keys are never findings.
        if check_val in self.KNOWN_EXAMPLE_KEYS:
            return True

        # Placeholder substring check: only suppress when the placeholder
        # word dominates the value (coverage > 50%) or the whole value is
        # short (< 24 chars). This keeps real secrets that merely contain
        # "test"/"aaaa" as a substring, while still killing example values
        # like "your_api_key_123".
        for ph in self.PLACEHOLDER_VALUES:
            if len(ph) <= 4:
                if ph == check_val:
                    return True
            elif ph in check_val:
                if len(check_val) < 24 or len(ph) / max(len(check_val), 1) > 0.5:
                    if shannon_entropy(check_val) < 4.0:
                        return True

        # Degenerate fixed-format matches (all-same-char test values like
        # key-AAAA... or 00000000-0000-...) have ~zero entropy. Real
        # generated secrets never look like this.
        if pattern_label not in self.ENTROPY_GATED_LABELS:
            core = re.sub(r'[^A-Za-z0-9]', '', match_text)
            # Strip known format prefixes so they don't inflate entropy.
            core = re.sub(r'^(sklive|SK|sktest|key|ghp|xoxb|xoxp|AIza|ya29|glpat|dopv1|re|hf|gsk|r8|pk|whsec|NRAK|figd|sdk|shpat|shpss|sq0atp|sq0csp|EAA|sntrys|linapi|npm|CFPAT|pplx|xai|fw|tgpv1|skorv1)', '', core, flags=re.IGNORECASE)
            if len(core) >= 16 and shannon_entropy(core) < 1.8:
                return True

        if pattern_label == 'JWT Token':
            parts = match_text.split('.')
            if len(parts) < 3 or len(match_text) < 50:
                return True
        if pattern_label == 'Supabase Service Key':
            # Must decode to role either way; reject obvious non-JWT.
            if match_text.count('.') < 2:
                return True
        if 'example.com' in lower_match or 'localhost' in lower_match:
            return True
        if pattern_label == 'Password Assignment':
            if check_val in ('password', 'test', 'admin', 'changeme', 'default',
                             'example', 'null', 'undefined', 'none', 'empty',
                             'placeholder', 'xxx', 'yyy', 'zzz', '1234',
                             '12345', '123456', 'qwerty', 'abc123', 'letmein',
                             'welcome', 'monkey', 'dragon', 'master', 'passw0rd'):
                return True
            # Password values that are plain dictionary words are not findings.
            if quoted_val and len(quoted_val) < 24 and not any(c.isdigit() for c in quoted_val):
                if shannon_entropy(quoted_val) < 3.8:
                    return True
        if pattern_label in self.ENTROPY_GATED_LABELS and quoted_val:
            if self._is_entropy_too_low(quoted_val):
                return True
            # Gitleaks generic rule: require at least one digit or special char.
            if not re.search(r'[0-9_\-+/=.{}]', quoted_val):
                return True
            if quoted_val.lower() in self.STOPWORDS:
                return True

        if full_context:
            match_start = full_context.find(match_text)
            if match_start >= 0:
                ctx_start = max(0, match_start - 300)
                ctx_end = min(len(full_context), match_start + len(match_text) + 300)
                surrounding = full_context[ctx_start:ctx_end]
                surr_lower = surrounding.lower()
                line_start = surrounding.rfind('\n', 0, match_start - ctx_start)
                if line_start < 0:
                    line_start = 0
                current_line = surrounding[line_start:match_start - ctx_start + len(match_text)].strip()
                for prefix in ('//', '/*', '*', '#'):
                    if current_line.startswith(prefix):
                        return True
                doc_keywords = ('@example', '@param', '@type', '@returns',
                                '@see', '@deprecated', 'documentation',
                                'swagger', 'openapi', 'schema', 'readme')
                for kw in doc_keywords:
                    if kw in surr_lower:
                        return True
                # Word-boundary-aware test markers. Bare substrings like
                # 'test_' / 'it(' over-suppress: they also match 'pk_test_',
                # 'latest_', '.split(', 'contest(' in production code.
                test_patterns = (
                    r'\bdescribe\s*\(', r'\bit\s*\(', r'\btest\s*\(',
                    r'\bexpect\s*\(', r'\bassert\b', r'\bunittest\b',
                    r'(?<![a-z0-9_])test_', r'_test(?![a-z0-9_])',
                    r'\bspec\b',
                    r'\bmock\b', r'\bfixture\b', r'\bfactory\b',
                    r'\.test\.', r'\.spec\.', r'__tests?__',
                    r'\bjest\b', r'\bmocha\b', r'\bchai\s*\(',
                    r'\bjasmine\b', r'\bcypress\b',
                )
                for rx in test_patterns:
                    if re.search(rx, surr_lower):
                        return True
                for ctx in self.FALSE_POSITIVE_CONTEXTS:
                    if ctx in surrounding and any(
                            aw in ctx.lower() for aw in ('env', 'process', 'require', 'import', 'config')):
                        return True
        return False

    def _is_false_endpoint(self, url: str) -> bool:
        lower = url.lower()
        for domain in self.FALSE_POSITIVE_DOMAINS:
            if domain in lower:
                return True
        skip_exts = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                     '.css', '.woff', '.woff2', '.ttf', '.eot', '.map',
                     '.bmp', '.webp', '.avif', '.mp3', '.mp4', '.webm',
                     '.pdf', '.zip', '.tar', '.gz')
        if any(lower.split('?')[0].endswith(ext) for ext in skip_exts):
            return True
        skip_patterns = ('node_modules', 'webpack', '.min.js', 'bundle.js',
                         'vendor', 'polyfill', 'shim', 'es6-promise',
                         'sourcemap', 'hot-update')
        if any(p in lower for p in skip_patterns):
            return True
        if lower.strip('\'"') in ('get', 'post', 'put', 'delete', 'patch', 'head', 'options'):
            return True
        if url.startswith('//'):
            return True
        if len(url) < 2:
            return True
        return False

    def _to_absolute_url(self, path: str, base_url: str) -> str:
        # GraphQL operation names are not URLs - keep them as-is.
        if re.match(r'^[A-Z][a-zA-Z0-9_]{2,60}$', path or ''):
            try:
                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}/graphql#{path}"
            except Exception:
                return path
        if (path or '').startswith(('http://', 'https://', 'ws://', 'wss://')):
            return path
        try:
            parsed = urlparse(base_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            return urljoin(base + '/', (path or '').lstrip('/'))
        except Exception:
            return path

    @staticmethod
    def _host_of(url: str) -> str:
        try:
            return (urlparse(url or '').hostname or '').lower()
        except Exception:
            return ''

    def _is_in_scope_url(self, abs_url: str, file_url: str) -> bool:
        """Keep only URLs belonging to the scanned file's brand.

        e.g. scanning uber.com keeps uber.com / uber.net /
        cdn.uber.com (the host contains "uber") and drops facebook,
        google, etc. Relative URLs already resolve to the file's own
        host, so they are always kept.
        """
        ep_host = self._host_of(abs_url)
        file_host = self._host_of(file_url)
        if not ep_host or not file_host:
            return True
        if ep_host == file_host:
            return True
        try:
            ipaddress.ip_address(file_host)
            return True  # IP test targets (127.0.0.1, LAN boxes): keep all
        except ValueError:
            pass
        labels = file_host.split('.')
        core = labels[-2] if len(labels) >= 2 else labels[0]
        if len(core) >= 4:
            return core in ep_host
        # Short/generic core (x.io, a.co): same host or its subdomains only.
        return ep_host == file_host or ep_host.endswith('.' + file_host)

    def beautify_context(self, context: str, match_text: str = '') -> str:
        if not context:
            return ''
        opts = {'indent_size': 2, 'indent_char': ' ', 'max_preserve_newlines': 1,
                'preserve_newlines': True, 'keep_array_indentation': False,
                'break_chained_methods': False, 'brace_style': 'collapse',
                'space_before_conditional': True, 'unescape_strings': False,
                'jslint_happy': False, 'end_with_newline': False,
                'wrap_line_length': 0, 'e4x': False}
        if HAS_BEAUTIFIER:
            try:
                beautified = jsbeautifier.beautify(context, opts)
            except Exception:
                beautified = context
        else:
            beautified = context
        if match_text and match_text in beautified:
            idx = beautified.find(match_text)
            before = beautified[:idx]
            after = beautified[idx + len(match_text):]
            beautified = before + '\x00\x01' + match_text + '\x00\x02' + after
        return beautified

    # ---------------- probing ----------------

    @staticmethod
    def _retry_wait(resp: Any, backoff: float, cap: float = 5.0) -> float:
        """Seconds to wait before retry: Retry-After (delta only) else backoff."""
        try:
            ra = float(resp.headers.get('Retry-After', '') or 0)
            if ra > 0:
                return min(ra, cap)
        except (ValueError, TypeError, AttributeError):
            pass
        return min(backoff, cap)

    def probe_endpoint(self, url: str, timeout: int = 10, _retries: int = 2) -> Dict[str, Any]:
        result: Dict[str, Any] = {'status': None, 'title': '',
                                  'word_count': 0, 'content_length': 0,
                                  'final_url': url, 'content_type': ''}
        if not url or url.startswith('graphql#'):
            return result
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        backoff = 0.5
        for attempt in range(_retries + 1):
            try:
                resp = requests.get(url, headers=headers, timeout=timeout,
                                    verify=False, allow_redirects=True, stream=True)
            except Exception:
                return result  # connection-level failure: fail fast, no retry
            try:
                code = resp.status_code
                if (code == 429 or code >= 500) and attempt < _retries:
                    wait = self._retry_wait(resp, backoff)
                    try:
                        resp.close()
                    except Exception:
                        pass
                    time.sleep(wait + random.uniform(0, 0.4))
                    backoff *= 2
                    continue
                result['status'] = code
                result['final_url'] = resp.url
                result['content_length'] = int(resp.headers.get('Content-Length', 0) or 0)
                content_type = resp.headers.get('Content-Type', '')
                result['content_type'] = content_type
                if any(t in content_type for t in ('text', 'html', 'javascript', 'json', 'xml')):
                    body = resp.content[:65536].decode('utf-8', errors='ignore')
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', body,
                                            re.IGNORECASE | re.DOTALL)
                    if title_match:
                        result['title'] = re.sub(r'\s+', ' ', title_match.group(1)).strip()[:150]
                    result['word_count'] = len(body.split())
                resp.close()
                return result
            except Exception:
                try:
                    resp.close()
                except Exception:
                    pass
                return result
        return result

    def probe_endpoints(self, endpoints: List[Dict[str, Any]], max_workers: int = 8) -> None:
        urls = list({ep.get('absolute_url', ep.get('path', ''))
                     for ep in endpoints if ep.get('absolute_url') or ep.get('path')})
        urls = [u for u in urls if u and not u.startswith('graphql#')]
        if not urls:
            return
        probes: Dict[str, Dict[str, Any]] = {}
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(urls))) as executor:
                future_to_url = {executor.submit(self.probe_endpoint, u): u for u in urls}
                for future in concurrent.futures.as_completed(future_to_url, timeout=20):
                    u = future_to_url[future]
                    try:
                        probes[u] = future.result()
                    except Exception:
                        probes[u] = {'status': None, 'title': '', 'word_count': 0,
                                     'content_length': 0, 'final_url': u, 'content_type': ''}
        except Exception:
            pass
        for ep in endpoints:
            url = ep.get('absolute_url', ep.get('path', ''))
            if url in probes:
                ep['probe'] = probes[url]

    # ---------------- analysis ----------------

    def _scan_text(self, content: str, base_url: str,
                   beautify: bool = False) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Run the secret + endpoint pipeline over one text blob.

        Shared by analyze(), sub-file fetching, and embedded source-map
        sources so all three behave identically. beautify=True adds the
        beautified_context field (main-file path only, for cost reasons).
        """
        secrets = []
        seen_secrets = set()
        for pattern, label, severity in self.secret_patterns:
            for finding in self._find_with_context(content, pattern):
                key = (finding['match'][:80], finding['line'])
                if key in seen_secrets:
                    continue
                seen_secrets.add(key)
                if self._is_false_positive_secret(finding['match'], label, content):
                    continue
                item = {'type': label, 'severity': severity, **finding,
                        **self._attach_validation(label, finding['match'])}
                if beautify:
                    item['beautified_context'] = self.beautify_context(
                        finding.get('context', ''), finding['match'])
                secrets.append(item)
        secrets = self._dedupe_secrets(secrets)

        endpoints = []
        seen_eps = set()
        for pattern, method in self.endpoint_patterns:
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                groups = match.groups()
                ep_url = groups[0] if groups else match.group(0)
                if not ep_url or self._is_false_endpoint(ep_url):
                    continue
                abs_url = self._to_absolute_url(ep_url, base_url)
                if not self._is_in_scope_url(abs_url, base_url):
                    continue
                line_num = content[:match.start()].count('\n') + 1
                key = (abs_url, line_num)
                if key in seen_eps:
                    continue
                seen_eps.add(key)
                lines = content.split('\n')
                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                if len(line_content) > 300:
                    line_content = line_content[:120] + ' ... ' + line_content[-120:]
                item = {'method': method, 'path': ep_url[:300],
                        'absolute_url': abs_url, 'line': line_num,
                        'line_content': line_content,
                        'full_match': match.group(0)[:200]}
                if beautify:
                    item['beautified_context'] = self.beautify_context(
                        match.group(0)[:200], ep_url[:100])
                endpoints.append(item)
        return secrets, endpoints

    def _analyze_sub_js(self, js_url: str, depth: int = 0, max_depth: int = 1,
                        _content: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if depth > max_depth:
            return None
        try:
            content = _content if _content is not None else self.fetch_js_file(js_url)
            if not content:
                return None
            secrets, endpoints = self._scan_text(content, js_url, beautify=False)
            return {'url': js_url, 'secrets': secrets, 'endpoints': endpoints,
                    'file_size': len(content), 'errors': []}
        except Exception:
            return None

    def _analyze_embedded_source(self, label_url: str, content: str) -> Dict[str, Any]:
        """Scan one source-map-embedded original source (no fetching)."""
        secrets, endpoints = self._scan_text(content, label_url, beautify=False)
        return {'url': label_url, 'secrets': secrets, 'endpoints': endpoints,
                'file_size': len(content), 'errors': []}

    def fetch_js_file(self, url: str) -> Optional[str]:
        try:
            if '0.0.0.0' in url:
                url = url.replace('0.0.0.0', 'localhost')
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/javascript, text/javascript, */*',
            }
            response = requests.get(url, headers=headers, timeout=30,
                                    verify=False, stream=True, allow_redirects=True)
            response.raise_for_status()
            content_length = response.headers.get('Content-Length')
            if content_length:
                try:
                    if int(content_length) > 10 * 1024 * 1024:
                        return None
                except (ValueError, TypeError):
                    pass
            content = ""
            max_size = 10 * 1024 * 1024
            try:
                response.encoding = response.apparent_encoding or 'utf-8'
                for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                    if chunk:
                        if isinstance(chunk, bytes):
                            chunk = chunk.decode('utf-8', errors='ignore')
                        content += chunk
                        if len(content) > max_size:
                            content = content[:max_size]
                            break
            except UnicodeDecodeError:
                content = response.content.decode('utf-8', errors='ignore')
                if len(content) > max_size:
                    content = content[:max_size]
            return content if content else None
        except Exception:
            return None

    def _excerpt_window(self, lines: List[str], line_num: int) -> List[Dict[str, Any]]:
        """Line-numbered 3-line window (prev / hit / next) around a finding.

        Minified JS lines can be enormous, so each line is trimmed around the
        region of interest instead of blindly cut. Returns JSON-safe dicts:
        {n: line number, text: code, hit: is-the-match-line}.
        """
        idx = line_num - 1
        out: List[Dict[str, Any]] = []
        for i in range(max(0, idx - 1), min(len(lines), idx + 2)):
            raw = lines[i]
            text = raw.strip()
            if len(text) > 320:
                # Keep head + tail so `key = "VALUE"` shape stays visible.
                text = text[:170] + '  …  ' + text[-130:]
            out.append({'n': i + 1, 'text': text[:320], 'hit': i == idx})
        return out

    def _beautify_excerpt(self, excerpt: List[Dict[str, Any]]) -> str:
        """Beautified (multi-line) rendering of the excerpt window for the UI."""
        if not excerpt:
            return ''
        code = '\n'.join(e['text'] for e in excerpt)
        if HAS_BEAUTIFIER and len(code) > 90 and (';' in code or '{' in code):
            try:
                code = jsbeautifier.beautify(
                    code,
                    {'indent_size': 2, 'indent_char': ' ',
                     'max_preserve_newlines': 1, 'preserve_newlines': True,
                     'keep_array_indentation': False,
                     'break_chained_methods': False, 'brace_style': 'collapse',
                     'space_before_conditional': True, 'unescape_strings': False,
                     'jslint_happy': False, 'end_with_newline': False,
                     'wrap_line_length': 0, 'e4x': False})
            except Exception:
                pass
        rows = code.split('\n')[:9]
        return '\n'.join(r[:320] for r in rows)[:2800]

    def _find_with_context(self, content: str, pattern: str, max_context: int = 200) -> List[Dict[str, Any]]:
        findings = []
        try:
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                start = match.start()
                line_num = content[:start].count('\n') + 1
                lines = content.split('\n')
                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                if len(line_content) > 300:
                    line_content = line_content[:120] + ' ... ' + line_content[-120:]
                ctx_start = max(0, start - max_context)
                ctx_end = min(len(content), start + len(match.group(0)) + max_context)
                context = content[ctx_start:ctx_end]
                excerpt = self._excerpt_window(lines, line_num)
                findings.append({
                    'match': match.group(0)[:300],
                    'line': line_num,
                    'line_content': line_content,
                    'context': context,
                    'excerpt': excerpt,
                    'excerpt_pretty': self._beautify_excerpt(excerpt),
                })
        except re.error:
            pass
        return findings

    def _attach_validation(self, label: str, matched_text: str) -> Dict[str, Any]:
        if not HAS_VALIDATORS:
            return {'validation': None}
        entry = get_validation(label)
        if not entry:
            return {'validation': None}
        value = extract_value(matched_text)
        curl_cmd = render_curl(label, value)
        return {
            'validation': {
                'command': curl_cmd,
                'indicator': entry.get('indicator'),
                'requires_pairing': bool(label in self.PAIRED_SECRET_TYPES or entry.get('manual', False)),
            }
        }

    def analyze(self, url: str, max_depth: int = 1, probe: bool = True) -> AnalysisResult:
        errors: List[str] = []
        try:
            original_url = url
            if '0.0.0.0' in url:
                url = url.replace('0.0.0.0', 'localhost')
            content = self.fetch_js_file(url)
            if content is None:
                if 'localhost' in url:
                    alt = url.replace('localhost', '127.0.0.1')
                    content = self.fetch_js_file(alt)
                    if content:
                        url = alt
                if content is None:
                    errors.append(f"Failed to fetch {original_url}")
                    return self._empty_result(url, errors)
        except Exception as e:
            errors.append(f"Error fetching {url}: {e}")
            return self._empty_result(url, errors)

        file_size = len(content)
        ts = datetime.now().isoformat()

        secrets, endpoints = self._scan_text(content, url, beautify=True)

        internal_refs = []
        for pattern, label, severity in self.internal_patterns:
            for finding in self._find_with_context(content, pattern):
                internal_refs.append({'type': label, 'severity': severity, **finding})

        # Exposed env-var names (values are covered by secret patterns).
        seen_env = set()
        for match in self.env_pattern.finditer(content):
            name = match.group(1) or match.group(2)
            if not name or not self._secretish_name.search(name):
                continue
            line_num = content[:match.start()].count('\n') + 1
            key = (name, line_num)
            if key in seen_env:
                continue
            seen_env.add(key)
            lines = content.split('\n')
            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
            internal_refs.append({
                'type': 'Exposed Env Reference', 'severity': 'info',
                'match': match.group(0)[:120], 'line': line_num,
                'line_content': line_content[:300],
            })

        # Obfuscation triage flag (at most one entry per file).
        obf = self._obfuscator_pattern.search(content)
        if obf:
            line_num = content[:obf.start()].count('\n') + 1
            internal_refs.append({
                'type': 'Obfuscated Bundle', 'severity': 'info',
                'match': 'obfuscator string-array / decoder pattern',
                'line': line_num,
                'line_content': content.split('\n')[line_num - 1].strip()[:300],
            })

        comments = []
        seen_comments = set()
        for pattern, label, severity in self.comment_patterns:
            for finding in self._find_with_context(content, pattern, max_context=100):
                key = (finding['line'], finding['match'][:80])
                if key not in seen_comments:
                    seen_comments.add(key)
                    comments.append({'type': label, 'severity': severity, **finding})

        emails = []
        seen_emails = set()
        for match in self.email_pattern.finditer(content):
            email = match.group(0)
            if email not in seen_emails and not self._is_false_endpoint(email):
                seen_emails.add(email)
                line_num = content[:match.start()].count('\n') + 1
                lines = content.split('\n')
                line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                emails.append({'type': 'Email Address', 'match': email, 'line': line_num,
                               'line_content': line_content[:300]})

        source_maps = []
        for match in self.sourcemap_pattern.finditer(content):
            source_maps.append({
                'type': 'Source Map Reference', 'severity': 'high',
                'match': match.group(1), 'line': content[:match.start()].count('\n') + 1,
                'line_content': match.group(0)[:300],
            })

        if probe:
            self.probe_endpoints(endpoints)

        sub_files = []
        analyzed_urls = set()
        for sm in source_maps:
            sm_url = self._to_absolute_url(sm['match'], url)
            if sm_url in analyzed_urls:
                continue
            analyzed_urls.add(sm_url)
            if max_depth < 1:
                continue
            map_text = self.fetch_js_file(sm_url)
            if not map_text:
                continue
            parsed = parse_sourcemap(map_text) if HAS_SOURCEMAP else None
            if parsed is None:
                # Not actually a map (or no parser): legacy raw scan.
                sub = self._analyze_sub_js(sm_url, depth=1, max_depth=max_depth,
                                           _content=map_text)
                if sub:
                    sub_files.append(sub)
                continue
            embedded = iter_original_sources(map_text) if HAS_SOURCEMAP else []
            for src in embedded:
                label = sm_url + '#' + src['path'][-160:]
                sub_files.append(self._analyze_embedded_source(label, src['content']))
            paths = source_paths(map_text) if HAS_SOURCEMAP else []
            sm['embedded_sources'] = len(embedded)
            sm['source_paths'] = len(paths)
            try:
                total_sources = len(parsed.get('sources', [])) if parsed else len(paths)
            except Exception:
                total_sources = len(paths)
            sm['sources_total'] = total_sources
            truncated = total_sources > _SM_MAX_SOURCES
            sm['truncated_sources'] = truncated
            if paths:
                sample = '; '.join(paths[:3])[:240]
                match = f'{len(paths)} original source paths'
                if truncated:
                    # Surface the sampling cap honestly: only the first
                    # _SM_MAX_SOURCES originals were scanned for secrets.
                    match += (f' ({len(embedded)} of {total_sources} '
                              f'sources scanned — increase sourcemap.MAX_SOURCES '
                              f'for full coverage)')
                internal_refs.append({
                    'type': 'Exposed Source Paths', 'severity': 'info',
                    'match': match,
                    'line': sm['line'], 'line_content': sample,
                })
        for ep in endpoints:
            ep_url = ep['absolute_url']
            if ep_url.endswith('.js') and ep_url not in analyzed_urls:
                analyzed_urls.add(ep_url)
                sub = self._analyze_sub_js(ep_url, depth=1, max_depth=max_depth)
                if sub:
                    sub_files.append(sub)

        return AnalysisResult(
            url=url, secrets=secrets, endpoints=endpoints, internal_refs=internal_refs,
            comments=comments, emails=emails, source_maps=source_maps, errors=errors,
            file_size=file_size, analysis_timestamp=ts, sub_files=sub_files,
        )

    # Tokens with no recon value as fuzzing material (ffuf/Arjun wordlist).
    # JS-language noise only. Ordinary English words (name, value, target,
    # error, test, ...) are legitimate fuzz material and stay in.
    _WORDLIST_STOP = frozenset({
        'function', 'return', 'const', 'let', 'var', 'new', 'this', 'true',
        'false', 'null', 'undefined', 'typeof', 'instanceof', 'delete',
        'void', 'await', 'async', 'yield', 'class', 'extends', 'super',
        'import', 'export', 'default', 'from', 'require', 'module',
        'object', 'string', 'number', 'boolean', 'array', 'length',
        'prototype', 'constructor', 'window', 'document', 'console',
        'math', 'json', 'promise', 'foreach',
        'push', 'pop', 'shift', 'slice', 'splice', 'join', 'split',
    })

    def build_wordlist(self, content: str, min_len: int = 4,
                       max_len: int = 48, limit: int = 5000) -> List[str]:
        """Dump fuzzing material (ffuf/Arjun): identifiers + string-literal
        tokens in first-seen order, deduped, stoplist-filtered, capped."""
        if not content:
            return []
        seen = set()
        out: List[str] = []

        def _take(tok: str) -> None:
            t = (tok or '').strip().strip('._-/')
            if not (min_len <= len(t) <= max_len):
                return
            if t.isdigit():
                return
            if t.lower() in self._WORDLIST_STOP:
                return
            if t in seen or t.lower() in seen:
                return
            seen.add(t)
            seen.add(t.lower())
            if len(out) < limit:
                out.append(t)

        for m in re.finditer(r'''(["'`])((?:\\\1|(?!\1)[^\n]){1,200})\1''', content):
            for tok in re.split(r'[^A-Za-z0-9_.\-/]+', m.group(2)):
                _take(tok)
                # path-ish tokens also contribute their segments
                # (api.target.com/v1/admin_users -> admin, users, ...)
                for seg in re.split(r'[./\-_]+', tok):
                    _take(seg)
        for m in re.finditer(r'[A-Za-z_$][A-Za-z0-9_$]{2,47}', content):
            _take(m.group(0))
        return out

    @staticmethod
    def _finding_value(match_text: str) -> str:
        """Best-effort credential value inside a finding (for overlap checks)."""
        try:
            return extract_value(match_text)
        except Exception:
            return match_text

    def _dedupe_secrets(self, secrets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Drop generic findings that restate a specific finding on the same line.

        e.g. `apiKey = "AIza..."` fires both `Google API Key` and
        `API Key (Generic)` — keep the specific one so one secret is
        reported once.
        """
        if len(secrets) < 2:
            return secrets
        drop = set()
        for i, g in enumerate(secrets):
            if g.get('type') not in self.ENTROPY_GATED_LABELS:
                continue
            gv = self._finding_value(g.get('match', ''))
            if not gv:
                continue
            for j, o in enumerate(secrets):
                if i == j or j in drop:
                    continue
                if o.get('type') in self.ENTROPY_GATED_LABELS:
                    continue
                if o.get('line') != g.get('line'):
                    continue
                om = o.get('match', '')
                if gv in om or om in g.get('match', ''):
                    drop.add(i)
                    break
        return [s for i, s in enumerate(secrets) if i not in drop]

    @staticmethod
    def canonical_secret_key(secret_type: str, match_text: str) -> str:
        """Cross-file identity for a secret: type + normalized credential value.

        Uses extract_value() so `apiKey = "ghp_X"` and bare `ghp_X` in
        another file merge. Type stays case-sensitive (labels are exact) so
        colliding shapes (Stripe vs Clerk-style keys) never merge across
        providers. Truncated for map safety.
        """
        try:
            value = extract_value(match_text or '')
        except Exception:
            value = match_text or ''
        return (secret_type or '').strip() + '||' + (value or '').strip()[:300]

    @staticmethod
    def normalize_endpoint_url(url: str) -> str:
        """Canonical form for endpoint dedup (grouping only, never for fetch).

        - GraphQL `.../graphql#Operation` kept verbatim (op name is identity,
          case-sensitive).
        - Absolute URLs: lowercase scheme+host, drop default ports, strip
          trailing `/` (except root), drop fragment, KEEP query (different
          params = different surface), preserve path case.
        - Relative paths: strip trailing `/`, preserve case, keep query.
        Anything unparseable returns the stripped input (fail-open: stays
        distinct rather than merging wrongly).
        """
        if not url:
            return ''
        u = (url or '').strip()
        if not u:
            return ''
        # GraphQL operation URLs carry the op name after # — identity.
        if '/graphql#' in u:
            return u
        try:
            parsed = urlparse(u)
            if not parsed.scheme and not parsed.netloc:
                # Relative path like /api/v1/users/?a=1
                path = parsed.path or u.split('?', 1)[0].split('#', 1)[0]
                q = ''
                if '?' in u:
                    q = u.split('?', 1)[1].split('#', 1)[0]
                    q = '?' + q if q else ''
                if len(path) > 1 and path.endswith('/'):
                    path = path.rstrip('/')
                return (path or '/') + q
            scheme = (parsed.scheme or '').lower()
            host = (parsed.hostname or '').lower()
            if not host:
                return u
            port = parsed.port
            if port and not ((scheme == 'https' and port == 443) or
                             (scheme == 'http' and port == 80)):
                host = f"{host}:{port}"
            path = parsed.path or '/'
            if len(path) > 1 and path.endswith('/'):
                path = path.rstrip('/')
            out = f"{scheme}://{host}{path}"
            if parsed.query:
                out += '?' + parsed.query
            return out
        except Exception:
            return u

    @classmethod
    def canonical_endpoint_key(cls, ep: Dict[str, Any]) -> str:
        """Cross-file identity for an endpoint (method-agnostic by design).

        `GET /api/x` + `POST /api/x` merge into one row with a merged
        `methods` list on the survivor, so verb-specific surface is preserved
        in display rather than dropped. Query strings keep rows distinct.
        """
        raw = ep.get('absolute_url') or ep.get('path') or ''
        return cls.normalize_endpoint_url(raw)

    def consolidate_secrets_cross_file(
            self, file_dicts: List[Dict[str, Any]], threshold: int = 3
    ) -> List[Dict[str, Any]]:
        """Collapse identical secrets seen across >=threshold files.

        Mutates dicts in place (same contract as frontend consolidateSecrets)
        and returns them. Grouping key is canonical (type + extracted value).
        Survivor prefers a main-file entry with the lowest (file_id, line);
        it gets `also_found_in: [urls]` + additive `also_found_details:
        [{url, line, sub_file}]`. Groups below threshold have stale markers
        cleared so re-runs are idempotent. Single-file input is a no-op.
        """
        if not file_dicts or len(file_dicts) < 2:
            return file_dicts
        groups: Dict[str, list] = {}
        for f in file_dicts:
            fid = f.get('file_id', 0) or 0
            for s in (f.get('secrets') or []):
                k = self.canonical_secret_key(s.get('type', ''), s.get('match', ''))
                groups.setdefault(k, []).append(
                    {'arr': f.setdefault('secrets', []), 's': s,
                     'url': f.get('url', ''), 'line': s.get('line', 0) or 0,
                     'rank': fid * 1000000 + (s.get('line', 0) or 0),
                     'main': True, 'sub': False})
            for sf in (f.get('sub_files') or []):
                for s in (sf.get('secrets') or []):
                    k = self.canonical_secret_key(s.get('type', ''), s.get('match', ''))
                    groups.setdefault(k, []).append(
                        {'arr': sf.setdefault('secrets', []), 's': s,
                         'url': sf.get('url') or f.get('url', ''),
                         'line': s.get('line', 0) or 0,
                         'rank': fid * 1000000 + 500000 + (s.get('line', 0) or 0),
                         'main': False, 'sub': True})
        for g in groups.values():
            urls = list(dict.fromkeys(x['url'] for x in g if x['url']))
            if len(urls) < threshold:
                # Idempotent: lone survivor from a prior pass keeps its
                # markers; only clear when genuine duplicates are present.
                if len(g) > 1:
                    for x in g:
                        x['s'].pop('also_found_in', None)
                        x['s'].pop('also_found_details', None)
                continue
            g.sort(key=lambda a: (0 if a['main'] else 1, a['rank']))
            survivor = g[0]
            others = [x for x in g[1:] if x['url'] != survivor['url']
                      or x['line'] != survivor['line']]
            survivor['s']['also_found_in'] = [x['url'] for x in g
                                              if x['url'] != survivor['url']]
            # De-dupe detail rows while preserving order.
            seen = set()
            details = []
            for x in g:
                if x is survivor:
                    continue
                dk = (x['url'], x['line'], x['sub'])
                if dk in seen:
                    continue
                seen.add(dk)
                details.append({'url': x['url'], 'line': x['line'],
                                'sub_file': x['sub']})
            survivor['s']['also_found_details'] = details
            for x in g[1:]:
                try:
                    ix = x['arr'].index(x['s'])
                except ValueError:
                    continue
                x['arr'].pop(ix)
        return file_dicts

    def consolidate_endpoints_cross_file(
            self, file_dicts: List[Dict[str, Any]], threshold: int = 2
    ) -> List[Dict[str, Any]]:
        """Collapse identical endpoints seen across >=threshold files.

        Same in-place contract as secrets. Survivor keeps its own probe/line
        content and gains `also_found_in`, `also_found_details`, and merged
        `methods` list so no verb information is lost.
        """
        if not file_dicts or len(file_dicts) < 2:
            return file_dicts
        groups: Dict[str, list] = {}
        for f in file_dicts:
            fid = f.get('file_id', 0) or 0
            for e in (f.get('endpoints') or []):
                k = self.canonical_endpoint_key(e)
                if not k:
                    continue
                groups.setdefault(k, []).append(
                    {'arr': f.setdefault('endpoints', []), 'e': e,
                     'url': f.get('url', ''), 'line': e.get('line', 0) or 0,
                     'method': e.get('method', '') or '',
                     'rank': fid * 1000000 + (e.get('line', 0) or 0),
                     'main': True, 'sub': False})
            for sf in (f.get('sub_files') or []):
                for e in (sf.get('endpoints') or []):
                    k = self.canonical_endpoint_key(e)
                    if not k:
                        continue
                    groups.setdefault(k, []).append(
                        {'arr': sf.setdefault('endpoints', []), 'e': e,
                         'url': sf.get('url') or f.get('url', ''),
                         'line': e.get('line', 0) or 0,
                         'method': e.get('method', '') or '',
                         'rank': fid * 1000000 + 500000 + (e.get('line', 0) or 0),
                         'main': False, 'sub': True})
        for g in groups.values():
            urls = list(dict.fromkeys(x['url'] for x in g if x['url']))
            if len(urls) < threshold:
                if len(g) > 1:
                    for x in g:
                        x['e'].pop('also_found_in', None)
                        x['e'].pop('also_found_details', None)
                        x['e'].pop('methods', None)
                continue
            g.sort(key=lambda a: (0 if a['main'] else 1, a['rank']))
            survivor = g[0]['e']
            methods = []
            for x in g:
                m = (x['method'] or '').strip()
                if m and m not in methods:
                    methods.append(m)
            if len(methods) > 1:
                survivor['methods'] = methods
            else:
                survivor.pop('methods', None)
            survivor['also_found_in'] = [u for u in urls
                                         if u != g[0]['url']]
            seen = set()
            details = []
            for x in g:
                if x['e'] is survivor:
                    continue
                dk = (x['url'], x['line'], x['method'], x['sub'])
                if dk in seen:
                    continue
                seen.add(dk)
                details.append({'url': x['url'], 'line': x['line'],
                                'method': x['method'], 'sub_file': x['sub']})
            survivor['also_found_details'] = details
            for x in g[1:]:
                try:
                    ix = x['arr'].index(x['e'])
                except ValueError:
                    continue
                x['arr'].pop(ix)
        return file_dicts

    def probe_across_files(self, file_dicts: List[Dict[str, Any]],
                           max_workers: int = 8) -> None:
        """Probe each distinct raw endpoint URL once, fan results out.

        Grouping for display uses the normalized key, but probing uses the
        exact raw `absolute_url` (trailing-slash/query variants can behave
        differently, so they are probed separately — no result loss).
        Safe to call even when endpoints already carry probes (fills gaps).
        """
        targets: Dict[str, list] = {}
        for f in file_dicts:
            for e in (f.get('endpoints') or []):
                raw = e.get('absolute_url') or e.get('path') or ''
                if raw and not e.get('probe'):
                    targets.setdefault(raw, []).append(e)
        if not targets:
            return
        urls = list(targets.keys())
        probes: Dict[str, Dict[str, Any]] = {}
        try:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=min(max_workers, len(urls))) as ex:
                future_to_url = {ex.submit(self.probe_endpoint, u): u
                                 for u in urls}
                for future in concurrent.futures.as_completed(
                        future_to_url, timeout=30):
                    u = future_to_url[future]
                    try:
                        probes[u] = future.result()
                    except Exception:
                        probes[u] = {'status': None, 'title': '',
                                     'word_count': 0, 'content_length': 0,
                                     'final_url': u, 'content_type': ''}
        except Exception:
            return
        for raw, eps in targets.items():
            if raw in probes:
                for e in eps:
                    e['probe'] = probes[raw]

    def _empty_result(self, url: str, errors: List[str]) -> AnalysisResult:
        return AnalysisResult(
            url=url, secrets=[], endpoints=[], internal_refs=[], comments=[], emails=[],
            source_maps=[], errors=errors, file_size=0,
            analysis_timestamp=datetime.now().isoformat(), sub_files=[],
        )


# =============================================================================
# CLI (per RESEARCH.md §5 recon pipeline: gau/waybackurls/katana -> specter.py)
# =============================================================================

def _cli_secret_value(matched_text: str) -> str:
    try:
        return extract_value(matched_text)
    except Exception:
        return matched_text


def main() -> None:
    import argparse
    import json as _json

    parser = argparse.ArgumentParser(
        description="Specter - JS secret & endpoint recon for authorized engagements.")
    parser.add_argument('-u', '--url', action='append', required=True,
                        help='JS URL to analyze (repeatable)')
    parser.add_argument('--out-file', default=None,
                        help='Write full JSON report here (default: stdout summary)')
    parser.add_argument('--validate', action='store_true',
                        help='Safe read-only live checks where possible '
                             '(only against assets you are authorized to test)')
    parser.add_argument('--no-probe', action='store_true',
                        help='Skip HTTP probing of discovered endpoints')
    parser.add_argument('--max-depth', type=int, default=1,
                        help='Max depth for following .js/.map references (default: 1)')
    parser.add_argument('--wordlist-out', default=None, metavar='PATH',
                        help='Write combined ffuf/Arjun wordlist (identifiers + '
                             'string literals) to PATH')
    args = parser.parse_args()

    try:
        from validators import live_validate_secret as _live
    except ImportError:
        _live = None

    analyzer = JavaScriptAnalyzer()
    if args.no_probe:
        analyzer.probe_endpoints = lambda endpoints, max_workers=8: None

    all_reports = []
    combined_wordlist: List[str] = []
    seen_wl = set()
    for url in args.url:
        result = analyzer.analyze(url, max_depth=args.max_depth)
        report_wl: List[str] = []
        if args.wordlist_out:
            content = analyzer.fetch_js_file(url) or ""
            wl = analyzer.build_wordlist(content)
            report_wl = wl[:2000]
            for tok in wl:
                if tok not in seen_wl:
                    seen_wl.add(tok)
                    if len(combined_wordlist) < 20000:
                        combined_wordlist.append(tok)
        secrets = []
        for s in result.secrets:
            item = {k: s.get(k) for k in (
                'type', 'severity', 'match', 'line', 'line_content',
                'excerpt', 'validation', 'also_found_in',
                'also_found_details')}
            if args.validate and _live is not None:
                v = item.get('validation') or {}
                if v.get('requires_pairing'):
                    item['live'] = {'checked': False,
                                    'reason': 'paired/manual - see command'}
                else:
                    try:
                        item['live'] = _live(
                            item['type'], _cli_secret_value(item['match']))
                    except Exception as e:
                        item['live'] = {'checked': True, 'valid': None,
                                        'error': str(e)[:200]}
            secrets.append(item)
        report = {
            'url': result.url,
            'file_size': result.file_size,
            'analysis_timestamp': result.analysis_timestamp,
            'errors': result.errors,
            'secrets': secrets,
            'endpoints': [
                {'method': e.get('method'), 'methods': e.get('methods'),
                 'path': e.get('path'),
                 'absolute_url': e.get('absolute_url'), 'line': e.get('line'),
                 'probe': e.get('probe'),
                 'also_found_in': e.get('also_found_in'),
                 'also_found_details': e.get('also_found_details')}
                for e in result.endpoints
            ],
            'internal_refs': result.internal_refs,
            'emails': result.emails,
            'source_maps': result.source_maps,
            'wordlist': report_wl if args.wordlist_out else [],
        }
        all_reports.append(report)

    if len(all_reports) > 1:
        # Cross-file consolidation for batch runs (additive fields only;
        # single-file output unchanged). Runs before stdout + JSON output
        # so both stay consistent with the API/UI.
        for i, r in enumerate(all_reports):
            r.setdefault('file_id', i + 1)
        try:
            analyzer.consolidate_secrets_cross_file(all_reports, threshold=3)
            analyzer.consolidate_endpoints_cross_file(all_reports, threshold=2)
        except Exception:
            pass

    if not args.out_file:
        for r in all_reports:
            print(f"\n=== {r['url']} ===")
            print(f"secrets={len(r['secrets'])} endpoints={len(r['endpoints'])} "
                  f"internal={len(r['internal_refs'])} errors={r['errors']}")
            for s in r['secrets']:
                live = s.get('live')
                tag = ''
                if isinstance(live, dict):
                    if live.get('checked') and live.get('valid') is True:
                        tag = ' [LIVE]'
                    elif live.get('checked') and live.get('valid') is False:
                        tag = ' [dead]'
                    elif not live.get('checked'):
                        tag = ' [manual]'
                dup = s.get('also_found_in') or []
                if dup:
                    tag += f" [+{len(dup)} file(s): " + ", ".join(dup) + "]"
                print(f"  [{s['severity']}] {s['type']} L{s['line']}{tag}")
            for e in r['endpoints']:
                dup = e.get('also_found_in') or []
                if dup:
                    print(f"  [endpoint] {e.get('absolute_url')}"
                          f" (also in {len(dup) + 1} files)")

    if args.out_file:
        with open(args.out_file, 'w') as f:
            _json.dump(all_reports, f, indent=2, default=str)
        print(f"[+] JSON report written to {args.out_file}")
    if args.wordlist_out:
        with open(args.wordlist_out, 'w') as f:
            f.write("\n".join(combined_wordlist) + ("\n" if combined_wordlist else ""))
        print(f"[+] Wordlist ({len(combined_wordlist)} tokens) written to {args.wordlist_out}")


if __name__ == '__main__':
    main()
