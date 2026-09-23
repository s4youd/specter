# Specter

JavaScript security analyzer for authorized bug bounty recon. Point it at JS
files — it extracts exposed secrets (146 fixed-format detectors), hidden API
endpoints (with status code + page title), GraphQL operation names,
internal/staging references, emails, and source-map leaks — including
secrets recovered from embedded source-map originals with per-file
attribution. Every secret finding ships with a copy-pasteable validation
command, and the UI adds
one-click **Validate All Secrets** (live / dead / needs-hands verdicts).
URL status, title, and word count are probed automatically during every
scan. Identical secrets found
across 3+ files are consolidated into one entry listing every file.

All analysis runs server-side. The browser receives results only.

## Install

```bash
git clone https://github.com/s4youd/Specter.git
cd Specter
pip install -r requirements.txt --break-system-packages
```

## Run

### Web UI

```bash
python run.py
```

Open `http://localhost:5000`. Paste a JS file URL, paste many URLs (Bulk),
or drop a `.txt`/`.csv` file with one URL per line. After a scan:

- **Validate All Secrets** — safe, read-only identity checks where possible.
  Results are grouped into **Valid · live**, **Invalid · dead**,
  **Needs hands** (paired secrets such as AWS key+secret, shop subdomains,
  Vault hosts — use the shown curl command), and **Unknown** (network/rate
  limit — retry or check manually).
- **Automatic URL probing** — every discovered URL is probed during the
  scan itself: status code, page title, word count, and final URL after
  redirects, shown right on each endpoint. No extra button needed.
- **Per-file Validate** — each file row has its own **Validate** button
  for that file's secrets; scoped results merge into the same panel and
  badges without wiping other files.
- Every secret expands into an accordion with **Copy** buttons (full
  secret value and full validation command — never truncated), the
  beautified 3-line code excerpt where it was found (match highlighted),
  and its validation command. Every endpoint URL opens in a new tab.
- **Cross-file duplicates** — the same secret in 3+ files shows once with
  a `×N files` badge and a clickable list of every file (also included in
  JSON export).

### CLI (recon pipeline friendly)

```bash
# Single file, human-readable summary
python specter.py -u https://target.com/app.js

# Multiple files + JSON report for jq triage
python specter.py -u https://target.com/a.js -u https://target.com/b.js --out-file reports.json

# Safe live validation where possible (authorized targets only)
python specter.py -u https://target.com/app.js --validate

# Skip endpoint probing / follow .js/.map references deeper
python specter.py -u https://target.com/app.js --no-probe --max-depth 2

# Dump a combined ffuf/Arjun wordlist (identifiers + string literals)
python specter.py -u https://target.com/app.js --wordlist-out wordlist.txt --no-probe
```

Full recon pipeline (per `RESEARCH.md`):

```bash
# 1. Collect JS URLs (historical + live)
echo "target.com" | gau --threads 10 | grep '\.js$' > js_urls.txt
echo "target.com" | waybackurls | grep '\.js$' >> js_urls.txt
katana -u https://target.com -jc -d 3 -silent | grep '\.js$' >> js_urls.txt
sort -u js_urls.txt -o js_urls.txt

# 2. Run Specter over the list (web UI file-drop does the same)
python run.py  # then drop js_urls.txt into the File tab
```

### HTTP API

| Endpoint | Method | Body | Returns |
|---|---|---|---|
| `/api/analyze` | POST | `{urls: [...]}` or `{url: ...}` | per-file secrets, endpoints (+probe), internals, emails, source maps |
| `/api/analyze/stream` | POST | same (SSE) | progress + per-file events for bulk scans |
| `/api/validate` | POST | `{secrets: [{type, match, file, line}]}` | `{summary: {valid, invalid, manual, unknown}, results: [...]}` with masked values, curl commands, and reading guides |
| `/api/liveness` | POST | `{urls: [...]}` | `{summary, results: [{url, status, title, word_count, final_url}]}` — unsafe (non-public) URLs are rejected unless `SPECTER_ALLOW_PRIVATE=true` |
| `/api/results/<session_id>` | GET | — | stored session |
| `/api/export/<session_id>` | GET | — | downloadable JSON |

## What It Finds

### Secrets and Credentials (146 detectors)

AWS keys/session tokens, Google API keys/OAuth/service accounts/reCAPTCHA
(site keys are flagged informational — public by design) + OAuth client
secrets, GitHub (PAT classic + fine-grained + OAuth + user + server +
refresh + generic),
GitLab (PAT + pipeline + runner + feature-flag), Stripe (live/test,
restricted, webhook, publishable — publishable flagged low since public by
design), Slack (bot/user/OAuth/webhook), Twilio (SID/auth/API/App SID),
SendGrid, Mailgun, Firebase FCM + database URLs, OpenAI, Anthropic,
Hugging Face, Groq, Replicate, Cohere, Mistral, Pinecone, DeepSeek,
Together, Perplexity, OpenRouter, xAI, Fireworks, Cerebras, Apify,
Tavily, LangSmith, Langfuse, HashiCorp Vault,
DigitalOcean, Linear, Snyk, Sentry (auth tokens + DSNs), New Relic,
Datadog, PagerDuty, Heroku, WakaTime, SonarCloud, Shopify, Telegram,
Square, PayPal Braintree, Discord (+ webhooks), Teams webhooks,
Atlassian, Bitbucket, Auth0, Okta, Docker Hub, PyPI, Terraform Cloud,
Pulumi, Netlify, Grafana, Plaid, Algolia, Mapbox (access + secret),
Postmark, Mailchimp, Airtable, Notion, Figma,
LaunchDarkly, Contentful, Cloudflare, Resend, Vercel, NPM, Facebook/Meta,
Twitter/X, private keys, crypto seeds, DB connection strings
(MongoDB/PostgreSQL/MySQL/Redis/AMQP — only when they carry credentials),
JWTs, Supabase keys (JWT + new `sb_secret_`/`sb_publishable_` formats),
Cloudinary URLs, Laravel app keys, WordPress salts, and a small set of
entropy-gated generic assignments (`api_key = ...`, `*_secret = ...`,
`admin_secret`, `private_token`, `refresh_token`, passwords).

Each finding carries a `validation` block: a ready-to-run curl (or CLI)
command, how to read the response, and a `requires_pairing` flag for
two-part secrets (AWS key+secret, Twilio SID+token, Auth0
client_id+secret, Algolia App ID+key, Shopify shop+token, Okta domain+token,
Contentful space+key, Plaid client_id+secret, etc.).

### API Endpoints

fetch/axios, XHR, jQuery AJAX, WebSocket, SSE, Angular/HttpClient, Express
routes, SPA navigation, base URLs, REST paths, full URLs, and **GraphQL
operation names** (seeds introspection testing). CDN assets, images,
fonts, and vendor bundles are filtered. Each endpoint is probed: status
code, title, word count, final URL.

**Same-brand scoping:** only URLs belonging to the scanned file's brand
are reported — scanning `uber.com` keeps `uber.com`, `uber.net`,
`*.uber.com` (anything with the brand in the host) and drops third
parties like facebook/google. Relative paths and GraphQL operations
always stay. IP test targets (e.g. `127.0.0.1`) keep everything.

### Internal and Staging References

Staging/dev/test/qa/beta URLs, private IP ranges, `.internal`/`.local`
domains, internal API references, AWS S3 bucket references, exposed
`process.env.*` / `import.meta.env.*` secret-ish variable names (values,
when present, are caught by the secret patterns), and an
`Obfuscated Bundle` flag when packer string-array/decoder patterns are
detected (results below such a flag may be incomplete — deobfuscate
manually; automated unpacking is deliberately out of scope).

### Source Maps / Emails / Comments

`sourceMappingURL` references are fetched and their embedded original
sources (`sourcesContent`) are each scanned with per-file attribution
under Sub Files, plus an `Exposed Source Paths` listing. Non-map
responses fall back to legacy raw scanning. Email addresses,
TODO/FIXME/SECURITY comments.

## False Positive Strategy (zero-FP design)

- **Fixed-format-first**: ~140 detectors anchor on provider shapes
  (prefix + exact length/charset). No loose `ENV_VAR = "(.*)"` catch-alls.
- **Entropy gates** on the few generic patterns: Shannon ≥ 3.5
  (≥ 4.3 when the value has no digits), min length, plus a
  digit-or-special-character requirement (Gitleaks generic-rule logic).
- **Degenerate rejection**: all-same-character values (`AAAA…`, UUID
   nil-patterns) and documentation example keys (`AKIAIOSFODNN7-EXAMPLE`…
   hyphenated here on purpose so this file never trips push protection)
  never fire.
- **Placeholder suppression**: `your_api_key`, `changeme`, `xxx`, test
  values — substring-aware so real secrets merely containing "test"
  still fire.
- **Word-boundary test/docs suppression**: `describe(`/`it(`/`expect(`
  blocks and `@example`/swagger contexts suppress, while `.split(`,
  `latest_`, `contest(`, `pk_test_` in production code do not.
- **Comment-line, `process.env`, import/require, and example-domain**
  suppression; bare-UUID and bare short values never match (context-gated
  instead: Postmark/Snyk/Heroku/WakaTime/SonarCloud/Airtable).

## Validation semantics

`valid` = issuer accepted the credential (rotate immediately) ·
`invalid` = issuer rejected it (dead/revoked — still report as hygiene) ·
`manual` = needs a paired value or a human step (the curl command shows
exactly what) · `unknown` = inconclusive transport error (retry).

Rate limiting is never reported as dead: HTTP 429 and 5xx map to
`unknown`, and both probing and validation retry with jittered
exponential backoff honoring `Retry-After` (capped at 5s).

**Known shape ambiguities** (the live check disambiguates — a dead verdict
on one provider means trying the colliding provider before discarding):
Clerk / WorkOS / Magic-style keys reuse the Stripe shape (`sk_live_*`,
`pk_live_*`); reCAPTCHA site and secret keys share the `6L` prefix and
length, so bare `6L` matches stay informational.

Only run validation against assets explicitly in scope. Every check is a
read-only identity call; POST-based checks (Slack `auth.test`, Linear /
New Relic GraphQL viewer queries) perform no writes. Webhook, FCM push,
PagerDuty integration, and DB-connection checks are manual-only by design.

## Local testing

The server blocks non-public targets (SSRF guard) on `/api/analyze` and
`/api/liveness`. To scan/probe localhost or LAN targets while testing
locally, start with:

```bash
SPECTER_ALLOW_PRIVATE=true python run.py
```

Never enable this on a publicly reachable server.

## File Structure

```
Specter/
  run.py          Flask server: /api/analyze, /api/validate, /api/liveness
  specter.py      Analysis engine + CLI (146 secret patterns, FP filters)
  validators.py   Validation-command DB + safe live checks per secret type
  requirements.txt
  README.md
  RESEARCH.md     research notes, validation cheat-sheet, pipeline docs
  tests/          pytest + node regression suites
  templates/
    index.html
  static/
    css/style.css
    js/app.js
```

## License

MIT

## Author

[s4youd](https://sayed.is-a.dev)
