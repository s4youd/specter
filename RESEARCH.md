# Specter v2 — Research Notes & Improvement Log

Research done for improving `specter.py`, a JS secret/endpoint scanner for
authorized bug bounty recon. Sources are all public, well-known bug-bounty
tooling and vendor docs. Everything below fed directly into `specter.py`,
`validators.py`, and `requirements.txt` in this delivery.

---

## 1. Sources consulted

| Resource | What I pulled from it |
|---|---|
| [streaak/keyhacks](https://github.com/streaak/keyhacks) (+ forks: Blindsinner, knadt, DavidG2Q, manarea, phoenix-sec, zeroc00I) | The core validation-command database — curl one-liners per API key type, and how to read a valid vs. invalid response |
| [gwen001/keyhacks.sh](https://github.com/gwen001/keyhacks.sh) | Automation pattern for batch-validating leaked keys |
| [m4ll0k/SecretFinder](https://github.com/m4ll0k/SecretFinder) (Burp extension + CLI, and forks: blackhatethicalhacking, storenth, 0xcrow13) | Baseline secret regex set, `-r`/custom-regex UX pattern, entire-domain crawl mode (`-e`) |
| [aankasman/secret-regex-list](https://github.com/aankasman/secret-regex-list) | Cross-check list of common "known-format" secret regexes (Slack, RSA/PGP headers, Facebook, GitHub legacy) |
| [KathanP19/JSFScan.sh](https://github.com/KathanP19/JSFScan.sh) | Full JS-recon pipeline shape: gather JS links → extract endpoints → find secrets → wordlist → DOM-XSS variable extraction → HTML report |
| [harshexploits/jsmap](https://github.com/harshexploits/jsmap) | "Passive-only" JS recon framing (no active scanning of out-of-scope infra) and `--deep`/code-split-chunk-following idea, which motivated the `--max-depth` flag |
| GerbenJavado/LinkFinder (referenced throughout writeups) | Endpoint-regex approach (absolute + relative path extraction, JS string literal parsing) |
| YesWeHack "Recon Series #1" (bug bounty recon guide) | Endpoint/parameter discovery workflow: manual Burp crawl baseline → LinkFinder → wordlist fuzzing |
| Medium: *"Automate JavaScript (JS) Extraction for Bug Bounty Recon"*, *"How to Find Hidden API Endpoints and Secrets in JS Files"*, *"Bug Bounty Hacking Recon Automation Methodology"* | Practical pipeline glue: `gau`/`waybackurls` → filter `.js` → `httpx`/`curl` download → SecretFinder/LinkFinder/grep sweep → `de4js` for deobfuscation |
| Vendor API docs (Stripe, GitHub, GitLab, Slack, Twilio, SendGrid, OpenAI, Anthropic, Google, AWS STS, HashiCorp Vault, Datadog, PagerDuty, Notion, Figma, Airtable, Mapbox, Telegram, Discord, Braintree, Plaid, Algolia, Auth0, LaunchDarkly) | Exact "whoami"/auth-check endpoints used to build `validators.py`, since KeyHacks doesn't cover every modern SaaS (OpenAI, Anthropic, Notion, Figma, LaunchDarkly, Contentful, Groq, etc. — all added from first-party API docs) |

I did **not** find a dedicated PortSwigger Web Security Academy lab specifically
on "JS secret scanning" — their JS-relevant content is about DOM XSS,
client-side prototype pollution, and CSTI, which is a different (also
valuable, but out of scope here) attack surface than static-secret/endpoint
extraction. HackTricks doesn't have one single canonical "JS secrets" page
either — its relevant content is scattered across the pentesting-web
methodology pages and mirrors the same LinkFinder/SecretFinder/gau pipeline
described above, so I've represented that via the primary tool sources
instead of restating page contents that would just be described as "how to
use LinkFinder," which is already covered above.

---

## 2. What was wrong / missing in the original script

1. **No validation step at all.** A regex hit tells you nothing about
   whether a secret is *live*. Zero-false-positive tooling is only useful if
   the analyst can immediately triage true-positives from dead/rotated keys.
2. **Regex coverage gaps.** Missing: Facebook/Meta Graph tokens, Twitter/X
   bearer tokens, new-format npm tokens (`npm_...`), Figma, Notion, Airtable,
   Contentful, LaunchDarkly, Groq/Replicate/Mistral/Pinecone (AI-provider
   sprawl since late 2023), Mapbox `pk.eyJ...` JWT-style tokens, GraphQL
   operation names (high recon value — feeds directly into introspection /
   mutation-fuzzing).
3. **Connection-string regexes matched too loosely.** The original
   `mongodb://...`, `postgres://...` etc. patterns matched even
   credential-less URIs (e.g. `mongodb://cluster.example.com/mydb`), which
   are not secrets. Tightened to require `user:pass@` in the match itself;
   the unauthenticated form is arguably still useful as an "Internal
   Reference" finding but shouldn't burn a "critical secret" slot.
4. **No concept of "paired" secrets.** AWS Access Key ID and Secret Access
   Key are two separate regex hits; without flagging that, a report reads as
   if each is independently exploitable, which is misleading and wastes
   validation attempts. Same issue for Twilio SID/token, Auth0
   client_id/secret, Atlassian email/token, etc.
5. **No structured output.** CLI-only, no JSON/Markdown report — makes it
   hard to feed into a report template or a second-stage tool.
6. **Entropy/false-positive logic was solid but under-documented** — kept
   almost entirely as-is (this was the best part of the original script) and
   only lightly extended to cover the new generic-secret label set.
7. **Endpoint extraction had good breadth already** (fetch/axios/jQuery/
   Angular/Express/SPA-router patterns) but no GraphQL operation-name
   extraction, which is one of the highest-signal JS recon patterns per the
   writeups above (an operation name directly seeds `-query`/introspection
   testing).
8. **Sub-file following had a hardcoded `depth > 1` cutoff** with no CLI
   control. Exposed as `--max-depth`.

---

## 3. What changed in `specter.py`

- **`validators.py`** (new file): every secret label that has a known,
  documented validation method now maps to a curl command (or CLI-tool
  command for non-HTTP secrets: `mongosh`, `psql`, `redis-cli`,
  `aws sts get-caller-identity`, `gcloud`, `openssl`). Each finding's output
  now includes:
  ```json
  "validation": {
    "command": "curl -s -H \"Authorization: token ghp_xxx\" https://api.github.com/user",
    "indicator": "200 + user JSON = valid. 401 'Bad credentials' = dead/revoked.",
    "requires_pairing": false
  }
  ```
- **`requires_pairing`** flag: secrets that need a second value (AWS
  key+secret, Twilio SID+token, Auth0 client_id+secret, Shopify shop
  subdomain, etc.) are explicitly marked so a report doesn't overstate a
  single regex hit's exploitability.
- **`--validate` flag** (opt-in, off by default): runs a *safe, read-only
  GET-only* live check for the subset of secrets where that's possible
  in one HTTP call with no paired data (GitHub, GitLab, OpenAI, Anthropic,
  Google API key/OAuth token, Mailgun, Telegram, Mapbox, Snyk, Airtable,
  Sentry, Datadog, NPM, Figma, Notion, LaunchDarkly, Hugging Face,
  DigitalOcean). Anything POST-based, destructive-adjacent, or paired is
  **intentionally left to the analyst** to run the printed curl manually —
  auto-firing a POST/webhook/DB-write with a scraped credential is not
  something a recon tool should do unattended.
- **New regex patterns** (see full diff in `specter.py`): Facebook/Meta
  Graph token, Facebook App Secret, Twitter/X Bearer Token, Twitter/X API
  Secret, npm new-format token, Groq, Replicate, Cohere, Mistral, Pinecone,
  Figma PAT, Notion integration token, Airtable key, Contentful key,
  LaunchDarkly SDK key, Mapbox JWT-style token, GraphQL operation name,
  Sentry Auth Token (`sntrys_...`), New Relic User API Key (`NRAK-...`),
  DigitalOcean PAT (`dop_v1_...`), tightened connection-string patterns.
- **Report writers**: `write_json_report()` and `write_markdown_report()`,
  selectable via `-o {cli,json,md}`.
- **CLI** via `argparse`: `-u/--url`, `-o/--output`, `--out-file`,
  `--validate`, `--no-probe`, `--max-depth`, `--workers`.
- Kept the original's strongest asset — the false-positive filtering
  (`_is_false_positive_secret`, entropy floor, placeholder dictionary,
  comment/test/doc-context suppression) — essentially unchanged, since
  research didn't surface anything better than what was already there;
  only extended the label sets it checks against so new patterns get the
  same treatment.

---

## 4. Validating what you find — quick reference

Full commands are embedded per-finding in the tool's output; this is the
condensed cheat-sheet version, organized by *how* you validate:

**Single curl, single header (safest, `--validate` auto-checks these):**
GitHub PAT/OAuth, GitLab PAT, OpenAI, Anthropic, Hugging Face, DigitalOcean,
Google API key/OAuth token, Mailgun (basic auth), Telegram bot token,
Mapbox, Snyk, Airtable, Sentry auth token, Datadog, NPM, Figma, Notion,
LaunchDarkly.

**Single curl, POST with JSON body (validate manually — don't auto-fire):**
Slack (`auth.test` / webhook — webhook posts to a *real channel*, keep the
body empty), Firebase FCM server key (pushes to real devices — highest
blast-radius check in this list, confirm-then-stop), Auth0 (client
credentials grant), Plaid (`institutions/get`), Linear (GraphQL viewer
query), New Relic (GraphQL).

**Needs a paired second secret found nearby in the same file:**
AWS Access Key ID + Secret Access Key, Twilio SID + Auth Token/API Secret,
Atlassian email + token, Bitbucket username + app password, Auth0
client_id + secret, Algolia App ID + Admin key, Shopify shop subdomain +
token, Okta org domain + token, Contentful space ID + key, Plaid client_id +
secret, PayPal Braintree merchant ID (embedded in the token's own 3rd
segment) + token.

**Non-HTTP tools:**
- AWS: `aws sts get-caller-identity` (needs AWS CLI + both key parts)
- MongoDB/Postgres/MySQL/Redis: `mongosh` / `psql` / `mysql` / `redis-cli`
  directly against the leaked connection string — **stop immediately after
  confirming connectivity**, don't browse collections/tables/keys without
  explicit program authorization to do so
- Private keys: `openssl rsa -check`, then MD5-compare the derived public
  key against the target's live TLS cert to prove the leaked key is
  actually *in use*, not just well-formed
- Google service account JSON: `gcloud auth activate-service-account`

**Rule of thumb for severity after validation:**
`live + production/write-scope` → critical · `live + read-only/test-mode`
→ medium · `dead/revoked/expired` → informational (still worth reporting
as a hygiene issue — "secret was live at commit X, rotated by report time"
— but not a standalone critical).

---

## 5. Endpoint discovery — how this fits a full recon pipeline

`specter.py` only analyzes JS you already point it at. To feed it at scale
(per JSFScan.sh / jsmap / the YesWeHack and Medium writeups above), the
typical pipeline is:

```bash
# 1. Collect JS URLs (historical + live)
echo "target.com" | gau --threads 10 | grep '\.js$' > js_urls.txt
echo "target.com" | waybackurls | grep '\.js$' >> js_urls.txt
katana -u https://target.com -jc -d 3 -silent | grep '\.js$' >> js_urls.txt
sort -u js_urls.txt -o js_urls.txt

# 2. Run Specter against each
while read -r url; do
  python3 specter.py -u "$url" -o json --out-file "reports/$(echo "$url" | md5sum | cut -d' ' -f1).json"
done < js_urls.txt

# 3. Triage: pull every secret across all reports, sorted by severity
jq -s '[.[].secrets[]] | sort_by(.severity)' reports/*.json > all_secrets.json

# 4. Feed discovered endpoints into further testing (ffuf wordlist, Arjun for params)
jq -s '[.[].endpoints[].absolute_url] | unique | .[]' reports/*.json > endpoints.txt
ffuf -u FUZZ -w endpoints.txt -mc all -fc 404
```

`--max-depth` controls how far Specter itself follows `.js`/`.map`
references it finds *inside* a file (code-split chunks, source maps); it
does not replace the outer collection stage above — that's a separate,
much larger surface (subdomain enum, crawling, historical URL mining) that
a single-file analyzer intentionally doesn't try to own.

---

## 6. Things I'd still improve next (didn't fit this pass)

- **Source map consumption**: currently Specter detects and fetches `.map`
  files as "sub_files" but doesn't parse the `sources`/`sourcesContent`
  fields to recover original (pre-bundle) file paths and source — that's
  often where the highest-value secrets/comments live, since minified
  bundles strip a lot of context. Worth a dedicated `sourcemap.py` module.
- **De-obfuscation hook**: for webpack-obfuscated or Terser-mangled bundles,
  piping through a headless `de4js`-equivalent (e.g. `babel` AST unpacking)
  before regex matching would recover secrets currently hidden behind
  string-array obfuscation. Out of scope for a regex-based tool as-is.
- **Wordlist generation**: JSFScan.sh's "generate wordlist from JS" and
  "extract variable names for XSS surface" features aren't reproduced here
  — could be a `--wordlist` flag that dumps all identifiers/string literals
  for use with ffuf/Arjun.
- **Rate limiting / backoff** on `--validate` and endpoint probing — right
  now it's a flat thread pool with a fixed timeout; a real engagement
  against a rate-limited target would want jittered backoff.
- **`.env`/webpack `DefinePlugin` leftover detection**: some frameworks
  inline `process.env.X` values at build time; a dedicated pass looking for
  suspiciously-adjacent env-var-named constants (beyond the current
  generic entropy check) could catch more of these.

---

## 7. Legal / responsible-use note

Every validation command in `validators.py` is read-only or a documented
"whoami" check — none of them revoke, delete, spend, or modify anything.
Still: only run `--validate` or any of these commands against assets that
are explicitly in scope for a program you're authorized to test, and follow
that program's disclosure rules for how much proof-of-impact detail to
include in a report (usually: confirm validity, don't dump real data).
