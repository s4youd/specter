#!/usr/bin/env python3
"""
validators.py - Secret validation command database for Specter (v3, consolidated).

Every entry maps a secret-type label (must match specter.py's secret_patterns
labels exactly) to:
  - a copy-pasteable curl command template ({value} = matched secret),
  - a human note on how to read VALID vs INVALID responses,
  - manual=True when a second piece of info (paired secret, shop subdomain,
    space ID, host...) is required that Specter cannot auto-supply.

Safety: every command is a read-only, non-destructive auth-check ("whoami").
Only run these against assets explicitly in scope for an authorized
engagement. A 200/valid response is itself sensitive proof-of-impact - do not
paste raw responses into public reports.

Known shape ambiguities (the live check disambiguates - a dead verdict on one
provider means "try the colliding provider's check before discarding"):
  - Clerk / WorkOS / Magic-style keys reuse the Stripe shape (sk_live_*,
    pk_live_*, sk_test_*). A 401 on api.stripe.com does NOT prove the key is
    dead - it may belong to one of those auth providers instead.
  - reCAPTCHA site keys and secret keys share the 6L prefix and length, so a
    bare 6L match is reported informational only; impact requires the secret
    key server-side, which looks identical.

Sources: streaak/keyhacks (+ forks), gwen001/keyhacks.sh, vendor API docs
(Stripe, GitHub, GitLab, Slack, Twilio, OpenAI, Anthropic, Google, AWS STS,
HashiCorp Vault, Datadog, PagerDuty, Notion, Figma, Airtable, Mapbox,
Telegram, Discord, Cloudflare, Resend, Vercel, Postmark, Mailchimp, Linear,
Sentry, Snyk, Groq, Replicate, Cohere, Mistral, Pinecone, DeepSeek, Together,
OpenRouter, xAI, Fireworks, Shodan, CircleCI, Buildkite, Hugging Face,
DigitalOcean, Square, Shopify, Auth0, Okta, Plaid, Algolia, Contentful,
LaunchDarkly, X/Twitter, Meta, NPM).
"""

from typing import Dict, Optional, Any
import re
import time
import random

VALIDATORS: Dict[str, dict] = {
    # ================= AWS =================
    "AWS Access Key ID": {
        "method": "GET",
        "curl": "AWS_ACCESS_KEY_ID={value} AWS_SECRET_ACCESS_KEY=<PAIRED_SECRET> aws sts get-caller-identity",
        "indicator": "Returns {Account, UserId, Arn} JSON = valid & live. 'InvalidClientTokenId' / 'SignatureDoesNotMatch' = dead or needs the paired secret.",
        "manual": True,
    },
    "AWS Secret Access Key": {
        "method": "GET",
        "curl": "AWS_ACCESS_KEY_ID=<PAIRED_ACCESS_KEY_ID> AWS_SECRET_ACCESS_KEY={value} aws sts get-caller-identity",
        "indicator": "Same as above - needs the paired Access Key ID found nearby in the same file.",
        "manual": True,
    },
    "AWS Session Token": {
        "method": "GET",
        "curl": "AWS_ACCESS_KEY_ID=<KEY> AWS_SECRET_ACCESS_KEY=<SECRET> AWS_SESSION_TOKEN={value} aws sts get-caller-identity",
        "indicator": "Needs the paired key + secret. Valid trio returns caller identity JSON.",
        "manual": True,
    },

    # ================= Google =================
    "Google API Key": {
        "method": "GET",
        "curl": 'curl -s "https://www.googleapis.com/discovery/v1/apis?key={value}"',
        "indicator": "HTTP 200 + API list JSON = live key. 'API_KEY_INVALID' = dead. For Maps-scoped keys also try: curl -s \"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={value}\"",
        "manual": False,
    },
    "Google OAuth Access Token": {
        "method": "GET",
        "curl": 'curl -s "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={value}"',
        "indicator": "200 + JSON with scope/expires_in = valid live token. 400 'invalid_token' = expired/revoked.",
        "manual": False,
    },
    "Google Service Account Key": {
        "method": "GET",
        "curl": "gcloud auth activate-service-account --key-file=service_account.json && gcloud auth print-access-token",
        "indicator": "Prints a ya29.* access token = valid credential file. Auth error = invalid/revoked. Needs the full JSON key file.",
        "manual": True,
    },

    # ================= GitHub =================
    "GitHub Personal Access Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: token {value}" https://api.github.com/user',
        "indicator": "200 + user JSON (login, id) = valid. 401 'Bad credentials' = dead. Check scopes: curl -sI -H \"Authorization: token {value}\" https://api.github.com/user | grep -i x-oauth-scopes",
        "manual": False,
    },
    "GitHub Fine-grained Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://api.github.com/user',
        "indicator": "200 = valid. Fine-grained tokens are repo/org scoped, so if /user 403s also try the suspected repo: curl -s -H \"Authorization: Bearer {value}\" https://api.github.com/repos/OWNER/REPO",
        "manual": False,
    },
    "GitHub OAuth Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: token {value}" https://api.github.com/user',
        "indicator": "Same as PAT check - 200 = live.",
        "manual": False,
    },
    "GitHub User Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: token {value}" https://api.github.com/user',
        "indicator": "200 = live. 401 = dead.",
        "manual": False,
    },
    "GitHub Server-to-Server Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://api.github.com/app',
        "indicator": "200 + app JSON = valid GitHub App token. 401 = dead/expired (these tokens expire after 1h by design).",
        "manual": False,
    },
    "GitHub Refresh Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://api.github.com/user',
        "indicator": "Refresh tokens are single-use and short-lived; a 200 means it has not been consumed yet. Normally 401 = already used/expired.",
        "manual": False,
    },

    # ================= GitLab =================
    "GitLab Personal Access Token": {
        "method": "GET",
        "curl": 'curl -s --header "PRIVATE-TOKEN: {value}" "https://gitlab.com/api/v4/user"',
        "indicator": "200 + user JSON = valid. 401 = dead. If self-hosted, swap gitlab.com for the target instance.",
        "manual": False,
    },
    "GitLab Pipeline Token": {
        "method": "GET",
        "curl": 'curl -s --header "PRIVATE-TOKEN: {value}" "https://gitlab.com/api/v4/user"',
        "indicator": "200 = valid. Pipeline tokens are project-scoped; prefer checking against the target project API.",
        "manual": False,
    },
    "GitLab Runner Token": {
        "method": "N/A",
        "curl": "# Runner tokens register a runner - do NOT auto-fire. Confirm context manually and report without registering.",
        "indicator": "Do not validate by registering a runner against someone else's instance. Treat as valid-by-format and report.",
        "manual": True,
    },
    "GitLab Feature Flag Token": {
        "method": "N/A",
        "curl": "# Feature-flag client tokens are evaluated inside the target app context; confirm the Unleash/Flag endpoint manually.",
        "indicator": "Manual: check whether the flag-evaluation endpoint accepts it in-app.",
        "manual": True,
    },

    # ================= Slack =================
    "Slack Bot Token": {
        "method": "POST",
        "curl": 'curl -s -X POST "https://slack.com/api/auth.test" -H "Authorization: Bearer {value}"',
        "indicator": "\"ok\":true + team/user info = valid. \"ok\":false,\"error\":\"invalid_auth\" = dead.",
        "manual": False,
    },
    "Slack Token": {
        "method": "POST",
        "curl": 'curl -s -X POST "https://slack.com/api/auth.test?token={value}&pretty=1"',
        "indicator": "\"ok\":true = valid live token.",
        "manual": False,
    },
    "Slack User Token": {
        "method": "POST",
        "curl": 'curl -s -X POST "https://slack.com/api/auth.test?token={value}&pretty=1"',
        "indicator": "\"ok\":true = valid.",
        "manual": False,
    },
    "Slack OAuth Access Token": {
        "method": "POST",
        "curl": 'curl -s -X POST "https://slack.com/api/auth.test" -H "Authorization: Bearer {value}"',
        "indicator": "\"ok\":true = valid.",
        "manual": False,
    },
    "Slack Incoming Webhook URL": {
        "method": "POST",
        "curl": 'curl -s -X POST -H "Content-type: application/json" -d \'{"text":""}\' "{value}"',
        "indicator": "\"missing_text_or_fallback_or_attachments\" = webhook is VALID (keep the body empty - real text posts to a real channel!). \"invalid_token\" / 404 = dead.",
        "manual": True,
    },

    # ================= Twilio =================
    "Twilio API Key": {
        "method": "GET",
        "curl": "curl -s -u {value}:<PAIRED_API_SECRET> https://api.twilio.com/2010-04-01/Accounts.json",
        "indicator": "200 + Accounts JSON = valid. 401 = dead. Needs the paired API Secret.",
        "manual": True,
    },
    "Twilio Account SID": {
        "method": "GET",
        "curl": "curl -s -u <ACCOUNT_SID>:<AUTH_TOKEN> https://api.twilio.com/2010-04-01/Accounts.json",
        "indicator": "200 = valid pair. Needs the Auth Token found nearby.",
        "manual": True,
    },
    "Twilio Credential": {
        "method": "GET",
        "curl": "curl -s -u <ACCOUNT_SID>:<AUTH_TOKEN> https://api.twilio.com/2010-04-01/Accounts.json",
        "indicator": "200 = valid.",
        "manual": True,
    },
    "Twilio Auth Token": {
        "method": "GET",
        "curl": "curl -s -u <ACCOUNT_SID>:{value} https://api.twilio.com/2010-04-01/Accounts/<ACCOUNT_SID>.json",
        "indicator": "200 + account JSON = valid pair. 401 = dead. Needs the Account SID found nearby.",
        "manual": True,
    },

    # ================= SendGrid / Mailgun =================
    "SendGrid API Key": {
        "method": "GET",
        "curl": 'curl -s -X GET "https://api.sendgrid.com/v3/scopes" -H "Authorization: Bearer {value}"',
        "indicator": "200 + {\"scopes\":[...]} = valid, shows exact permissions. 401 = dead.",
        "manual": False,
    },
    "Mailgun API Key": {
        "method": "GET",
        "curl": 'curl -s --user "api:{value}" "https://api.mailgun.net/v3/domains"',
        "indicator": "200 + domain list = valid. 401 = dead.",
        "manual": False,
    },

    # ================= Stripe =================
    "Stripe Live Secret Key": {
        "method": "GET",
        "curl": "curl -s https://api.stripe.com/v1/charges?limit=1 -u {value}:",
        "indicator": "200 + charges list (even empty) = LIVE PRODUCTION KEY - critical, stop after confirming, do not enumerate customer data. 401 'Invalid API Key' = dead.",
        "manual": False,
    },
    "Stripe Test Secret Key": {
        "method": "GET",
        "curl": "curl -s https://api.stripe.com/v1/charges?limit=1 -u {value}:",
        "indicator": "200 = valid test-mode key (low impact).",
        "manual": False,
    },
    "Stripe Live Restricted Key": {
        "method": "GET",
        "curl": "curl -s https://api.stripe.com/v1/charges?limit=1 -u {value}:",
        "indicator": "200 or a 403 with a specific permission error (still confirms validity) = live. 401 = dead.",
        "manual": False,
    },
    "Stripe Test Restricted Key": {
        "method": "GET",
        "curl": "curl -s https://api.stripe.com/v1/charges?limit=1 -u {value}:",
        "indicator": "200/403-permission-error = live test key. 401 = dead.",
        "manual": False,
    },
    "Stripe Webhook Secret": {
        "method": "N/A",
        "curl": "# Not API-callable - verifies inbound webhook signatures locally.\n# Confirm the app webhook endpoint exists:\n# curl -s -o /dev/null -w \"%{http_code}\" https://target.com/webhooks/stripe",
        "indicator": "Impact = ability to forge webhook payloads against the app's webhook endpoint.",
        "manual": True,
    },

    # ================= NPM =================
    "NPM Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://registry.npmjs.org/-/npm/v1/user',
        "indicator": "200 + username = valid. 401 = dead.",
        "manual": False,
    },

    # ================= AI providers =================
    "OpenAI API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.openai.com/v1/models -H "Authorization: Bearer {value}"',
        "indicator": "200 + model list = valid live key (billable!). 401 'invalid_api_key' = dead. Also reveals org/project scope.",
        "manual": False,
    },
    "Anthropic API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.anthropic.com/v1/models -H "x-api-key: {value}" -H "anthropic-version: 2023-06-01"',
        "indicator": "200 + model list = valid live key. 401 = dead.",
        "manual": False,
    },
    "Anthropic OAuth Token": {
        "method": "GET",
        "curl": 'curl -s https://api.anthropic.com/v1/models -H "Authorization: Bearer {value}" -H "anthropic-version: 2023-06-01"',
        "indicator": "200 + model list = valid live OAuth token (Claude Code style). 401 = dead/expired.",
        "manual": False,
    },
    "OpenAI Admin Key": {
        "method": "GET",
        "curl": 'curl -s https://api.openai.com/v1/models -H "Authorization: Bearer {value}"',
        "indicator": "200 + model list = valid. Admin keys carry org-level scope - treat as critical, rotate immediately.",
        "manual": False,
    },
    "Hugging Face Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://huggingface.co/api/whoami-v2',
        "indicator": "200 + account JSON (name, orgs) = valid. 401 = dead.",
        "manual": False,
    },
    "Groq API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.groq.com/openai/v1/models -H "Authorization: Bearer {value}"',
        "indicator": "200 + model list = valid. 401 = dead.",
        "manual": False,
    },
    "Replicate API Token": {
        "method": "GET",
        "curl": 'curl -s "https://api.replicate.com/v1/predictions?limit=1" -H "Authorization: Token {value}"',
        "indicator": "200 + predictions JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Cohere API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.cohere.com/v1/models -H "Authorization: Bearer {value}"',
        "indicator": "200 + model list = valid. 401 = dead.",
        "manual": False,
    },
    "Mistral AI Key": {
        "method": "GET",
        "curl": 'curl -s https://api.mistral.ai/v1/models -H "Authorization: Bearer {value}"',
        "indicator": "200 + model list = valid. 401 = dead.",
        "manual": False,
    },
    "Pinecone API Key": {
        "method": "GET",
        "curl": 'curl -s "https://api.pinecone.io/indexes" -H "Api-Key: {value}"',
        "indicator": "200 + index list = valid. 401 = dead. (If the project uses a custom controller host, swap the hostname.)",
        "manual": False,
    },
    "DeepSeek API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.deepseek.com/models -H "Authorization: Bearer {value}"',
        "indicator": "200 + model list = valid. 401 = dead.",
        "manual": False,
    },
    "Together AI Key": {
        "method": "GET",
        "curl": 'curl -s https://api.together.xyz/v1/models -H "Authorization: Bearer {value}"',
        "indicator": "200 + model list = valid. 401 = dead.",
        "manual": False,
    },
    "Perplexity API Key": {
        "method": "POST",
        "curl": 'curl -s https://api.perplexity.ai/chat/completions -H "Authorization: Bearer {value}" -H "Content-Type: application/json" -d \'{"model":"sonar","messages":[{"role":"user","content":"hi"}],"max_tokens":1}\'',
        "indicator": "200 = valid (costs ~1 token - only run with authorization). 401 = dead. Prefer manual confirmation.",
        "manual": True,
    },
    "OpenRouter API Key": {
        "method": "GET",
        "curl": 'curl -s https://openrouter.ai/api/v1/auth/key -H "Authorization: Bearer {value}"',
        "indicator": "200 + key metadata (usage/limit) = valid. 401/403 = dead.",
        "manual": False,
    },
    "xAI API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.x.ai/v1/models -H "Authorization: Bearer {value}"',
        "indicator": "200 + model list = valid. 401 = dead.",
        "manual": False,
    },
    "Fireworks API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.fireworks.ai/inference/v1/models -H "Authorization: Bearer {value}"',
        "indicator": "200 + model list = valid. 401 = dead.",
        "manual": False,
    },
    "Cerebras API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.cerebras.ai/v1/models -H "Authorization: Bearer {value}"',
        "indicator": "200 + model list = valid. 401 = dead. (Newer provider - if the path drifted, check current docs.)",
        "manual": True,
    },
    "Apify Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://api.apify.com/v2/users/me',
        "indicator": "200 + user JSON = valid. 401 = dead. (Newer provider - if the path drifted, check current docs.)",
        "manual": True,
    },
    "Tavily API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.tavily.com/usage -H "Authorization: Bearer {value}"',
        "indicator": "200 + usage JSON = valid. 401 = dead. (Newer provider - if the path drifted, check current docs.)",
        "manual": True,
    },
    "LangSmith API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.smith.langchain.com/sessions -H "x-api-key: {value}"',
        "indicator": "200 (even empty list) = valid. 401/403 = dead. (Newer provider - if the path drifted, check current docs.)",
        "manual": True,
    },
    "Langfuse Secret Key": {
        "method": "GET",
        "curl": 'curl -s -u "{value}:" https://cloud.langfuse.com/api/public/projects',
        "indicator": "200 + projects JSON = valid. 401 = dead. Self-hosted? swap the hostname. (Langfuse pairs this with a public key - confirm in current docs.)",
        "manual": True,
    },

    # ================= HashiCorp / DO / Linear / Snyk =================
    "HashiCorp Vault Token": {
        "method": "GET",
        "curl": 'curl -s --header "X-Vault-Token: {value}" https://<VAULT_HOST>:8200/v1/auth/token/lookup-self',
        "indicator": "200 + token metadata (policies, ttl) = valid. 403 = dead/expired. Needs the target Vault host.",
        "manual": True,
    },
    "DigitalOcean Token": {
        "method": "GET",
        "curl": 'curl -s -X GET -H "Authorization: Bearer {value}" "https://api.digitalocean.com/v2/account"',
        "indicator": "200 + account JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Linear API Key": {
        "method": "POST",
        "curl": 'curl -s -X POST https://api.linear.app/graphql -H "Authorization: {value}" -H "Content-Type: application/json" -d \'{"query":"{ viewer { id name } }"}\'',
        "indicator": "200 + viewer JSON = valid. 'Authentication required' = dead.",
        "manual": False,
    },
    "Snyk Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: token {value}" https://snyk.io/api/v1/user/me',
        "indicator": "200 + user JSON = valid. 401 = dead.",
        "manual": False,
    },

    # ================= Shopify / Telegram / Square / Discord =================
    "Shopify Access Token": {
        "method": "GET",
        "curl": 'curl -s -H "X-Shopify-Access-Token: {value}" "https://<SHOP>.myshopify.com/admin/api/2024-01/shop.json"',
        "indicator": "200 + shop JSON = valid. 401 = dead. Needs the target shop subdomain.",
        "manual": True,
    },
    "Shopify Shared Secret": {
        "method": "N/A",
        "curl": "# Shared secret verifies webhook HMACs locally - pair with the shop subdomain and check webhook docs.",
        "indicator": "Manual: used to forge/verify webhook signatures for that shop.",
        "manual": True,
    },
    "Telegram Bot Token": {
        "method": "GET",
        "curl": 'curl -s "https://api.telegram.org/bot{value}/getMe"',
        "indicator": "\"ok\":true + bot info = valid live bot token (can send messages as the bot!). \"ok\":false = dead.",
        "manual": False,
    },
    "Square Access Token": {
        "method": "GET",
        "curl": 'curl -s https://connect.squareup.com/v2/locations -H "Authorization: Bearer {value}"',
        "indicator": "200 + locations JSON = valid live token. 401 = dead.",
        "manual": False,
    },
    "Square OAuth Secret": {
        "method": "POST",
        "curl": 'curl -s -X POST https://connect.squareup.com/oauth2/token -H "Content-Type: application/json" -d \'{"client_id":"<CLIENT_ID>","client_secret":"{value}","grant_type":"client_credentials"}\'',
        "indicator": "200 + access_token = valid pair. Needs the client_id found nearby.",
        "manual": True,
    },
    "Discord Bot Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bot {value}" https://discord.com/api/v10/users/@me',
        "indicator": "200 + bot user JSON = valid live bot token. 401 = dead.",
        "manual": False,
    },

    # ================= Atlassian / Bitbucket / Auth0 / Okta / Plaid =================
    "Atlassian API Token": {
        "method": "GET",
        "curl": 'curl -s -u <EMAIL>:{value} "https://<SITE>.atlassian.net/rest/api/3/myself"',
        "indicator": "200 + user JSON = valid. Needs the paired account email and site subdomain.",
        "manual": True,
    },
    "Bitbucket Token": {
        "method": "GET",
        "curl": 'curl -s -u <USERNAME>:{value} "https://api.bitbucket.org/2.0/user"',
        "indicator": "200 + user JSON = valid app password/token. 401 = dead. Needs paired username.",
        "manual": True,
    },
    "Auth0 Client Secret": {
        "method": "POST",
        "curl": 'curl -s -X POST "https://<TENANT>.auth0.com/oauth/token" -H "Content-Type: application/json" -d \'{"client_id":"<CLIENT_ID>","client_secret":"{value}","audience":"https://<TENANT>.auth0.com/api/v2/","grant_type":"client_credentials"}\'',
        "indicator": "200 + access_token JSON = valid pair. 401/403 = dead. Needs tenant + client_id found nearby.",
        "manual": True,
    },
    "Okta API Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: SSWS {value}" "https://<OKTA_DOMAIN>/api/v1/users/me"',
        "indicator": "200 + user JSON = valid. 401 = dead. Needs the Okta org domain found nearby.",
        "manual": True,
    },
    "Plaid Secret Key": {
        "method": "POST",
        "curl": 'curl -s -X POST https://production.plaid.com/institutions/get -H "Content-Type: application/json" -d \'{"client_id":"<CLIENT_ID>","secret":"{value}","count":1,"offset":0}\'',
        "indicator": "200 + institutions JSON = valid LIVE production secret (financial data access). 400 'INVALID_API_KEYS' = dead. Needs client_id nearby.",
        "manual": True,
    },
    "PayPal Braintree Access Token": {
        "method": "GET",
        "curl": "# Merchant ID is embedded in the token itself (3rd $-segment). Use the server SDK with that merchant ID to confirm.",
        "indicator": "Manual: a live production token = payment-gateway access (HIGH severity).",
        "manual": True,
    },

    # ================= Firebase / Sentry / NR / Datadog / PagerDuty =================
    "Firebase Cloud Messaging (FCM) Server Key": {
        "method": "POST",
        "curl": 'curl -s -X POST https://fcm.googleapis.com/fcm/send -H "Authorization: key={value}" -H "Content-Type: application/json" -d \'{"registration_ids":["ABC"]}\'',
        "indicator": "200 + {\"multicast_id\":...} = valid live server key (can push to ALL app users!) - HIGH severity. 401 = dead. Validate manually only.",
        "manual": True,
    },
    "Sentry DSN": {
        "method": "N/A",
        "curl": "# DSNs are meant to be public (client-side error reporting) - informational unless paired with a private Sentry instance.",
        "indicator": "Informational only.",
        "manual": True,
    },
    "Sentry Auth Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://sentry.io/api/0/organizations/',
        "indicator": "200 + org list = valid LIVE (can read/write org issues, source maps, PII in breadcrumbs). 401 = dead.",
        "manual": False,
    },
    "New Relic User API Key": {
        "method": "POST",
        "curl": 'curl -s https://api.newrelic.com/graphql -H "API-Key: {value}" -H "Content-Type: application/json" -d \'{"query":"{ actor { user { email } } }"}\'',
        "indicator": "200 + actor JSON = valid. Auth error = dead.",
        "manual": False,
    },
    "Datadog API Key": {
        "method": "GET",
        "curl": 'curl -s "https://api.datadoghq.com/api/v1/validate" -H "DD-API-KEY: {value}"',
        "indicator": "{\"valid\":true} = live key. {\"valid\":false} = dead.",
        "manual": False,
    },
    "PagerDuty API Key": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Token token={value}" -H "Accept: application/vnd.pagerduty+json;version=2" https://api.pagerduty.com/users?limit=1',
        "indicator": "200 + users JSON = valid. 401 = dead.",
        "manual": False,
    },

    # ================= Algolia / Mapbox / Postmark / Mailchimp =================
    "Algolia Admin API Key": {
        "method": "GET",
        "curl": 'curl -s -H "X-Algolia-API-Key: {value}" -H "X-Algolia-Application-Id: <APP_ID>" "https://<APP_ID>-dsn.algolia.net/1/keys"',
        "indicator": "200 + keys JSON = valid ADMIN key (full index read/write/delete). 403 = dead/wrong app id. Needs the App ID found nearby.",
        "manual": True,
    },
    "Mapbox Access Token": {
        "method": "GET",
        "curl": 'curl -s "https://api.mapbox.com/geocoding/v5/mapbox.places/test.json?access_token={value}"',
        "indicator": "200 + geocoding JSON = valid. 401 'Not Authorized' = dead.",
        "manual": False,
    },
    "Mapbox Secret Token": {
        "method": "GET",
        "curl": 'curl -s "https://api.mapbox.com/geocoding/v5/mapbox.places/test.json?access_token={value}"',
        "indicator": "200 = valid. Secret (`sk.`) tokens carry write scope (uploads, datasets) - treat as critical, rotate immediately.",
        "manual": False,
    },
    "Postmark API Key": {
        "method": "GET",
        "curl": 'curl -s "https://api.postmarkapp.com/server" -H "X-Postmark-Server-Token: {value}"',
        "indicator": "200 + server JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Mailchimp API Key": {
        "method": "GET",
        "curl": 'curl -s -u "anystring:{value}" "https://<DC>.api.mailchimp.com/3.0/"',
        "indicator": "200 + account JSON = valid. The datacenter (DC) is the suffix after '-' in the key itself, e.g. key-us21 -> us21.",
        "manual": False,
    },

    # ================= Airtable / Notion / Figma / LaunchDarkly / Contentful =================
    "Airtable API Key": {
        "method": "GET",
        "curl": 'curl -s https://api.airtable.com/v0/meta/whoami -H "Authorization: Bearer {value}"',
        "indicator": "200 + {\"id\":...} = valid. 401 = dead.",
        "manual": False,
    },
    "Notion Integration Token": {
        "method": "GET",
        "curl": 'curl -s https://api.notion.com/v1/users/me -H "Authorization: Bearer {value}" -H "Notion-Version: 2022-06-28"',
        "indicator": "200 + bot/user JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Notion Token": {
        "method": "GET",
        "curl": 'curl -s https://api.notion.com/v1/users/me -H "Authorization: Bearer {value}" -H "Notion-Version: 2022-06-28"',
        "indicator": "200 + bot/user JSON = valid. 401 = dead. (`ntn_` is the newer token format - same check.)",
        "manual": False,
    },
    "Supabase Secret Key": {
        "method": "N/A",
        "curl": "# Supabase secret keys start with sb_secret_ - confirm in the Supabase dashboard (Project Settings > API Keys),\n# then rotate. The matching publishable key (sb_publishable_) is public by design.",
        "indicator": "Presence of a live sb_secret_ = full backend access. Rotate immediately; the publishable sibling is not a finding alone.",
        "manual": True,
    },
    "Supabase Publishable Key": {
        "method": "N/A",
        "curl": "# Publishable keys (sb_publishable_) ship in frontend code by design - not a vulnerability alone.",
        "indicator": "Informational - confirm no accompanying sb_secret_ key in the same bundle.",
        "manual": True,
    },
    "Google OAuth Client Secret": {
        "method": "POST",
        "curl": 'curl -s -X POST https://oauth2.googleapis.com/token -d "client_id=<CLIENT_ID>&client_secret={value}&grant_type=client_credentials"',
        "indicator": "Needs the OAuth client_id found nearby. 200 + access_token = valid pair; 401 'invalid_client' = dead.",
        "manual": True,
    },
    "Figma Personal Access Token": {
        "method": "GET",
        "curl": 'curl -s -H "X-Figma-Token: {value}" https://api.figma.com/v1/me',
        "indicator": "200 + user JSON = valid. 403 = dead.",
        "manual": False,
    },
    "LaunchDarkly SDK Key": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: {value}" https://app.launchdarkly.com/api/v2/projects',
        "indicator": "200 + projects JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Contentful API Key": {
        "method": "GET",
        "curl": 'curl -s "https://cdn.contentful.com/spaces/<SPACE_ID>/entries?access_token={value}"',
        "indicator": "200 + entries JSON = valid. 401 = dead. Needs the space ID found nearby.",
        "manual": True,
    },
    "Contentful Management Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://api.contentful.com/spaces',
        "indicator": "200 + spaces JSON = valid management token (full CMS write). 401 = dead.",
        "manual": False,
    },

    # ================= Social =================
    "Facebook/Meta Graph API Token": {
        "method": "GET",
        "curl": 'curl -s "https://graph.facebook.com/me?access_token={value}"',
        "indicator": "200 + user JSON = valid live token. 400 'Invalid OAuth access token' = dead.",
        "manual": False,
    },
    "Facebook App Secret": {
        "method": "GET",
        "curl": "curl -s \"https://graph.facebook.com/oauth/access_token?client_id=<APP_ID>&client_secret={value}&grant_type=client_credentials\"",
        "indicator": "200 + access_token = valid pair. Needs the App ID found nearby.",
        "manual": True,
    },
    "Twitter/X Bearer Token": {
        "method": "GET",
        "curl": 'curl -s "https://api.twitter.com/1.1/application/rate_limit_status.json" -H "Authorization: Bearer {value}"',
        "indicator": "200 + rate-limit JSON = valid. 401 'Unauthorized' = dead.",
        "manual": False,
    },
    "Twitter/X API Secret": {
        "method": "POST",
        "curl": 'curl -s -X POST "https://api.twitter.com/oauth2/token" -u "<API_KEY>:{value}" -d "grant_type=client_credentials"',
        "indicator": "200 + bearer token = valid pair. Needs the API key found nearby.",
        "manual": True,
    },

    # ================= DevOps / monitoring =================
    "CircleCI Token": {
        "method": "GET",
        "curl": 'curl -s -H "Circle-Token: {value}" https://circleci.com/api/v2/me',
        "indicator": "200 + user JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Buildkite Access Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://api.buildkite.com/v2/user',
        "indicator": "200 + user JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Shodan API Key": {
        "method": "GET",
        "curl": 'curl -s "https://api.shodan.io/api-info?key={value}"',
        "indicator": "200 + plan/query-credits JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Cloudflare API Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://api.cloudflare.com/client/v4/user/tokens/verify',
        "indicator": "{\"success\":true} = valid. 401/403 = dead.",
        "manual": False,
    },
    "Resend API Key": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://api.resend.com/domains',
        "indicator": "200 + domains JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Vercel Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://api.vercel.com/v2/user',
        "indicator": "200 + user JSON = valid. 401/403 = dead.",
        "manual": False,
    },

    # ================= JWT / DB / keys =================
    "JWT Token": {
        "method": "N/A",
        "curl": "# Decode locally first (never send an unknown JWT to a third-party site):\n echo '{value}' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool\n# Then replay against the app's own authenticated API:\n curl -s -H \"Authorization: Bearer {value}\" https://target.com/api/me",
        "indicator": "Check 'exp' claim locally first. A 200 on a protected endpoint using this token = live session.",
        "manual": True,
    },
    "Supabase Service Key": {
        "method": "N/A",
        "curl": "# Supabase keys are JWTs - decode locally: echo '{value}' | cut -d. -f2 | base64 -d | python3 -m json.tool\n# 'role: service_role' = FULL DB BYPASS (critical). 'role: anon' = limited. Then test read-only against the project's own Supabase URL.",
        "indicator": "role claim decides severity. Confirm with a read-only select against the in-scope project URL only.",
        "manual": True,
    },
    "MongoDB Connection String": {
        "method": "N/A",
        "curl": 'mongosh "{value}" --eval "db.runCommand({ping:1})"',
        "indicator": "{ ok: 1 } = valid LIVE database connection - CRITICAL, stop immediately after confirming.",
        "manual": True,
    },
    "PostgreSQL Connection String": {
        "method": "N/A",
        "curl": 'psql "{value}" -c "SELECT 1;"',
        "indicator": "Returns a row = valid LIVE connection - CRITICAL, stop immediately.",
        "manual": True,
    },
    "MySQL Connection String": {
        "method": "N/A",
        "curl": 'mysql -h <HOST> -u <USER> -p -e "SELECT 1;"',
        "indicator": "Returns a row = valid LIVE connection - CRITICAL, stop immediately.",
        "manual": True,
    },
    "Redis Connection String": {
        "method": "N/A",
        "curl": 'redis-cli -u "{value}" PING',
        "indicator": "PONG = valid LIVE reachable Redis - CRITICAL if internet-facing.",
        "manual": True,
    },
    "Private Key": {
        "method": "N/A",
        "curl": "openssl rsa -in leaked_key.pem -check -noout    # validates well-formedness\n# Prove impact by matching against the target's published cert:\n openssl x509 -in target_cert.pem -noout -pubkey | openssl md5\n openssl rsa -in leaked_key.pem -pubout | openssl md5   # match = this key belongs to that cert",
        "indicator": "Matching hashes = confirmed live impact.",
        "manual": True,
    },
    "PGP Private Key Block": {
        "method": "N/A",
        "curl": "gpg --show-keys leaked.asc    # confirms a parseable private block without importing it",
        "indicator": "Parseable block + matching published fingerprint = confirmed impact.",
        "manual": True,
    },
    "Crypto Seed Phrase": {
        "method": "N/A",
        "curl": "# NEVER import an unknown seed phrase into a live wallet - possession alone is the finding.",
        "indicator": "12/24-word BIP-39 phrase = full wallet compromise if live. Report without touching funds.",
        "manual": True,
    },
    "Crypto Private Key (Hex)": {
        "method": "N/A",
        "curl": "# Do not import - derive the address offline (e.g. cast wallet address <key>) and check for a balance via a block explorer.",
        "indicator": "Non-zero balance on the derived address = live funds at risk.",
        "manual": True,
    },

    # ================= Ported from specter-improved.py research set =================
    "GitHub Token (Generic)": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: token {value}" https://api.github.com/user',
        "indicator": "200 + user JSON = valid (typically a classic PAT). 401 'Bad credentials' = dead.",
        "manual": False,
    },
    "Stripe Live Publishable Key": {
        "method": "N/A",
        "curl": "# Publishable keys are public by design (Stripe.js needs them client-side) - not a vulnerability alone.\n# Note it as recon (identifies the Stripe account) and focus on whether a secret key is exposed too.",
        "indicator": "Informational - confirm no accompanying sk_live_/rk_live_ key in the same bundle.",
        "manual": True,
    },
    "Stripe Test Publishable Key": {
        "method": "N/A",
        "curl": "# Test publishable keys are public by design - informational only.",
        "indicator": "Informational.",
        "manual": True,
    },
    "Twilio App SID": {
        "method": "GET",
        "curl": "curl -s -u <ACCOUNT_SID>:<AUTH_TOKEN> https://api.twilio.com/2010-04-01/Accounts/<ACCOUNT_SID>/Applications/{value}.json",
        "indicator": "200 + application JSON = the App SID exists under that account. Needs the account SID + auth token pair.",
        "manual": True,
    },
    "Firebase Realtime Database URL": {
        "method": "GET",
        "curl": 'curl -s "https://<DB>.firebaseio.com/.json"',
        "indicator": "200 + JSON body = WORLD-READABLE database (critical). 'Permission denied' = locked down (good). Replace <DB> with the host from the finding.",
        "manual": True,
    },
    "AWS S3 Bucket Reference": {
        "method": "GET",
        "curl": "curl -s -o /dev/null -w \"%{http_code}\" https://<BUCKET>.s3.amazonaws.com/ && aws s3 ls s3://<BUCKET>/ --no-sign-request",
        "indicator": "200 / bucket listing = publicly listable (data exposure). 403 = exists but private. NoSuchBucket = dead reference.",
        "manual": True,
    },
    "Google Service Account Config": {
        "method": "GET",
        "curl": "gcloud auth activate-service-account --key-file=service_account.json && gcloud auth print-access-token",
        "indicator": "A `\"type\": \"service_account\"` marker alone only proves a config fragment - needs the full JSON key file (private_key) to be exploitable.",
        "manual": True,
    },
    "Google reCAPTCHA Site Key": {
        "method": "N/A",
        "curl": "# Site keys (6L...) are public by design - they ship in frontend HTML. No validation needed.",
        "indicator": "Informational - only interesting if paired with a reCAPTCHA *secret* key server-side.",
        "manual": True,
    },
    "Snyk Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: token {value}" https://snyk.io/api/v1/user/me',
        "indicator": "200 + user JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Heroku API Key": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" -H "Accept: application/vnd.heroku+json;version=3" https://api.heroku.com/account',
        "indicator": "200 + account JSON = valid LIVE (can manage apps, config, add-ons). 401 = dead.",
        "manual": False,
    },
    "WakaTime API Key": {
        "method": "GET",
        "curl": 'curl -s -u "{value}:" https://wakatime.com/api/v1/users/current',
        "indicator": "200 + user JSON = valid. 401 = dead.",
        "manual": False,
    },
    "Sonarcloud Token": {
        "method": "GET",
        "curl": 'curl -s -u "{value}:" https://sonarcloud.io/api/authentication/validate',
        "indicator": "{\"valid\":true} = live token. {\"valid\":false} = dead.",
        "manual": False,
    },
    "AMQP Connection String": {
        "method": "N/A",
        "curl": "# Confirm with a read-only AMQP client (e.g. python pika, read-only vhost) - stop after connectivity, do not consume/publish.\n# Default guest:guest credentials against localhost are NOT a finding.",
        "indicator": "Successful connection + channel open = live broker access - scope determines severity.",
        "manual": True,
    },
    "PagerDuty Integration Key": {
        "method": "N/A",
        "curl": "# Integration/routing keys trigger a real page to the on-call human - do NOT fire unless explicitly authorized.",
        "indicator": "Do not auto-trigger; treat as valid-by-context and report responsibly.",
        "manual": True,
    },

    # ================= Webhook URLs (post-capable: manual empty-body probe) ===
    "Discord Webhook URL": {
        "method": "GET",
        "curl": 'curl -s -o /dev/null -w "%{http_code}" "{value}"',
        "indicator": "200 = webhook is VALID (can post to a real channel - keep probes read-only, never send content). 404/401 = dead.",
        "manual": True,
    },
    "Teams Webhook URL": {
        "method": "GET",
        "curl": 'curl -s -o /dev/null -w "%{http_code}" "{value}"',
        "indicator": "200/202 = webhook is VALID (can post to a real channel - never send content). 404/403 = dead.",
        "manual": True,
    },

    # ================= Package registries / IaC (manual console lookup) ======
    "Docker Personal Access Token": {
        "method": "GET",
        "curl": 'curl -s -u "{value}:" "https://hub.docker.com/v2/user/"',
        "indicator": "200 + user JSON = valid (can push/pull private repos per its scopes). 401 = dead.",
        "manual": True,
    },
    "PyPI API Token": {
        "method": "GET",
        "curl": "# Confirm at https://pypi.org/manage/account/token/ and rotate there; tokens are project- or account-scoped.",
        "indicator": "A live token can publish packages as you - rotate immediately. Scope (project vs account) decides blast radius.",
        "manual": True,
    },
    "Terraform Cloud Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://app.terraform.io/api/v2/account-details',
        "indicator": "200 + account JSON = valid (can read/apply workspaces per scope). 401 = dead.",
        "manual": True,
    },
    "Pulumi Access Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: token {value}" https://api.pulumi.com/api/user',
        "indicator": "200 + user JSON = valid. 401 = dead.",
        "manual": True,
    },
    "Netlify Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://api.netlify.com/api/v1/user',
        "indicator": "200 + user JSON = valid (can manage sites/deploys/env). 401 = dead.",
        "manual": True,
    },
    "Grafana Service Token": {
        "method": "GET",
        "curl": 'curl -s -H "Authorization: Bearer {value}" https://<GRAFANA_HOST>/api/org',
        "indicator": "200 + org JSON = valid service-account token. 401 = dead. Swap in the target's Grafana host.",
        "manual": True,
    },

    # ================= Media uploads =========================================
    "Cloudinary URL": {
        "method": "GET",
        "curl": "# The URL embeds api_key:api_secret - confirm via the Cloudinary console usage API (read-only):\n# curl -s -u <API_KEY>:{value} \"https://api.cloudinary.com/v1_1/<CLOUD>/usage\"",
        "indicator": "Successful usage response = live credentials (full media library write/delete). Rotate immediately.",
        "manual": True,
    },

    # ================= Generic / paired leftovers (guidance, always manual) ===
    "API Key (Generic)": {
        "method": "N/A",
        "curl": "# Generic match - identify the provider first from the variable name and nearby URLs,\n# then use that provider's documented whoami endpoint (see the entries above).",
        "indicator": "No universal check exists. Triage: provider name -> matching validator entry in this file.",
        "manual": True,
    },
    "Secret Key (Generic)": {
        "method": "N/A",
        "curl": "# Generic match - identify the provider first from the variable name and nearby URLs,\n# then use that provider's documented whoami endpoint (see the entries above).",
        "indicator": "No universal check exists. Triage: provider name -> matching validator entry in this file.",
        "manual": True,
    },
    "Access Token (Generic)": {
        "method": "N/A",
        "curl": "# If it has 3 dot-separated segments it is a JWT - decode locally:\n echo '{value}' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool\n# Otherwise identify the provider from context and use its whoami endpoint.",
        "indicator": "JWT 'exp'/'iss' claims or the provider's identity endpoint decide validity.",
        "manual": True,
    },
    "Password Assignment": {
        "method": "N/A",
        "curl": "# Only test against the in-scope login/database you are authorized for - never spray\n# a scraped password across third-party services.",
        "indicator": "A successful authenticated action in-scope = live credential. Report rotation need regardless.",
        "manual": True,
    },
    "Basic Auth Credential": {
        "method": "N/A",
        "curl": "# Decode locally to see what it is (no network):\n echo '{value}' | base64 -d 2>/dev/null\n# Then validate only against the app's own login endpoint if in scope.",
        "indicator": "Decoded user:pass shape + acceptance by the in-scope app = live credential.",
        "manual": True,
    },
    "Amazon MWS Auth Token": {
        "method": "GET",
        "curl": "# Needs the Seller ID + Marketplace ID found nearby; confirm via the SP-API getMarketplaceParticipations call.",
        "indicator": "A valid participations response = live MWS/SP-API credential pair.",
        "manual": True,
    },
}


def get_validation(secret_type: str) -> Optional[dict]:
    """Return the validator entry for a secret type label, or None."""
    return VALIDATORS.get(secret_type)


def render_curl(secret_type: str, value: str) -> Optional[str]:
    """Fill in the curl template for a matched secret value."""
    entry = VALIDATORS.get(secret_type)
    if not entry:
        return None
    try:
        return entry["curl"].format(value=value)
    except (KeyError, IndexError):
        return entry["curl"]


def extract_value(matched_text: str) -> str:
    """Pull just the credential value out of a `key = 'VALUE'` style match."""
    value = (matched_text or "").strip()
    # Prefer the longest quoted segment (handles `key="val"` and JSON).
    best = ""
    for q in ('"', "'", "`"):
        qi = value.find(q)
        if qi >= 0:
            qe = value.rfind(q)
            if qe > qi:
                cand = value[qi + 1:qe]
                if len(cand) > len(best):
                    best = cand
    if best:
        value = best
    # Bare `key=value` fallback (no quotes).
    if best == "" and "=" in value and " " not in value.strip():
        parts = value.split("=", 1)
        if len(parts) == 2 and parts[1].strip():
            value = parts[1].strip().strip("\"'`")
    # Telegram / webhook style: the whole match IS the secret.
    return value.strip()


# ---------------------------------------------------------------------------
# Safe auto-validation (used by the "Validate All Secrets" button).
# Only read-only, single-call GET/POST identity checks with no paired data
# and no side effects. Everything else returns checked=False (manual).
# ---------------------------------------------------------------------------

def _retry_wait(resp: Any, backoff: float, cap: float = 5.0) -> float:
    """Seconds to wait before retry: Retry-After (delta only) else backoff."""
    try:
        ra = float(resp.headers.get('Retry-After', '') or 0)
        if ra > 0:
            return min(ra, cap)
    except (ValueError, TypeError, AttributeError):
        pass
    return min(backoff, cap)


def _verdict(code: int) -> Dict[str, Any]:
    """Map an issuer status to a validity verdict.

    429 / 5xx are INCONCLUSIVE (rate-limited or issuer trouble) - never
    reported as dead. Only an explicit rejection counts as invalid.
    """
    if code == 200:
        return {"checked": True, "status_code": code, "valid": True}
    if code in (401, 403):
        return {"checked": True, "status_code": code, "valid": False}
    if code == 429 or code >= 500:
        return {"checked": True, "status_code": code, "valid": None,
                "error": "rate limited - retry later" if code == 429 else "issuer error - retry later"}
    return {"checked": True, "status_code": code, "valid": False}


def _safe_get(url: str, headers: Optional[dict] = None, timeout: int = 8,
              auth: Optional[tuple] = None, _retries: int = 2) -> dict:
    import requests
    backoff = 0.5
    for attempt in range(_retries + 1):
        try:
            r = requests.get(url, headers=headers or {}, auth=auth,
                             timeout=timeout, verify=False)
        except Exception as e:
            return {"checked": True, "valid": None, "error": str(e)[:200]}
        if (r.status_code == 429 or r.status_code >= 500) and attempt < _retries:
            time.sleep(_retry_wait(r, backoff) + random.uniform(0, 0.4))
            backoff *= 2
            continue
        return _verdict(r.status_code)
    return {"checked": True, "valid": None, "error": "retries exhausted"}


def _safe_post(url: str, headers: Optional[dict] = None, payload: Optional[dict] = None,
               timeout: int = 8, _retries: int = 2) -> dict:
    import requests
    backoff = 0.5
    for attempt in range(_retries + 1):
        try:
            r = requests.post(url, headers=headers or {}, json=payload,
                              timeout=timeout, verify=False)
        except Exception as e:
            return {"checked": True, "valid": None, "error": str(e)[:200]}
        code = r.status_code
        if (code == 429 or code >= 500) and attempt < _retries:
            time.sleep(_retry_wait(r, backoff) + random.uniform(0, 0.4))
            backoff *= 2
            continue
        if code == 429 or code >= 500:
            return {"checked": True, "status_code": code, "valid": None,
                    "error": "rate limited - retry later" if code == 429 else "issuer error - retry later"}
        try:
            body = r.json()
        except Exception:
            body = {}
        ok = False
        if isinstance(body, dict):
            if body.get("ok") is True:
                ok = True
            elif isinstance(body.get("data"), dict) and body["data"].get("viewer"):
                ok = True
            elif isinstance(body.get("data"), dict) and body["data"].get("actor"):
                ok = True
        if code == 200 and ok:
            valid = True
        elif code in (401, 403):
            valid = False
        else:
            valid = (code == 200)
        return {"checked": True, "status_code": code, "valid": valid}
    return {"checked": True, "valid": None, "error": "retries exhausted"}


def live_validate_secret(label: str, value: str, timeout: int = 8) -> Dict[str, Any]:
    """Best-effort safe live check. Returns {checked, valid, status_code?, ...}.

    valid=True  -> issuer accepted the credential (LIVE)
    valid=False -> issuer rejected it (DEAD / revoked)
    valid=None  -> inconclusive (network error, rate limit, non-200 oddity)
    checked=False -> needs manual/paired validation (see curl command)
    """
    entry = get_validation(label)
    if not entry or entry.get("manual"):
        return {"checked": False, "reason": "requires manual / paired validation - see curl command"}
    v = (value or "").strip()
    if not v or len(v) < 8:
        return {"checked": False, "reason": "empty value"}

    try:
        if label == "Google API Key":
            return _safe_get(f"https://www.googleapis.com/discovery/v1/apis?key={v}", timeout=timeout)
        if label == "Google OAuth Access Token":
            return _safe_get(f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={v}", timeout=timeout)
        if label in ("GitHub Personal Access Token", "GitHub OAuth Token",
                     "GitHub User Token", "GitHub Refresh Token",
                     "GitHub Token (Generic)"):
            return _safe_get("https://api.github.com/user", {"Authorization": f"token {v}", "User-Agent": "Specter"}, timeout=timeout)
        if label in ("GitHub Fine-grained Token", "GitHub Server-to-Server Token"):
            return _safe_get("https://api.github.com/user", {"Authorization": f"Bearer {v}", "User-Agent": "Specter"}, timeout=timeout)
        if label in ("GitLab Personal Access Token", "GitLab Pipeline Token"):
            return _safe_get("https://gitlab.com/api/v4/user", {"PRIVATE-TOKEN": v}, timeout=timeout)
        if label in ("OpenAI API Key", "OpenAI Admin Key"):
            return _safe_get("https://api.openai.com/v1/models", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Anthropic API Key":
            return _safe_get("https://api.anthropic.com/v1/models",
                             {"x-api-key": v, "anthropic-version": "2023-06-01"}, timeout=timeout)
        if label == "Anthropic OAuth Token":
            return _safe_get("https://api.anthropic.com/v1/models",
                             {"Authorization": f"Bearer {v}", "anthropic-version": "2023-06-01"}, timeout=timeout)
        if label == "Hugging Face Token":
            return _safe_get("https://huggingface.co/api/whoami-v2", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "DigitalOcean Token":
            return _safe_get("https://api.digitalocean.com/v2/account", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Mailgun API Key":
            return _safe_get("https://api.mailgun.net/v3/domains", timeout=timeout, auth=("api", v))
        if label == "Telegram Bot Token":
            return _safe_get(f"https://api.telegram.org/bot{v}/getMe", timeout=timeout)
        if label in ("Mapbox Access Token", "Mapbox Secret Token"):
            return _safe_get(f"https://api.mapbox.com/geocoding/v5/mapbox.places/test.json?access_token={v}", timeout=timeout)
        if label == "Snyk Token":
            return _safe_get("https://snyk.io/api/v1/user/me", {"Authorization": f"token {v}"}, timeout=timeout)
        if label == "Airtable API Key":
            return _safe_get("https://api.airtable.com/v0/meta/whoami", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Sentry Auth Token":
            return _safe_get("https://sentry.io/api/0/organizations/", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Datadog API Key":
            return _safe_get("https://api.datadoghq.com/api/v1/validate", {"DD-API-KEY": v}, timeout=timeout)
        if label == "NPM Token":
            return _safe_get("https://registry.npmjs.org/-/npm/v1/user", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "LaunchDarkly SDK Key":
            return _safe_get("https://app.launchdarkly.com/api/v2/projects?limit=1", {"Authorization": v}, timeout=timeout)
        if label == "Figma Personal Access Token":
            return _safe_get("https://api.figma.com/v1/me", {"X-Figma-Token": v}, timeout=timeout)
        if label in ("Notion Integration Token", "Notion Token"):
            return _safe_get("https://api.notion.com/v1/users/me",
                             {"Authorization": f"Bearer {v}", "Notion-Version": "2022-06-28"}, timeout=timeout)
        if label == "SendGrid API Key":
            return _safe_get("https://api.sendgrid.com/v3/scopes", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label in ("Stripe Live Secret Key", "Stripe Test Secret Key",
                     "Stripe Live Restricted Key", "Stripe Test Restricted Key"):
            import requests
            try:
                r = requests.get("https://api.stripe.com/v1/charges?limit=1",
                                 auth=(v, ""), timeout=timeout, verify=False)
                return {"checked": True, "status_code": r.status_code,
                        "valid": r.status_code == 200}
            except Exception as e:
                return {"checked": True, "valid": None, "error": str(e)[:200]}
        if label == "Discord Bot Token":
            return _safe_get("https://discord.com/api/v10/users/@me", {"Authorization": f"Bot {v}"}, timeout=timeout)
        if label == "Square Access Token":
            return _safe_get("https://connect.squareup.com/v2/locations?limit=1",
                             {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "PagerDuty API Key":
            return _safe_get("https://api.pagerduty.com/users?limit=1",
                             {"Authorization": f"Token token={v}",
                              "Accept": "application/vnd.pagerduty+json;version=2"}, timeout=timeout)
        if label == "Postmark API Key":
            return _safe_get("https://api.postmarkapp.com/server", {"X-Postmark-Server-Token": v}, timeout=timeout)
        if label == "Heroku API Key":
            return _safe_get("https://api.heroku.com/account",
                             {"Authorization": f"Bearer {v}",
                              "Accept": "application/vnd.heroku+json;version=3"}, timeout=timeout)
        if label == "WakaTime API Key":
            return _safe_get("https://wakatime.com/api/v1/users/current", timeout=timeout, auth=(v, ""))
        if label == "Sonarcloud Token":
            return _safe_get("https://sonarcloud.io/api/authentication/validate", timeout=timeout, auth=(v, ""))
        if label == "Mailchimp API Key":
            m = re.search(r"-([a-z]{2}\d{1,2})$", v)
            if not m:
                return {"checked": False, "reason": "cannot derive datacenter suffix from key - validate manually"}
            dc = m.group(1)
            return _safe_get(f"https://{dc}.api.mailchimp.com/3.0/", timeout=timeout, auth=("anystring", v))
        if label == "Groq API Key":
            return _safe_get("https://api.groq.com/openai/v1/models", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Replicate API Token":
            return _safe_get("https://api.replicate.com/v1/predictions?limit=1",
                             {"Authorization": f"Token {v}"}, timeout=timeout)
        if label == "Cohere API Key":
            return _safe_get("https://api.cohere.com/v1/models", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Mistral AI Key":
            return _safe_get("https://api.mistral.ai/v1/models", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Pinecone API Key":
            return _safe_get("https://api.pinecone.io/indexes", {"Api-Key": v}, timeout=timeout)
        if label == "DeepSeek API Key":
            return _safe_get("https://api.deepseek.com/models", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Together AI Key":
            return _safe_get("https://api.together.xyz/v1/models", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "OpenRouter API Key":
            return _safe_get("https://openrouter.ai/api/v1/auth/key", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "xAI API Key":
            return _safe_get("https://api.x.ai/v1/models", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Fireworks API Key":
            return _safe_get("https://api.fireworks.ai/inference/v1/models",
                             {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Contentful Management Token":
            return _safe_get("https://api.contentful.com/spaces?limit=1",
                             {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "CircleCI Token":
            return _safe_get("https://circleci.com/api/v2/me", {"Circle-Token": v}, timeout=timeout)
        if label == "Buildkite Access Token":
            return _safe_get("https://api.buildkite.com/v2/user", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Shodan API Key":
            return _safe_get(f"https://api.shodan.io/api-info?key={v}", timeout=timeout)
        if label == "Cloudflare API Token":
            return _safe_get("https://api.cloudflare.com/client/v4/user/tokens/verify",
                             {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Resend API Key":
            return _safe_get("https://api.resend.com/domains", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Vercel Token":
            return _safe_get("https://api.vercel.com/v2/user", {"Authorization": f"Bearer {v}"}, timeout=timeout)
        if label == "Facebook/Meta Graph API Token":
            return _safe_get(f"https://graph.facebook.com/me?access_token={v}", timeout=timeout)
        if label == "Twitter/X Bearer Token":
            return _safe_get("https://api.twitter.com/1.1/application/rate_limit_status.json",
                             {"Authorization": f"Bearer {v}"}, timeout=timeout)
        # Safe read-only POST identity checks (no side effects).
        if label in ("Slack Bot Token", "Slack OAuth Access Token"):
            return _safe_post("https://slack.com/api/auth.test",
                              {"Authorization": f"Bearer {v}"}, None, timeout=timeout)
        if label in ("Slack Token", "Slack User Token"):
            return _safe_post(f"https://slack.com/api/auth.test?token={v}&pretty=1", None, None, timeout=timeout)
        if label == "Linear API Key":
            return _safe_post("https://api.linear.app/graphql", {"Authorization": v},
                              {"query": "{ viewer { id name } }"}, timeout=timeout)
        if label == "New Relic User API Key":
            return _safe_post("https://api.newrelic.com/graphql", {"API-Key": v},
                              {"query": "{ actor { user { email } } }"}, timeout=timeout)
    except Exception as e:
        return {"checked": True, "valid": None, "error": str(e)[:200]}

    return {"checked": False, "reason": "no automated safe check for this type - use the curl command"}
