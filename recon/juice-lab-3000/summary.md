# Recon summary — http://juice.lab:3000

- **Target:** http://juice.lab:3000
- **Target type:** Single URL (web application) — no subdomain discovery applicable
- **Reachable service:** HTTP 200 on `/`, final URL `http://juice.lab:3000/`, body ~9.9 KB
- **Redirects:** `/api-docs` → 301 → `/api-docs/` (200)

## Technology fingerprint
- **Confirmed:** OWASP Juice Shop (SPA). Evidence: `<title>OWASP Juice Shop</title>`, MIT
  source-header comment (2014-2026 Bjoern Kimminich), `X-Recruiting: /#/jobs` header.
- **Confirmed:** Angular-based SPA (`data-beasties-container` attribute, hash-routed
  `/#/jobs` header value).
- **Hypothesis:** Node.js/Express backend (Juice Shop default). `/api` returns HTTP 500
  (expected Juice Shop behavior for the bare `/api` path).

## Response headers / security posture
- `Access-Control-Allow-Origin: *` (wildcard CORS)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `Feature-Policy: payment 'self'`
- `X-Recruiting: /#/jobs`
- No HSTS/CSP observed on the document response.

## Initial attack-surface clues
- `/api-docs/` — live Swagger UI (API documentation exposed).
- `/api-docs/swagger.json` and `/swagger.json` — served (SPA fallback HTML returned;
  the real spec is under the Swagger UI bundle).
- `/graphql` — present (HTTP 200).
- `/rest` and `/api` — present (HTTP 500 when hit bare).
- `/metrics` — Prometheus metrics exposed (e.g. `file_uploads_count`,
  `file_upload_errors`) — leaks internal counters.
- `/robots.txt` — `Disallow: /ftp`.
- `/ftp/` — **open directory listing** with sensitive files:
  - `acquisitions.md`
  - `announcement_encrypted.md`
  - `coupons_2013.md.bak`
  - `eastere.gg`
  - `encrypt.pyc`
  - `incident-support.kdbx`
  - `legal.md`
  - `package-lock.json.bak`
  - `package.json.bak`
  - `suspicious_errors.yml`
  - `quarantine/`

## Relevant uncertainties
- `/graphql` presence confirmed by 200, but schema/introspection not yet validated.
- Whether `/api-docs/swagger.json` exposes the full REST spec needs enumeration.
- `/ftp/` file contents not yet retrieved (noted as attack surface, not yet a finding).

## Recommended next phase
- `web-enumeration`: dump `/api-docs/` Swagger spec + `/graphql` introspection;
  enumerate `/rest/*` and `/api/*`; catalogue `/ftp/` artifacts, `/metrics` surface,
  and login/auth routes.
