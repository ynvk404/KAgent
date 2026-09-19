---
name: recon
description: >
  Initial reconnaissance of a target: identify the reachable service,
  fingerprint the technology stack, and collect obvious attack-surface
  clues. Works for a domain, IP, URL, or localhost target (e.g.
  http://localhost:3000). Use when the agent has just received a new
  target and has no prior information about it — before endpoint-level
  enumeration or vulnerability testing.
allowed-tools:
  - shell
  - http
  - file_write
---

# Recon playbook

You have been asked to establish an initial picture of a target the user is
authorized to test. This phase answers "what is this target and what is it
running?" It does not map endpoints, parameters, or forms. That belongs to
`web-enumeration`.

Default to `curl` and the built-in `http` tool. Do not pull in specialized
scanners such as `nmap`, `subfinder`, `httpx`, `ffuf`, or `gobuster` unless
the user explicitly asks for them, or the target is a root domain wide enough
that a single request cannot establish reachability.

Execution rule: substitute the real target into commands before running them.
Never write literal placeholders such as `<TARGET>`, `<HOST>`, or `<APEX>`
to files. If the target is unclear or its scope was not already stated in
the conversation, ask once before running commands.

## Target identifier convention

Before writing any output path, derive a single, stable identifier from the
target and reuse it for every file this skill (and downstream skills) write.
This must be deterministic — the same target must always produce the same
identifier, so `recon`, `web-enumeration`, and `web-input-analysis` land in
the same directory.

1. Start from `agent.target.base_url()` if set, otherwise
   `agent.target.name()`.
2. Strip the scheme (`http://`, `https://`).
3. Lowercase everything.
4. Replace any run of characters outside `[a-z0-9]` with a single `-`.
5. Trim leading/trailing `-`.
6. Truncate to 64 characters.

This mirrors the charset and normalization already enforced for finding
slugs in `src/findings/store.py` (`_SAFE_SLUG_RE`, `slugify()`) — lowercase
alphanumerics and hyphens only, no underscores, no path separators, 64-char
cap. Do not invent a different charset per skill.

Example: `https://App.Example.com:8443/` → `app-example-com-8443`.

Below, `<target>` always refers to this derived identifier, not the raw
target string.

## 1. Confirm the target and its shape

Restate the target and confirm that it is in scope, but only ask for
confirmation when scope has not already been made explicit.

Classify the target because this determines which reconnaissance steps apply:

- **Single URL** such as `http://localhost:3000` or
  `https://app.example.com`: proceed directly to step 2.
- **Bare domain/apex** such as `example.com`: this may represent multiple
  hosts. Consider step 1b when broader surface mapping is explicitly needed.
- **IP address**: skip subdomain discovery and proceed to step 2.

Do not perform external-domain reconnaissance against a target that is clearly
a single local URL, localhost service, or standalone IP.

## 1b. Passive subdomain discovery for a root domain

Only perform this step when all of the following are true:

- the target is a bare apex domain;
- broader attack-surface mapping is intended;
- the discovered subdomains remain within the authorized scope.

Skip this step entirely for single URLs, localhost targets, and IP addresses.

Use public certificate-transparency data without adding specialized tooling.
`crt.sh` may return `502`, HTML, or an empty body instead of JSON, so validate
the response before parsing and retry with backoff:

```sh
APEX="example.com"  # replace with the real scoped apex
: > subs.txt

for attempt in 1 2 3; do
  resp=$(curl -fsS --max-time 30 \
    -H 'Accept: application/json' \
    "https://crt.sh/?q=%25.$APEX&output=json" \
    2>/dev/null || true)

  if printf '%s' "$resp" \
    | jq -e 'type == "array"' >/dev/null 2>&1; then

    printf '%s' "$resp" \
      | jq -r '.[].name_value' \
      | sed 's/^\*\.//' \
      | tr 'A-Z' 'a-z' \
      | tr -d '\r' \
      | sort -u > subs.txt

    break
  fi

  sleep 3
done

[ -s subs.txt ] || \
  printf 'warning: crt.sh unavailable or returned non-JSON; try another source\n' >&2
```

Save the deduplicated list with `file_write` to:

`recon/<target>/subs.txt`

(using the identifier derived above for the apex, not the raw `$APEX` string).

Treat each discovered hostname as a separate target for reachability checks.

Do not automatically escalate to `subfinder`, `amass`, or `assetfinder`.
Only use them when the user explicitly requests them or the scope and
testing plan justify broader enumeration.

## 2. Establish reachability

For a single target, one request is normally sufficient.

Capture the HTTP status, final URL, response headers, and basic page metadata:

```sh
TARGET="http://localhost:3000"  # replace with the real target

curl -ksS \
  -o /tmp/body \
  -w '%{http_code}\t%{url_effective}\t%{header_json}\n' \
  --max-time 8 \
  "$TARGET/" > /tmp/meta

code=$(cut -f1 /tmp/meta)
url=$(cut -f2 /tmp/meta)
headers_json=$(cut -f3 /tmp/meta)

server=$(printf '%s' "$headers_json" \
  | jq -r '.server[0] // "-"')

powered_by=$(printf '%s' "$headers_json" \
  | jq -r '.["x-powered-by"][0] // "-"')

title=$(sed -n \
  's/.*<title>\(.*\)<\/title>.*/\1/p' \
  /tmp/body \
  | head -1)

printf '%s\t%s\tserver=%s\tpowered-by=%s\ttitle=%s\n' \
  "$code" "$url" "$server" "$powered_by" "$title"
```

Avoid repeated requests when the initial response already provides sufficient
information.

If the first response is ambiguous, limited follow-up requests may be used,
for example:

```sh
curl -ksS -X OPTIONS --max-time 5 "$TARGET/"
curl -ksS --max-time 5 "$TARGET/api"
curl -ksS --max-time 5 "$TARGET/api/health"
```

Do not turn these probes into broad endpoint enumeration.

If the local curl build does not support `%{header_json}`, capture headers
separately:

```sh
curl -ksS \
  -D /tmp/headers \
  -o /tmp/body \
  --max-time 8 \
  "$TARGET/"

grep -i '^server:' /tmp/headers
grep -i '^x-powered-by:' /tmp/headers
```

## 3. Fingerprint the technology

Use the observations already collected to identify likely technologies.

Look for evidence such as:

- Server response headers;
- `X-Powered-By`;
- framework-specific cookies such as `JSESSIONID` or `.AspNetCore`;
- generator metadata;
- framework-specific static asset paths;
- recognizable error-page structures;
- authentication/session indicators;
- API indicators exposed by the initial response or a small number of
  low-noise probes.

For limited probing of obvious application indicators:

```sh
TARGET="http://localhost:3000"

for p in /api /api/health /graphql /swagger.json /robots.txt; do
  code=$(curl -ksS \
    -o /dev/null \
    -w "%{http_code}" \
    --max-time 5 \
    "$TARGET$p")

  echo "$code $p"
done
```

These probes are for technology and application-shape identification only.
Detailed API, route, endpoint, and parameter enumeration belongs to
`web-enumeration`.

Treat fingerprint results as hypotheses until supported by concrete evidence.
Do not state that a technology is confirmed without an observable indicator.

## 4. Record initial attack-surface clues

Record only the high-value clues already visible from reconnaissance.

Examples include:

- login or authentication pages referenced by the initial application;
- administrative interfaces visible from existing links or resources;
- obvious API entry points;
- exposed API documentation;
- authentication/session mechanisms;
- security-relevant response headers;
- cookie flags such as `Secure` and `HttpOnly`;
- JavaScript bundle names that reveal application structure.

Do not perform broad content discovery here.

In particular, do not run wordlist-based endpoint discovery, directory
brute-forcing, or parameter enumeration. Those tasks belong to
`web-enumeration`.

## 5. Record reconnaissance results

Write a concise summary to:

`recon/<target>/summary.md`

The summary should contain:

- target and target type (URL, apex, or IP);
- reachable service and observed status;
- final URL after redirects, when applicable;
- observed technologies, explicitly marked as confirmed or hypothesis;
- initial attack-surface clues;
- relevant uncertainties;
- recommended next phase.

Do not create a security finding from reconnaissance observations alone unless
reproducible evidence already demonstrates a vulnerability. (Findings, when
they eventually exist, are persisted and named by `confirm_finding` — do not
reuse the target identifier for a finding file name.)

## 6. Transition to the next phase

When the target is a web application:

- transition to `web-enumeration` to identify endpoints, routes, parameters,
  forms, and API surfaces;
- use `web-input-analysis` only after enumeration has produced concrete
  candidate inputs;
- do not jump directly to a vulnerability-specific skill merely because a
  technology or framework was fingerprinted.

The normal flow is:

```text
recon
  ↓
web-enumeration
  ↓
web-input-analysis
  ↓
vulnerability-specific skill
```

## Stop conditions

Stop reconnaissance when:

- the target has been classified;
- reachability has been established or the failure is clearly recorded;
- major technology indicators have been identified or explicitly marked
  unknown;
- initial attack-surface clues have been recorded;
- the next phase can be determined.

Do not escalate reconnaissance into high-volume scanning, full subdomain
brute-forcing, or deep content discovery. Those activities belong to later
phases and should only be performed when justified by the testing plan and
authorized scope.
