# Current finding format

- **Severity:** high
- **Candidate ID:** cand_current0123456789
- **Evidence:** ev_current
- **Vulnerability Type:** SQL Injection
- **CWE:** CWE-89
- **OWASP:** A03:2021 Injection
- **URL:** https://lab.example.test/search
- **Method:** GET
- **Parameter:** id
- **Reported at:** 2026-10-01T12:00:00+00:00

## Observed impact

The linked proof demonstrates the response difference.
## Evidence notes
### Repeated observation
#### Detail

## Potential impact

Additional impact remains unassessed.
## Conditional scenario
### Boundary

## Payload

```
id=1 OR 1=1
## Payload-looking evidence
```

## Remediation

Use parameterized queries.
## Rollout notes

