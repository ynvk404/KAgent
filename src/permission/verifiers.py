"""Production evidence contracts. These verify observations, never action safety.

The SQLi contract deliberately supports repeated query boolean probes with JSON
row results. Other techniques/classes require their own adapter or operator proof
review; an error word, echo, arbitrary body differential or model label is not proof.
"""
import json
import re
from urllib.parse import parse_qs, urlsplit

from src.permission.observations import VerifiedResult


def sql_boolean(candidate, items):
    if candidate.location not in {None, "query"} or not candidate.parameter or len(items) < 4:
        return None
    pairs = {}
    for item in items:
        if item.status != 200 or item.method != "GET":
            return None
        params = parse_qs(urlsplit(item.url).query, keep_blank_values=True)
        values = params.pop(candidate.parameter, [])
        if len(values) != 1:
            return None
        match = re.search(r"(?i)\b(AND|OR)\s*\(?\s*(\d+)\s*=\s*(\d+)\s*\)?", values[0])
        if match is None or "'" not in values[0][:match.start()]:
            return None
        template = values[0][:match.start()] + "{predicate}" + values[0][match.end():]
        identity = (urlsplit(item.url).path, json.dumps(params, sort_keys=True), template, match[1].upper())
        try:
            rows = json.loads(item.body).get("data")
        except (ValueError, AttributeError):
            return None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            return None
        truth = int(match[2]) == int(match[3])
        if bool(rows) != truth:
            return None
        signature = json.dumps(rows, sort_keys=True)
        pairs.setdefault(identity, {True: [], False: []})[truth].append(signature)
    if len(pairs) != 1:
        return None
    sides = next(iter(pairs.values()))
    if any(len(side) < 2 or len(set(side)) != 1 for side in sides.values()):
        return None
    return VerifiedResult("confirmed", "Repeated SQL boolean predicates changed returned JSON rows; no broader data impact tested.",
                          "medium", tuple(item.id for item in items), "TRUE returned rows; FALSE returned no rows, repeated twice.",
                          "runtime:sql-boolean-json-v1")


def register_production_verifiers(store):
    store.register_verifier("sql-injection", sql_boolean)
