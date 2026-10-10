"""Scope-filtered capture view. Origin binding does not authenticate an actor.

Imported payloads remain untrusted observations; this view issues no proof
certificate or permission. Actor-specific grants need a trusted browser adapter.
"""
from __future__ import annotations
from src.browser.store import CaptureStore
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy
from src.engagement.state import OutOfScopeError
from src.target.origin import HTTPOrigin


class ScopedCaptureStore(CaptureStore):
    def __init__(self, source: CaptureStore, policy: ExecutionPolicy):
        self.source = source
        self.policy = policy

    def controller_burp_requests(self, origin: HTTPOrigin):
        """Trusted UI metadata read, without issuing or impersonating a receipt.

        Tool reads still use allowed() and require their registry receipt.
        Filtering precedes all UI/selection limits, including the exact origin.
        """
        if {"*", "browser_capture_requests", "browser_capture_get"} & self.policy.revoked:
            raise ExecutionBlocked('blocked: capture tool/session-revoked')
        self.policy.require_network(origin.as_url())
        rows = []
        for row in self.source.list_requests(limit=self.source.max_entries):
            if row.source != 'burp':
                continue
            try:
                if HTTPOrigin.from_url(row.url) != origin:
                    continue
                self.policy.require_network(row.url)
            except (ValueError, OutOfScopeError, ExecutionBlocked):
                continue
            rows.append(row)
        return rows

    def allowed(self, url):
        if not self.policy.nested_allowed():
            raise ExecutionBlocked('blocked: capture-without-current-receipt')
        try:
            self.policy.require_network(url)
            return True
        except (ValueError, OutOfScopeError):
            return False
        except ExecutionBlocked:
            return False

    def list_requests(self, url_substr=None, method=None, limit=200):
        return [row for row in self.source.list_requests(url_substr, method, self.source.max_entries)
                if self.allowed(row.url)][:limit]

    def get_request(self, id_):
        row = self.source.get_request(id_)
        if row is not None and not self.allowed(row.url):
            raise ExecutionBlocked('blocked: capture-origin-outside-profile-or-revoked')
        return row

    def resolve_baseline(self, ref):
        row = self.source.resolve_baseline(ref)
        if row is not None and not self.allowed(row.url or ''):
            raise ExecutionBlocked('blocked: capture-origin-outside-profile-or-revoked')
        return row

    def list_endpoints(self, url_substr=None, method=None):
        return [row for row in self.source.list_endpoints(url_substr, method) if self.allowed(row.url)]

    def list_snapshots(self):
        return [row for row in self.source.list_snapshots() if self.allowed(row.url)]

    def latest_snapshot(self, url_substr=None):
        return next((row for row in reversed(self.list_snapshots()) if not url_substr or url_substr.lower() in row.url.lower()), None)

    def list_burp_tasks(self):
        return [row for row in self.source.list_burp_tasks() if self.allowed(row.url or row.target or '')]

    def list_burp_issues(self):
        return [row for row in self.source.list_burp_issues() if self.allowed(row.url)]

    def status(self):
        return {'request_count': len(self.list_requests(limit=self.source.max_entries)),
                'endpoint_count': len(self.list_endpoints()), 'snapshot_count': len(self.list_snapshots()),
                'last_activity_at': max((r.received_at for r in self.list_requests(limit=self.source.max_entries)), default=0)}

    def clear(self):
        if not self.policy.nested_allowed():
            raise ExecutionBlocked('blocked: capture-without-current-receipt')
        with self.source._lock:
            self.source.requests = {key: row for key, row in self.source.requests.items() if not self.allowed(row.url)}
            self.source.endpoints = {key: row for key, row in self.source.endpoints.items() if not self.allowed(row.url)}
            self.source.snapshots = [row for row in self.source.snapshots if not self.allowed(row.url)]
            self.source.burp_tasks = [row for row in self.source.burp_tasks if not self.allowed(row.url or row.target or '')]
            self.source.burp_issues = {key: row for key, row in self.source.burp_issues.items() if not self.allowed(row.url)}
